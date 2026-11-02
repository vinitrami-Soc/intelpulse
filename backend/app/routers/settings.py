"""Workspace settings (spec 7): provider switches and keys, retention, and a key test.

Keys go in and never come out: an admin sees whether a key is set and its last
four characters, and can replace or remove it. A key travels in a request
header, so only printable ASCII without spaces is accepted.
"""
from __future__ import annotations

import re
from typing import Any

import httpx
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..enrichment import PROVIDERS, credentials
from ..enrichment.credentials import KEY_SLOTS
from ..ioc import Indicator
from ..models import Workspace
from ..net import build_client
from ..platform import audit
from ..platform import settings_store as store
from ..platform.auth import Actor
from ..platform.box import server_box
from ..platform.deps import require_actor, require_session_admin
from ..platform.errors import ApiError
from ..services import workspace_settings as ws_settings

router = APIRouter(tags=["settings"])

KEY_RE = re.compile(r"^[\x21-\x7e]{1,512}$")
# One harmless lookup per kind of indicator: public, well known, and nobody's incident.
SAMPLES = {
    "ip": "8.8.8.8",
    "domain": "example.com",
    "url": "https://example.com/",
    "hash": "44d88612fea8a8f36de82e1278abb02f",  # the EICAR test file
    "cve": "CVE-2021-44228",
}


class ProviderSwitch(BaseModel):
    model_config = {"extra": "forbid"}
    enabled: bool


class SettingsUpdate(BaseModel):
    """Send only what changes. A key of "" removes it."""

    model_config = {"extra": "forbid"}

    providers: dict[str, ProviderSwitch] | None = None
    keys: dict[str, str] | None = None
    retention_days: int | None = Field(None, ge=1, le=365)


def _provider(name: str):
    provider = next((p for p in PROVIDERS if p.name == name), None)
    if provider is None:
        raise ApiError(404, "not_found", "no such provider")
    return provider


@router.get("/settings")
async def read_settings(
    actor: Actor = Depends(require_session_admin), db: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    return await ws_settings.describe(db, server_box(), actor.workspace_id)


@router.patch("/settings")
async def update_settings(
    body: SettingsUpdate, actor: Actor = Depends(require_session_admin), db: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    ws, box = actor.workspace_id, server_box()
    changed: dict[str, Any] = {}

    for name, switch in (body.providers or {}).items():
        _provider(name)
        before = await store.get_value(db, ws, ws_settings.enabled_setting(name), True) is not False
        if before != switch.enabled:
            await store.set_value(db, ws, ws_settings.enabled_setting(name), switch.enabled)
            changed.setdefault("providers", {})[name] = {"enabled": switch.enabled}

    for slot, raw in (body.keys or {}).items():
        if slot not in KEY_SLOTS:
            raise ApiError(422, "invalid", f"no key slot called {slot!r}: use one of " + ", ".join(KEY_SLOTS))
        value = raw.strip()
        if value and not KEY_RE.match(value):
            raise ApiError(422, "invalid", "a key is 1 to 512 printable characters, without spaces")
        had = bool(await store.get_secret(db, box, ws, ws_settings.key_setting(slot)))
        await store.set_secret(db, box, ws, ws_settings.key_setting(slot), value)
        if value or had:
            # what happened, never the key
            changed.setdefault("keys", {})[slot] = ("replaced" if had else "set") if value else "removed"

    if body.retention_days is not None:
        before = await ws_settings.retention_days(db, ws)
        if before != body.retention_days:
            await store.set_value(db, ws, "retention_days", body.retention_days)
            changed["retention_days"] = {"from": before, "to": body.retention_days}

    if changed:
        await audit.record(db, action="settings.updated", actor=actor.label, workspace_id=ws, detail=changed)
    return {**await ws_settings.describe(db, box, ws), "changed": sorted(changed)}


@router.post("/settings/providers/{name}/test")
async def test_provider(
    name: str, actor: Actor = Depends(require_session_admin), db: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    """One lookup of a harmless indicator with this workspace's key, past the cache."""
    provider = _provider(name)
    kind = next((k for k in SAMPLES if k in provider.supported_types), None)
    if kind is None:
        raise ApiError(422, "invalid", "this provider has nothing to test with")
    sample = Indicator(value=SAMPLES[kind], type=kind, original=SAMPLES[kind])
    creds = await ws_settings.credentials_for(db, server_box(), actor.workspace_id)
    with credentials.using(creds):
        async with build_client(timeout=settings.provider_timeout_seconds,
                                limits=httpx.Limits(max_connections=2)) as client:
            result = await provider.lookup(client, sample, use_cache=False)
    await audit.record(db, action="settings.provider_tested", actor=actor.label, workspace_id=actor.workspace_id,
                       target=name, detail={"status": result.status})
    return {"provider": name, "indicator": sample.value, "status": result.status, "error": result.error,
            "latency_ms": result.latency_ms}


@router.get("/workspace")
async def read_workspace(actor: Actor = Depends(require_actor), db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """What every member may know about their workspace: its name and which sources answer."""
    workspace = await db.get(Workspace, actor.workspace_id)
    creds = await ws_settings.credentials_for(db, server_box(), actor.workspace_id)
    with credentials.using(creds):
        providers = [{
            "name": p.name, "label": p.label, "supported_types": sorted(p.supported_types),
            "enabled": p.name not in creds.disabled,
            "ready": p.name not in creds.disabled and p.configured(),
        } for p in PROVIDERS]
    return {
        "id": actor.workspace_id,
        "name": workspace.name if workspace else "",
        "kind": workspace.kind if workspace else "organization",
        "providers": providers,
        "retention_days": await ws_settings.retention_days(db, actor.workspace_id),
    }
