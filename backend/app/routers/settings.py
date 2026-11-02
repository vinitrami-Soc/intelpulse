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


class JiraIn(BaseModel):
    model_config = {"extra": "forbid"}
    base_url: str | None = Field(None, max_length=300)
    email: str | None = Field(None, max_length=254)
    project_key: str | None = Field(None, max_length=50)
    issue_type: str | None = Field(None, max_length=60)
    api_token: str | None = Field(None, max_length=512)


class ServiceNowIn(BaseModel):
    model_config = {"extra": "forbid"}
    base_url: str | None = Field(None, max_length=300)
    user: str | None = Field(None, max_length=120)
    table: str | None = Field(None, max_length=80)
    password: str | None = Field(None, max_length=512)


class TicketsIn(BaseModel):
    model_config = {"extra": "forbid"}
    jira: JiraIn | None = None
    servicenow: ServiceNowIn | None = None


class SettingsUpdate(BaseModel):
    """Send only what changes. A key, a field or a secret of "" removes it."""

    model_config = {"extra": "forbid"}

    providers: dict[str, ProviderSwitch] | None = None
    keys: dict[str, str] | None = None
    retention_days: int | None = Field(None, ge=1, le=365)
    tickets: TicketsIn | None = None


PLAIN_RE = re.compile(r"^[^\x00-\x1f\x7f]*$")
SECRET_RE = re.compile(r"^[\x20-\x7e]{1,512}$")   # sent base64-encoded in Basic auth
FIELD_RULES = {
    "email": (re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$"), "an email address"),
    "project_key": (re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,49}$"), "a Jira project key, like SOC"),
    "table": (re.compile(r"^[a-z0-9_]{1,80}$"), "a ServiceNow table name, like incident"),
}


def _sink_url(value: str) -> str:
    """An https address of a tracker: no credentials, query or fragment in it."""
    try:
        url = httpx.URL(value)
    except (httpx.InvalidURL, ValueError) as exc:
        raise ApiError(422, "invalid", "that is not an address") from exc
    if url.scheme != "https" or not url.host or url.userinfo or url.query or url.fragment:
        raise ApiError(422, "invalid", "a tracker address is https://host[/path], with no credentials, query or fragment")
    return str(url).rstrip("/")


async def _update_sinks(db: AsyncSession, box, ws: int, tickets: TicketsIn) -> dict[str, list[str]]:
    changed: dict[str, list[str]] = {}
    for sink, body in (("jira", tickets.jira), ("servicenow", tickets.servicenow)):
        if body is None:
            continue
        fields, secret = ws_settings.SINK_FIELDS[sink]
        given = body.model_dump(include=body.model_fields_set)
        for field in fields:
            if field not in given:
                continue
            value = (given[field] or "").strip()
            if value and field == "base_url":
                value = _sink_url(value)
            elif value and not PLAIN_RE.match(value):
                raise ApiError(422, "invalid", f"{field} cannot hold control characters")
            elif value and field in FIELD_RULES and not FIELD_RULES[field][0].match(value):
                raise ApiError(422, "invalid", f"{field} must be {FIELD_RULES[field][1]}")
            name = ws_settings.sink_setting(sink, field)
            if (await store.get_value(db, ws, name) or "") != value:
                await store.set_value(db, ws, name, value or None)
                changed.setdefault(sink, []).append(field)
        if secret in given:
            value = given[secret] or ""
            if value and not SECRET_RE.match(value):
                raise ApiError(422, "invalid", f"{secret} must be 1 to 512 printable characters")
            name = ws_settings.sink_setting(sink, secret)
            had = bool(await store.get_secret(db, box, ws, name))
            await store.set_secret(db, box, ws, name, value)
            if value or had:
                changed.setdefault(sink, []).append(f"{secret} " + (("replaced" if had else "set") if value else "removed"))
    return changed


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

    if body.tickets is not None:
        sinks = await _update_sinks(db, box, ws, body.tickets)
        if sinks:
            changed["tickets"] = sinks

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
        "ticket_sinks": (await ws_settings.sink_config(db, server_box(), actor.workspace_id)).sinks(),
    }
