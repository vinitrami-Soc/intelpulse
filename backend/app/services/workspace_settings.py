"""A workspace's own settings: its provider keys and switches, and its retention.

Keys are sealed (settings_store) and never read back: the API shows whether one
is set and its last four characters. Scoring weights stay server configuration,
so a verdict means the same thing in every workspace (spec 7).
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..enrichment import PROVIDERS
from ..enrichment.credentials import ENV_KEYS, KEY_SLOTS, Credentials
from ..models import DEFAULT_WORKSPACE_ID, SERVER
from ..platform import audit
from ..platform import settings_store as store
from ..platform.crypto import Box
from .tickets import JIRA, SERVICENOW, SinkConfig

logger = logging.getLogger(__name__)

RETENTION_DEFAULT = 30
RETENTION_RANGE = (1, 365)
IMPORTED = "provider_keys_imported"
SINKS_IMPORTED = "ticket_sinks_imported"

# Each tracker's plain fields and its one secret, as SinkConfig names them.
SINK_FIELDS: dict[str, tuple[tuple[str, ...], str]] = {
    JIRA: (("base_url", "email", "project_key", "issue_type"), "api_token"),
    SERVICENOW: (("base_url", "user", "table"), "password"),
}
SINK_DEFAULTS = {"jira_issue_type": "Task", "servicenow_table": "incident"}


def sink_setting(sink: str, field: str) -> str:
    return f"sink:{sink}:{field}"


def key_setting(slot: str) -> str:
    return f"provider_key:{slot}"


def enabled_setting(provider: str) -> str:
    return f"provider_enabled:{provider}"


async def credentials_for(db: AsyncSession, box: Box, workspace_id: int) -> Credentials:
    keys = {}
    for slot in KEY_SLOTS:
        value = await store.get_secret(db, box, workspace_id, key_setting(slot))
        if value:
            keys[slot] = value
    disabled = set()
    for provider in PROVIDERS:
        if await store.get_value(db, workspace_id, enabled_setting(provider.name), True) is False:
            disabled.add(provider.name)
    return Credentials(workspace_id=workspace_id, keys=keys, disabled=frozenset(disabled))


async def sink_config(db: AsyncSession, box: Box, workspace_id: int) -> SinkConfig:
    values: dict[str, str | None] = {}
    for sink, (fields, secret) in SINK_FIELDS.items():
        for field in fields:
            value = await store.get_value(db, workspace_id, sink_setting(sink, field))
            values[f"{sink}_{field}"] = value if isinstance(value, str) and value else None
        values[f"{sink}_{secret}"] = await store.get_secret(db, box, workspace_id, sink_setting(sink, secret))
    for name, default in SINK_DEFAULTS.items():
        values[name] = values.get(name) or default
    return SinkConfig(**values)


async def describe_sinks(db: AsyncSession, box: Box, workspace_id: int) -> dict[str, Any]:
    config = await sink_config(db, box, workspace_id)
    out: dict[str, Any] = {"configured": config.sinks()}
    for sink, (fields, secret) in SINK_FIELDS.items():
        secret_value = getattr(config, f"{sink}_{secret}")
        out[sink] = {field: getattr(config, f"{sink}_{field}") for field in fields}
        out[sink][secret] = {"set": bool(secret_value), "hint": store.mask(secret_value)}
    return out


async def retention_days(db: AsyncSession, workspace_id: int) -> int:
    value = await store.get_value(db, workspace_id, "retention_days", RETENTION_DEFAULT)
    return value if isinstance(value, int) and RETENTION_RANGE[0] <= value <= RETENTION_RANGE[1] else RETENTION_DEFAULT


async def describe(db: AsyncSession, box: Box, workspace_id: int) -> dict[str, Any]:
    """What an admin sees: never a key, only whether one is set and its last characters."""
    keys = {}
    for slot, label in KEY_SLOTS.items():
        value = await store.get_secret(db, box, workspace_id, key_setting(slot))
        keys[slot] = {"label": label, "set": bool(value), "hint": store.mask(value),
                      "used_by": [p.name for p in PROVIDERS if getattr(p, "key_slot", None) == slot]}
    providers = []
    for provider in PROVIDERS:
        slot = getattr(provider, "key_slot", None)
        enabled = await store.get_value(db, workspace_id, enabled_setting(provider.name), True) is not False
        providers.append({
            "name": provider.name, "label": provider.label, "supported_types": sorted(provider.supported_types),
            "requires_key": provider.requires_key, "key_slot": slot, "enabled": enabled,
            "key_set": bool(slot and keys[slot]["set"]),
        })
    return {"providers": providers, "keys": keys, "retention_days": await retention_days(db, workspace_id),
            "tickets": await describe_sinks(db, box, workspace_id)}


async def import_env_keys(db: AsyncSession, box: Box) -> list[str]:
    """Once, on the first start of v2: the keys 1.x read from the environment move into the
    default organization's settings. From then on, only workspace settings hold keys."""
    if await store.get_value(db, SERVER, IMPORTED) is not None:
        if any(getattr(settings, attr) for attr in ENV_KEYS.values()):
            logger.warning("provider keys in the environment are ignored since v2: set them in Settings")
        return []
    moved = []
    for slot, attr in ENV_KEYS.items():
        value = getattr(settings, attr)
        if value and not await store.get_secret(db, box, DEFAULT_WORKSPACE_ID, key_setting(slot)):
            await store.set_secret(db, box, DEFAULT_WORKSPACE_ID, key_setting(slot), value)
            moved.append(slot)
    await store.set_value(db, SERVER, IMPORTED, True)
    if moved:
        await audit.record(db, action="settings.keys_imported", actor="server", workspace_id=DEFAULT_WORKSPACE_ID,
                           detail={"slots": moved})
        logger.warning("provider keys moved from the environment into the default organization's settings: %s; "
                       "remove them from the environment", ", ".join(moved))
    return moved


async def import_env_sinks(db: AsyncSession, box: Box) -> list[str]:
    """Once, on the first start of this version: the Jira and ServiceNow settings 1.x read
    from the environment move into the default organization, the secrets sealed."""
    if await store.get_value(db, SERVER, SINKS_IMPORTED) is not None:
        return []
    env = SinkConfig.from_env()
    moved = []
    for sink, (fields, secret) in SINK_FIELDS.items():
        if sink not in env.sinks():
            continue
        if await store.get_value(db, DEFAULT_WORKSPACE_ID, sink_setting(sink, "base_url")):
            continue  # the organization set its own already
        for field in fields:
            value = getattr(env, f"{sink}_{field}")
            if value:
                await store.set_value(db, DEFAULT_WORKSPACE_ID, sink_setting(sink, field), value)
        await store.set_secret(db, box, DEFAULT_WORKSPACE_ID, sink_setting(sink, secret), getattr(env, f"{sink}_{secret}"))
        moved.append(sink)
    await store.set_value(db, SERVER, SINKS_IMPORTED, True)
    if moved:
        await audit.record(db, action="settings.sinks_imported", actor="server", workspace_id=DEFAULT_WORKSPACE_ID,
                           detail={"sinks": moved})
        logger.warning("ticket settings moved from the environment into the default organization: %s",
                       ", ".join(moved))
    return moved

