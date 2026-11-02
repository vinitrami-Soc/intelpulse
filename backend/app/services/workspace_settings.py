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

logger = logging.getLogger(__name__)

RETENTION_DEFAULT = 30
RETENTION_RANGE = (1, 365)
IMPORTED = "provider_keys_imported"


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
    return {"providers": providers, "keys": keys, "retention_days": await retention_days(db, workspace_id)}


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
