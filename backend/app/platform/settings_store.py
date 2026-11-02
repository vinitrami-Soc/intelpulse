"""Settings of a workspace, or of the server (workspace ``SERVER``).

Plain values are JSON; secrets (provider keys, ticket credentials, the setup
code) are kept only sealed, each bound to ``settings:<workspace>:<key>`` so a
sealed value copied to another workspace or key does not open. Secrets are
written and checked, never handed back to a browser: callers that show them
use ``mask()``.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Setting, utcnow
from .crypto import Box


def _bound(workspace_id: int, key: str) -> str:
    return f"settings:{workspace_id}:{key}"


async def _row(db: AsyncSession, workspace_id: int, key: str) -> Setting | None:
    return (
        await db.execute(select(Setting).where(Setting.workspace_id == workspace_id, Setting.key == key))
    ).scalars().first()


async def get_value(db: AsyncSession, workspace_id: int, key: str, default: Any = None) -> Any:
    row = await _row(db, workspace_id, key)
    return default if row is None or row.value is None else row.value


async def set_value(db: AsyncSession, workspace_id: int, key: str, value: Any) -> None:
    row = await _row(db, workspace_id, key)
    if row is None:
        row = Setting(workspace_id=workspace_id, key=key)
        db.add(row)
    row.value, row.sealed, row.updated_at = value, None, utcnow()
    await db.flush()


async def get_secret(db: AsyncSession, box: Box, workspace_id: int, key: str) -> str | None:
    row = await _row(db, workspace_id, key)
    if row is None or not row.sealed:
        return None
    return box.open(row.sealed, _bound(workspace_id, key)).decode("utf-8")


async def set_secret(db: AsyncSession, box: Box, workspace_id: int, key: str, secret: str | None) -> None:
    """Store a secret sealed; None or "" removes it."""
    row = await _row(db, workspace_id, key)
    if not secret:
        if row is not None:
            await db.delete(row)
            await db.flush()
        return
    if row is None:
        row = Setting(workspace_id=workspace_id, key=key)
        db.add(row)
    row.value, row.updated_at = None, utcnow()
    row.sealed = box.seal(secret.encode("utf-8"), _bound(workspace_id, key))
    await db.flush()


def mask(secret: str | None) -> str | None:
    """How a stored secret is shown: its last four characters, at most."""
    if not secret:
        return None
    return "•" * 8 + secret[-4:] if len(secret) > 8 else "•" * 8
