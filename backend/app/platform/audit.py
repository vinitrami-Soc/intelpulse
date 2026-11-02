"""The append-only, hash-chained audit log. Ported from PhishHawk's ``server/audit.py``.

One chain for the whole server. Each record says whose it is: a workspace's,
or the server's own (``SERVER``). Its hash covers the previous record's hash
and its own fields, and ``audit_head`` keeps the newest hash and the count, so
``verify()`` reports any record that was edited, removed or reordered, and a
log cut off at the end.

``digest()`` must never change: migration 0003 holds a frozen copy of it,
used to chain the records written before the chain existed.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import AuditHead, AuditLog, utcnow

GENESIS = "0" * 64


def _stamp(at: datetime) -> str:
    """UTC without an offset: SQLite hands datetimes back without one."""
    if at.tzinfo is not None:
        at = at.astimezone(UTC).replace(tzinfo=None)
    return at.isoformat()


def digest(prev_hash: str, entry: AuditLog) -> str:
    body: dict[str, Any] = {
        "at": _stamp(entry.created_at),
        "actor": entry.actor,
        "action": entry.action,
        "target": entry.target,
        "detail": entry.detail,
    }
    if entry.workspace_id is not None:
        body["workspace"] = entry.workspace_id
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


async def record(
    db: AsyncSession,
    *,
    action: str,
    actor: str,
    workspace_id: int | None,
    target: str | None = None,
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    """Append one record inside the caller's transaction."""
    head = (await db.execute(select(AuditHead).with_for_update())).scalars().first()
    if head is None:
        head = AuditHead(id=1, hash=GENESIS, count=0)
        db.add(head)
    entry = AuditLog(
        workspace_id=workspace_id,
        action=action,
        actor=actor,
        target=target,
        detail=detail or {},
        created_at=utcnow().replace(microsecond=0),
        prev_hash=head.hash,
    )
    entry.hash = digest(head.hash, entry)
    db.add(entry)
    head.hash, head.count = entry.hash, head.count + 1
    await db.flush()
    return entry


async def verify(db: AsyncSession) -> list[str]:
    """What is wrong with the log, or an empty list when it is intact."""
    problems: list[str] = []
    prev, count = GENESIS, 0
    for entry in (await db.execute(select(AuditLog).order_by(AuditLog.id))).scalars():
        count += 1
        if entry.prev_hash != prev:
            problems.append(f"record {entry.id} does not follow the one before it")
        if entry.hash != digest(entry.prev_hash, entry):
            problems.append(f"record {entry.id} was changed")
        prev = entry.hash
    head = (await db.execute(select(AuditHead))).scalars().first()
    recorded = head.count if head is not None else 0
    if (head is not None and head.hash != prev) or recorded != count:
        problems.append(f"the newest records are missing ({recorded} recorded, {count} found)")
    return problems
