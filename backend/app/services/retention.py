"""Retention, deletion and hold (spec 6.5).

The sweep deletes tier 1 (a case's sealed input) once it is older than its
workspace's retention days, unless the case is held, and marks the case with when.
Everything else about the case (its verdict, indicators and workflow) stays. It
writes one audit record per workspace with the count, never the inputs.

Deleting by hand works the same way for one case. Deleting a case completely
removes tier 2 as well, and the audit record keeps the case ID and the SHA-256 of
the input it had, so a deleted case can still be named.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Case, CaseInput, Workspace, utcnow
from ..platform import audit
from . import workspace_settings as ws_settings

SWEEPER = "retention-sweep"


async def delete_input(db: AsyncSession, case: Case, *, actor: str, now: datetime | None = None) -> str | None:
    """Delete one case's tier 1 now; returns the SHA-256 it had, or None when there was none."""
    row = await db.get(CaseInput, case.id)
    if row is None:
        return None
    digest = row.sha256
    await db.delete(row)
    case.input_deleted_at = now or utcnow()
    await audit.record(db, action="case.input_deleted", actor=actor, workspace_id=case.workspace_id,
                       target=case.id, detail={"input_sha256": digest})
    return digest


async def sweep(db: AsyncSession, *, now: datetime | None = None) -> dict[int, int]:
    """One pass over every workspace; returns {workspace id: inputs deleted}."""
    now = now or utcnow()
    swept: dict[int, int] = {}
    for workspace_id in (await db.execute(select(Workspace.id).order_by(Workspace.id))).scalars().all():
        days = await ws_settings.retention_days(db, workspace_id)
        cutoff = now - timedelta(days=days)
        ids = (await db.execute(
            select(Case.id).join(CaseInput, CaseInput.case_id == Case.id)
            .where(Case.workspace_id == workspace_id, Case.created_at < cutoff, Case.held.is_(False))
        )).scalars().all()
        if not ids:
            continue
        await db.execute(delete(CaseInput).where(CaseInput.case_id.in_(ids)))
        await db.execute(update(Case).where(Case.id.in_(ids)).values(input_deleted_at=now))
        await audit.record(db, action="retention.swept", actor=SWEEPER, workspace_id=workspace_id,
                           detail={"inputs_deleted": len(ids), "retention_days": days})
        swept[workspace_id] = len(ids)
    return swept
