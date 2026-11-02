"""The case workflow (spec 8.3): status, assignee, closing, and the tickets raised.

A case starts `new`, is worked `in_progress` and is `closed` with a reason.
Closing stamps `closed_at`; reopening clears it and the reason. The assignee is
a member of the case's workspace who can still sign in. Every change is audited
with what it was and what it became.
"""
from __future__ import annotations

from datetime import UTC
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Case, CaseTicket, User, utcnow
from ..platform import audit
from ..platform.auth import Actor
from ..platform.errors import ApiError
from .tickets import Ticket

STATUSES = ("new", "in_progress", "closed")
CLOSED_REASONS = ("true_positive", "false_positive", "benign", "duplicate")


def iso(at) -> str | None:
    """UTC, always with its offset: SQLite hands datetimes back without one."""
    if not at:
        return None
    return (at if at.tzinfo is not None else at.replace(tzinfo=UTC)).isoformat()


async def member(db: AsyncSession, workspace_id: int, user_id: int) -> User | None:
    """A member of this workspace who can still sign in, or None."""
    user = await db.get(User, user_id)
    if user is None or user.workspace_id != workspace_id or user.disabled:
        return None
    return user


def person(user: User | None) -> dict[str, Any] | None:
    return None if user is None else {"id": user.id, "username": user.username, "display_name": user.display_name}


async def update_case(db: AsyncSession, actor: Actor, case: Case, changes: dict[str, Any]) -> dict[str, Any]:
    """Apply `changes` (status, assignee_id, closed_reason) to `case`; returns what changed."""
    before = {"status": case.status, "assignee_id": case.assignee_id, "closed_reason": case.closed_reason}
    status = changes.get("status", case.status)
    reason = changes.get("closed_reason", case.closed_reason if status == "closed" else None)

    if "assignee_id" in changes:
        assignee_id = changes["assignee_id"]
        if assignee_id is not None and await member(db, case.workspace_id, assignee_id) is None:
            raise ApiError(422, "invalid", "the assignee must be an active member of this workspace")
        case.assignee_id = assignee_id

    if status == "closed":
        if reason not in CLOSED_REASONS:
            raise ApiError(422, "invalid", "closing a case needs a reason: " + ", ".join(CLOSED_REASONS))
        if case.status != "closed" or case.closed_at is None:
            case.closed_at = utcnow()
        case.closed_reason = reason
    else:
        if "closed_reason" in changes and changes["closed_reason"] is not None:
            raise ApiError(422, "invalid", "only a closed case has a closing reason")
        case.closed_at = None
        case.closed_reason = None
    case.status = status

    after = {"status": case.status, "assignee_id": case.assignee_id, "closed_reason": case.closed_reason}
    changed = {key: {"from": before[key], "to": after[key]} for key in after if before[key] != after[key]}
    if changed:
        await audit.record(db, action="case.updated", actor=actor.label, workspace_id=case.workspace_id,
                           target=case.id, detail=changed)
    return changed


async def record_ticket(db: AsyncSession, actor: Actor, case: Case, ticket: Ticket) -> CaseTicket:
    """Keep the ticket with the case, and audit it."""
    row = CaseTicket(workspace_id=case.workspace_id, case_id=case.id, sink=ticket.sink, key=ticket.key[:120],
                     url=ticket.url[:500], created_by=actor.user_id)
    db.add(row)
    await audit.record(db, action="ticket.created", actor=actor.label, workspace_id=case.workspace_id,
                       target=case.id, detail=ticket.as_dict())
    return row


async def tickets_for(db: AsyncSession, case_id: str) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(CaseTicket, User.username)
            .outerjoin(User, User.id == CaseTicket.created_by)
            .where(CaseTicket.case_id == case_id)
            .order_by(CaseTicket.id)
        )
    ).all()
    return [{"sink": t.sink, "key": t.key, "url": t.url, "created_by": username, "created_at": iso(t.created_at)}
            for t, username in rows]


async def ticket_counts(db: AsyncSession, case_ids: list[str]) -> dict[str, int]:
    if not case_ids:
        return {}
    rows = await db.execute(
        select(CaseTicket.case_id, func.count(CaseTicket.id))
        .where(CaseTicket.case_id.in_(case_ids)).group_by(CaseTicket.case_id)
    )
    return dict(rows.all())
