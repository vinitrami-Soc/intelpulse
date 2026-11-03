"""Invitations (spec 5.4): an admin makes a one-use link for a role; whoever opens it
within seven days makes their own account in that workspace.

The token is 32 random bytes, shown once to the admin who made it; the server keeps
its SHA-256. A link that is unknown, used, revoked or expired gets the same answer,
so the answer tells a guesser nothing.
"""
from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Invite, User, Workspace, utcnow
from ..text import clean_label
from . import audit, auth
from .errors import ApiError

LIFETIME = timedelta(days=7)
ROLES = ("analyst", "admin")
GONE = "this invitation is not valid: it may have been used, revoked or expired. Ask for a new one"


def _aware(at: datetime) -> datetime:
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


def state(invite: Invite, now: datetime | None = None) -> str:
    if invite.used_at is not None:
        return "used"
    return "expired" if _aware(invite.expires_at) <= (now or utcnow()) else "open"


async def create(db: AsyncSession, *, workspace: Workspace, role: str, created_by: int | None,
                 actor: str) -> tuple[str, Invite]:
    if workspace.kind != "organization":
        raise ApiError(403, "forbidden", "an individual workspace has one member: it takes no invitations")
    if role not in ROLES:
        raise ApiError(422, "invalid", "role is analyst or admin")
    token = secrets.token_urlsafe(32)
    invite = Invite(workspace_id=workspace.id, role=role, token_hash=auth.digest(token), created_by=created_by,
                    expires_at=utcnow() + LIFETIME)
    db.add(invite)
    await db.flush()
    await audit.record(db, action="invite.created", actor=actor, workspace_id=workspace.id,
                       target=str(invite.id), detail={"role": role})
    return token, invite


async def find(db: AsyncSession, token: str, *, lock: bool = False) -> Invite:
    """The open invitation this token names, or 404 in every other case."""
    if not token or len(token) > 200:
        raise ApiError(404, "not_found", GONE)
    query = select(Invite).where(Invite.token_hash == auth.digest(token))
    if lock:
        query = query.with_for_update()
    invite = (await db.execute(query)).scalars().first()
    if invite is None or state(invite) != "open":
        raise ApiError(404, "not_found", GONE)
    return invite


async def join(db: AsyncSession, *, token: str, username: str, password: str, display_name: str = "") -> User:
    """The new member's account, in the invitation's workspace and role; the link then stops working."""
    invite = await find(db, token, lock=True)   # locked: two people opening one link cannot both join
    try:
        user = await auth.create_user(db, username, password, role=invite.role, workspace_id=invite.workspace_id,
                                      display_name=clean_label(display_name, 120))
    except auth.AuthError as exc:
        raise ApiError(422, "invalid", str(exc)) from exc
    invite.used_at = utcnow()
    invite.used_by = user.id
    await audit.record(db, action="invite.used", actor=user.username, workspace_id=invite.workspace_id,
                       target=str(invite.id), detail={"role": invite.role})
    return user
