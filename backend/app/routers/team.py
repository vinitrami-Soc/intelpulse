"""The workspace's members: who they are, their role, and (for an admin) managing them.

Without email (M3), an admin sets a member's password and the member must
choose their own at the next sign-in; only the owner sets an admin's. A
workspace always keeps an active admin, nobody demotes, disables or deletes
themselves, and nobody but the owner touches the owner's account.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import ApiToken, Case, CaseTicket, User
from ..platform import audit, auth
from ..platform.auth import Actor
from ..platform.deps import require_member, require_session_admin
from ..platform.errors import ApiError
from ..text import clean_label

router = APIRouter(tags=["team"])


class MemberIn(BaseModel):
    model_config = {"extra": "forbid"}
    username: str = Field(..., max_length=64)
    display_name: str = Field("", max_length=120)
    role: Literal["admin", "analyst"] = "analyst"
    password: str = Field(..., max_length=1024)


class MemberUpdate(BaseModel):
    """Send only what changes. A new password must be changed by its owner at the next sign-in."""

    model_config = {"extra": "forbid"}
    display_name: str | None = Field(None, max_length=120)
    role: Literal["admin", "analyst"] | None = None
    disabled: bool | None = None
    password: str | None = Field(None, max_length=1024)


def _iso(at) -> str | None:
    return at.isoformat() if at else None


def _member(user: User, *, full: bool) -> dict[str, Any]:
    out = {"id": user.id, "username": user.username, "display_name": user.display_name, "role": user.role,
           "owner": user.owner, "disabled": user.disabled}
    if full:  # an admin also sees how to reach them and when they last signed in
        out.update(email=user.email, must_change_password=user.must_change_password,
                   created_at=_iso(user.created_at), last_login_at=_iso(user.last_login_at))
    return out


async def _in_workspace(db: AsyncSession, actor: Actor, user_id: int) -> User:
    user = await db.get(User, user_id)
    if user is None or user.workspace_id != actor.workspace_id:
        raise ApiError(404, "not_found", "member not found")
    return user


async def _other_active_admins(db: AsyncSession, user: User) -> int:
    return (await db.execute(
        select(func.count(User.id)).where(User.workspace_id == user.workspace_id, User.role == "admin",
                                          User.disabled.is_(False), User.id != user.id)
    )).scalar_one()


@router.get("/users")
async def list_members(actor: Actor = Depends(require_member), db: AsyncSession = Depends(get_session)) -> list[dict]:
    """Every member of the workspace (an analyst needs them to assign a case)."""
    users = (await db.execute(
        select(User).where(User.workspace_id == actor.workspace_id).order_by(User.username)
    )).scalars().all()
    return [_member(user, full=actor.is_admin) for user in users]


@router.post("/users", status_code=201)
async def add_member(body: MemberIn, actor: Actor = Depends(require_session_admin),
                     db: AsyncSession = Depends(get_session)) -> dict:
    try:
        user = await auth.create_user(db, body.username.strip().lower(), body.password, role=body.role,
                                      workspace_id=actor.workspace_id,
                                      display_name=clean_label(body.display_name, 120))
    except auth.AuthError as exc:
        raise ApiError(422, "invalid", str(exc)) from exc
    user.must_change_password = True
    await audit.record(db, action="user.created", actor=actor.label, workspace_id=actor.workspace_id,
                       target=user.username, detail={"role": user.role})
    return _member(user, full=True)


@router.patch("/users/{user_id}")
async def update_member(body: MemberUpdate, user_id: int = Path(..., ge=1, le=2**63 - 1),
                        actor: Actor = Depends(require_session_admin),
                        db: AsyncSession = Depends(get_session)) -> dict:
    user = await _in_workspace(db, actor, user_id)
    given = body.model_dump(include=body.model_fields_set)
    if not given:
        raise ApiError(422, "invalid", "nothing to change")
    if user.owner and not actor.owner:
        raise ApiError(403, "forbidden", "only the owner changes the owner's account")
    if user.id == actor.user_id and ({"role", "disabled"} & given.keys()):
        raise ApiError(403, "forbidden", "you cannot change your own role or disable yourself")
    if "password" in given and user.role == "admin" and user.id != actor.user_id and not actor.owner:
        raise ApiError(403, "forbidden", "only the owner sets an admin's password")
    if user.owner and given.get("role") == "analyst":
        raise ApiError(403, "forbidden", "the owner stays an admin")
    # Defence in depth: the acting admin is themselves an active admin and cannot act on
    # themselves, so this holds already; it stays should that ever change.
    losing_admin = user.role == "admin" and (given.get("role") == "analyst" or given.get("disabled") is True)
    if losing_admin and not await _other_active_admins(db, user):
        raise ApiError(409, "last_admin", "the workspace needs another active admin first")

    changed: list[str] = []
    if "display_name" in given:
        name = clean_label(given["display_name"] or "", 120) or user.username
        if name != user.display_name:
            user.display_name = name
            changed.append("display_name")
    if given.get("role") and given["role"] != user.role:
        user.role = given["role"]
        changed.append("role")
    if given.get("disabled") is not None and given["disabled"] != user.disabled:
        user.disabled = given["disabled"]
        changed.append("disabled" if user.disabled else "enabled")
        if user.disabled:
            await auth.end_sessions(db, user.id)
    if given.get("password"):
        try:
            auth.set_password(user, given["password"])
        except auth.AuthError as exc:
            raise ApiError(422, "invalid", str(exc)) from exc
        user.must_change_password = True   # theirs to choose at the next sign-in
        await auth.end_sessions(db, user.id)
        changed.append("password")
    if changed:
        await audit.record(db, action="user.updated", actor=actor.label, workspace_id=actor.workspace_id,
                           target=user.username, detail={"changed": changed, "role": user.role})
    return {**_member(user, full=True), "changed": changed}


@router.delete("/users/{user_id}", status_code=204)
async def remove_member(user_id: int = Path(..., ge=1, le=2**63 - 1), actor: Actor = Depends(require_session_admin),
                        db: AsyncSession = Depends(get_session)) -> None:
    """The account goes; their cases and audit records stay (a case's creator and assignee become nobody)."""
    user = await _in_workspace(db, actor, user_id)
    if user.owner:
        raise ApiError(403, "forbidden", "the owner's account cannot be removed")
    if user.id == actor.user_id:
        raise ApiError(403, "forbidden", "you cannot remove yourself")
    if user.role == "admin" and not user.disabled and not await _other_active_admins(db, user):
        raise ApiError(409, "last_admin", "the workspace needs another active admin first")
    await auth.end_sessions(db, user.id)
    # What the foreign keys do on Postgres, done by hand so SQLite agrees: their work stays, unattributed.
    await db.execute(update(Case).where(Case.assignee_id == user.id).values(assignee_id=None))
    await db.execute(update(Case).where(Case.created_by == user.id).values(created_by=None))
    await db.execute(update(CaseTicket).where(CaseTicket.created_by == user.id).values(created_by=None))
    await db.execute(update(ApiToken).where(ApiToken.created_by == user.id).values(created_by=None))
    await audit.record(db, action="user.removed", actor=actor.label, workspace_id=actor.workspace_id,
                       target=user.username, detail={"role": user.role})
    await db.delete(user)
