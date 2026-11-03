"""Invitations: an admin's to make, list and revoke (signed in); the link's to preview and use."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Path, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..models import Invite, User, Workspace
from ..platform import audit, invites
from ..platform.auth import Actor
from ..platform.deps import login_throttle, require_session_admin
from ..platform.errors import ApiError
from ..security import client_ip

router = APIRouter(tags=["team"])      # an admin's, behind the sign-in
public = APIRouter(tags=["account"])   # the link's, for someone with no account yet


class InviteIn(BaseModel):
    model_config = {"extra": "forbid"}
    role: Literal["analyst", "admin"] = "analyst"


class JoinCheck(BaseModel):
    token: str = Field(..., max_length=200)


class JoinIn(JoinCheck):
    model_config = {"extra": "forbid"}
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=1024)
    display_name: str = Field("", max_length=200)


def _iso(at) -> str | None:
    return at.isoformat() if at else None


def _link(token: str) -> str:
    """Where the invitation opens: the console's #/join view, on PUBLIC_URL when it is set."""
    base = settings.public_url.strip().rstrip("/")
    return (base + "/" if base else "") + "#/join/" + token


def _out(invite: Invite, made_by: str | None, used_by: str | None) -> dict[str, Any]:
    return {"id": invite.id, "role": invite.role, "state": invites.state(invite), "created_by": made_by,
            "created_at": _iso(invite.created_at), "expires_at": _iso(invite.expires_at),
            "used_at": _iso(invite.used_at), "used_by": used_by}


@router.post("/invites", status_code=201)
async def create_invite(body: InviteIn, actor: Actor = Depends(require_session_admin),
                        db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """A one-use link for a role, good for seven days. The token is shown once: send the link."""
    workspace = await db.get(Workspace, actor.workspace_id)
    token, invite = await invites.create(db, workspace=workspace, role=body.role, created_by=actor.user_id,
                                         actor=actor.label)
    return {**_out(invite, actor.username, None), "token": token, "link": _link(token)}


@router.get("/invites")
async def list_invites(actor: Actor = Depends(require_session_admin),
                       db: AsyncSession = Depends(get_session)) -> list[dict[str, Any]]:
    """The workspace's invitations, newest first: open, used or expired. Never their tokens."""
    made, used = User.__table__.alias("made"), User.__table__.alias("used")
    rows = (await db.execute(
        select(Invite, made.c.username, used.c.username)
        .outerjoin(made, made.c.id == Invite.created_by).outerjoin(used, used.c.id == Invite.used_by)
        .where(Invite.workspace_id == actor.workspace_id).order_by(Invite.id.desc()).limit(200)
    )).all()
    return [_out(invite, made_by, used_by) for invite, made_by, used_by in rows]


@router.delete("/invites/{invite_id}", status_code=204)
async def revoke_invite(invite_id: int = Path(..., ge=1, le=2**63 - 1), actor: Actor = Depends(require_session_admin),
                        db: AsyncSession = Depends(get_session)) -> None:
    invite = await db.get(Invite, invite_id)
    if invite is None or invite.workspace_id != actor.workspace_id:
        raise ApiError(404, "not_found", "invitation not found")
    if invite.used_at is not None:
        raise ApiError(409, "used", "this invitation was used already: remove the member instead")
    await audit.record(db, action="invite.revoked", actor=actor.label, workspace_id=actor.workspace_id,
                       target=str(invite.id), detail={"role": invite.role})
    await db.delete(invite)


def _throttled(request: Request) -> tuple[str, ...]:
    keys = ("join:" + client_ip(request),)
    wait = login_throttle.wait(*keys)
    if wait > 0:
        raise ApiError(429, "throttled", f"too many invalid invitations: wait {int(wait) + 1} s",
                       {"Retry-After": str(int(wait) + 1)})
    return keys


@public.post("/join/check")
async def check_invite(body: JoinCheck, request: Request, db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """What an invitation opens: the workspace's name and the role. The token travels in the body,
    never in a URL a log would keep."""
    keys = _throttled(request)
    try:
        invite = await invites.find(db, body.token.strip())
    except ApiError:
        login_throttle.failed(*keys)
        raise
    workspace = await db.get(Workspace, invite.workspace_id)
    return {"workspace": {"name": workspace.name, "kind": workspace.kind}, "role": invite.role,
            "expires_at": _iso(invite.expires_at)}


@public.post("/join", status_code=201)
async def join(body: JoinIn, request: Request, response: Response, db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Make one's own account with an invitation, and sign in. The link then stops working."""
    from .account import _open  # the same sign-in as setup and sign-up

    keys = _throttled(request)
    try:
        user = await invites.join(db, token=body.token.strip(), username=body.username.strip().lower(),
                                  password=body.password, display_name=body.display_name)
    except ApiError as exc:
        if exc.status_code == 404:
            login_throttle.failed(*keys)
        raise
    return await _open(db, response, user)
