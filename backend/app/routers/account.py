"""Signing in and out, and the owner's one-time setup.

`GET /api/session` is how the console tells a server from the static demo: a
JSON answer here means server mode.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..models import SERVER, LoginSession, User, Workspace
from ..platform import accounts, audit, auth
from ..platform.box import server_box
from ..platform.deps import SESSION_COOKIE, login_throttle, require_actor
from ..platform.errors import ApiError
from ..security import client_ip

router = APIRouter(tags=["account"])


class SignIn(BaseModel):
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=1024)


class SetUp(BaseModel):
    code: str = Field(..., max_length=64)
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=1024)
    organization: str = Field(..., max_length=200)
    display_name: str = Field("", max_length=200)
    email: str | None = Field(None, max_length=254)


async def _payload(db: AsyncSession, user: User | None, row: LoginSession | None) -> dict[str, Any]:
    workspace = await db.get(Workspace, user.workspace_id) if user else None
    return {
        "mode": "server",
        "setup_needed": user is None and await accounts.needs_setup(db),
        "signup": False,  # sign-up arrives with milestone M3
        "email": False,
        "user": None if user is None else {
            "id": user.id,
            "username": user.username,
            "display_name": user.display_name,
            "role": user.role,
            "owner": user.owner,
            "must_change_password": user.must_change_password,
        },
        "workspace": None if workspace is None else {
            "id": workspace.id, "name": workspace.name, "kind": workspace.kind,
        },
        "csrf": row.csrf_token if row else None,
    }


def _set_cookie(response: Response, cookie: str) -> None:
    response.set_cookie(
        SESSION_COOKIE, cookie, httponly=True, secure=settings.cookie_secure, samesite="strict",
        max_age=int(auth.SESSION_ABSOLUTE.total_seconds()), path="/",
    )


async def _open(db: AsyncSession, response: Response, user: User) -> dict[str, Any]:
    cookie, row = await auth.open_session(db, user)
    _set_cookie(response, cookie)
    return await _payload(db, user, row)


@router.get("/session")
async def read_session(request: Request, db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Who is signed in on this browser, the CSRF token for their writes, and whether the server needs setup."""
    cookie = request.cookies.get(SESSION_COOKIE)
    actor = await auth.find_session(db, cookie) if cookie else None
    if actor is None:
        return await _payload(db, None, None)
    return await _payload(db, await db.get(User, actor.user_id), await db.get(LoginSession, actor.session_id))


@router.post("/session")
async def sign_in(
    body: SignIn, request: Request, response: Response, db: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    username = body.username.strip().lower()
    keys = ("user:" + username, "ip:" + client_ip(request))
    wait = login_throttle.wait(*keys)
    if wait > 0:
        raise ApiError(429, "throttled", f"too many failed sign-ins: wait {int(wait) + 1} s",
                       {"Retry-After": str(int(wait) + 1)})
    user = await auth.check_login(db, username, body.password)
    if user is None:
        login_throttle.failed(*keys)
        # whose, nobody knows yet: the record belongs to the server, not to a workspace
        await audit.record(db, action="session.failed", actor=username[:64] or "?", workspace_id=SERVER)
        await db.commit()
        raise ApiError(401, "unauthorized", "wrong username or password")
    login_throttle.succeeded(*keys)
    await audit.record(db, action="session.opened", actor=user.username, workspace_id=user.workspace_id)
    return await _open(db, response, user)


@router.delete("/session", status_code=204)
async def sign_out(
    request: Request, response: Response, actor: auth.Actor = Depends(require_actor),
    db: AsyncSession = Depends(get_session),
) -> None:
    cookie = request.cookies.get(SESSION_COOKIE)
    if actor.via == "session" and cookie:
        await auth.close_session(db, cookie)
        await audit.record(db, action="session.closed", actor=actor.label, workspace_id=actor.workspace_id)
    response.delete_cookie(SESSION_COOKIE, path="/", secure=settings.cookie_secure, httponly=True,
                           samesite="strict")


@router.post("/setup", status_code=201)
async def set_up(
    body: SetUp, request: Request, response: Response, db: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    """The owner's account, with the code `python -m app.cli setup-code` printed. Works once."""
    keys = ("setup:" + client_ip(request),)
    wait = login_throttle.wait(*keys)
    if wait > 0:
        raise ApiError(429, "throttled", f"too many wrong codes: wait {int(wait) + 1} s",
                       {"Retry-After": str(int(wait) + 1)})
    try:
        user = await accounts.set_up(
            db, server_box(), code=body.code, username=body.username.strip().lower(), password=body.password,
            organization=body.organization, display_name=body.display_name, email=body.email,
        )
    except ApiError as exc:
        if exc.error == "wrong_code":
            login_throttle.failed(*keys)
        raise
    login_throttle.succeeded(*keys)
    return await _open(db, response, user)
