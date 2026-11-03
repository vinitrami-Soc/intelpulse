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
from ..platform import accounts, audit, auth, email_flows, mail, server_settings
from ..platform.box import server_box
from ..platform.deps import SESSION_COOKIE, login_throttle, require_actor
from ..platform.errors import ApiError
from ..security import client_ip, limiter

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


class SignUp(BaseModel):
    model_config = {"extra": "forbid"}
    kind: str = Field(..., max_length=20, description="`individual` (just me) or `organization`")
    username: str = Field(..., max_length=64)
    password: str = Field(..., max_length=1024)
    display_name: str = Field("", max_length=200)
    organization: str = Field("", max_length=200)
    email: str | None = Field(None, max_length=254)


async def _payload(db: AsyncSession, user: User | None, row: LoginSession | None) -> dict[str, Any]:
    workspace = await db.get(Workspace, user.workspace_id) if user else None
    setup_needed = user is None and await accounts.needs_setup(db)
    return {
        "mode": "server",
        "setup_needed": setup_needed,
        "signup": not setup_needed and await server_settings.signup_open(db),
        "email": mail.enabled(),
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
    await email_flows.send_confirmation(db, user)
    return await _open(db, response, user)


@router.post("/signup", status_code=201)
async def sign_up(
    body: SignUp, request: Request, response: Response, db: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    """A new workspace and its admin, signed in: only while the owner allows sign-up."""
    key = "signup:" + client_ip(request)
    limit = settings.signup_per_address_daily
    wait = limiter.wait(key, limit, 86_400)
    if wait:
        raise ApiError(429, "throttled", f"too many sign-ups from this address: try again in {wait // 3600 + 1} h",
                       {"Retry-After": str(wait)})
    user = await accounts.sign_up(
        db, kind=body.kind, username=body.username.strip().lower(), password=body.password,
        display_name=body.display_name, organization=body.organization, email=body.email,
    )
    limiter.record(key, 86_400)
    await email_flows.send_confirmation(db, user)
    return await _open(db, response, user)


class Forgot(BaseModel):
    login: str = Field(..., max_length=254, description="a username or an email address")


class Reset(BaseModel):
    token: str = Field(..., max_length=200)
    password: str = Field(..., max_length=1024)


class Confirm(BaseModel):
    token: str = Field(..., max_length=200)


FORGOT_ANSWER = ("if an account has that username or address, and the address is confirmed, a link to reset "
                 "its password is on its way: it works once, for one hour")


@router.post("/password/forgot", status_code=202)
async def forgot_password(body: Forgot, request: Request, db: AsyncSession = Depends(get_session)) -> dict[str, str]:
    """The same answer whether or not an account matches."""
    if not mail.enabled():
        raise ApiError(409, "email_off", "this server does not send email: ask an admin to set a new password")
    key = "forgot:" + client_ip(request)
    wait = limiter.wait(key, 5, 3600)
    if wait:
        raise ApiError(429, "throttled", f"too many requests from this address: try again in {wait // 60 + 1} min",
                       {"Retry-After": str(wait)})
    limiter.record(key, 3600)
    await email_flows.forgot(db, body.login)
    return {"detail": FORGOT_ANSWER}


@router.post("/password/reset")
async def reset_password(body: Reset, request: Request, db: AsyncSession = Depends(get_session)) -> dict[str, str]:
    """A new password with the emailed link: once, within the hour. Every session of the account ends."""
    keys = ("reset:" + client_ip(request),)
    wait = login_throttle.wait(*keys)
    if wait > 0:
        raise ApiError(429, "throttled", f"too many invalid links: wait {int(wait) + 1} s", {"Retry-After": str(int(wait) + 1)})
    try:
        await email_flows.reset(db, body.token.strip(), body.password)
    except ApiError as exc:
        if exc.status_code == 404:
            login_throttle.failed(*keys)
        raise
    return {"detail": "password changed: sign in with it. Every session of the account has ended"}


@router.post("/email/confirm")
async def confirm_email(body: Confirm, request: Request, db: AsyncSession = Depends(get_session)) -> dict[str, str]:
    """Confirm an address with the emailed link (the page's button sends this, never the link itself)."""
    keys = ("confirm:" + client_ip(request),)
    wait = login_throttle.wait(*keys)
    if wait > 0:
        raise ApiError(429, "throttled", f"too many invalid links: wait {int(wait) + 1} s", {"Retry-After": str(int(wait) + 1)})
    try:
        user = await email_flows.confirm(db, body.token.strip())
    except ApiError as exc:
        login_throttle.failed(*keys)
        raise exc
    return {"detail": "address confirmed", "email": user.email or ""}
