"""A person's own account: their name, email and password.

Changing the password needs the current one, ends every other session of the
account, and clears the "choose a new password" flag an admin's reset sets.
"""
from __future__ import annotations

import re
from datetime import timedelta

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import EmailToken, User, Workspace, utcnow
from ..platform import audit, auth, email_flows, mail
from ..platform.auth import Actor
from ..platform.deps import login_throttle, require_member
from ..platform.errors import ApiError
from ..text import clean_label

router = APIRouter(tags=["profile"])

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")


class ProfileUpdate(BaseModel):
    model_config = {"extra": "forbid"}
    display_name: str | None = Field(None, max_length=120)
    email: str | None = Field(None, max_length=254)
    current_password: str | None = Field(None, max_length=1024)
    new_password: str | None = Field(None, max_length=1024)


async def _profile(db: AsyncSession, user: User) -> dict:
    workspace = await db.get(Workspace, user.workspace_id)
    return {
        "id": user.id, "username": user.username, "display_name": user.display_name, "email": user.email,
        "email_confirmed": user.email_confirmed_at is not None, "email_enabled": mail.enabled(),
        "role": user.role, "owner": user.owner, "must_change_password": user.must_change_password,
        "workspace": {"id": workspace.id, "name": workspace.name, "kind": workspace.kind} if workspace else None,
    }


async def _confirm_password(db: AsyncSession, user: User, sent: str | None) -> None:
    """The account's own password, before what a stolen session could use to keep the account:
    a new password, or a new address for the reset link. Wrong guesses slow down as at sign-in."""
    key = "user:" + user.username
    wait = login_throttle.wait(key)
    if wait > 0:
        raise ApiError(429, "throttled", f"too many wrong passwords: wait {int(wait) + 1} s",
                       {"Retry-After": str(int(wait) + 1)})
    if await auth.check_login(db, user.username, sent or "") is None:
        login_throttle.failed(key)
        raise ApiError(403, "wrong_password", "the current password is not right")
    login_throttle.succeeded(key)


@router.get("/profile")
async def read_profile(actor: Actor = Depends(require_member), db: AsyncSession = Depends(get_session)) -> dict:
    return await _profile(db, await db.get(User, actor.user_id))


@router.patch("/profile")
async def update_profile(body: ProfileUpdate, actor: Actor = Depends(require_member),
                         db: AsyncSession = Depends(get_session)) -> dict:
    user = await db.get(User, actor.user_id)
    given = body.model_dump(include=body.model_fields_set)
    changed: list[str] = []
    if actor.must_change_password and not given.get("new_password"):
        raise ApiError(403, "password_change_required", "choose a new password first")

    if "display_name" in given:
        name = clean_label(given["display_name"] or "", 120) or user.username
        if name != user.display_name:
            user.display_name = name
            changed.append("display_name")
    if "email" in given:
        email = (given["email"] or "").strip() or None
        if email is not None and not EMAIL_RE.match(email):
            raise ApiError(422, "invalid", "that is not an email address")
        if email != user.email:
            await _confirm_password(db, user, given.get("current_password"))
            user.email = email
            user.email_confirmed_at = None
            changed.append("email")
            await db.flush()
            await email_flows.send_confirmation(db, user)
    if given.get("new_password"):
        current = given.get("current_password") or ""
        await _confirm_password(db, user, current)
        if current == given["new_password"]:
            raise ApiError(422, "invalid", "choose a password that is not the current one")
        try:
            auth.set_password(user, given["new_password"])   # clears must_change_password
        except auth.AuthError as exc:
            raise ApiError(422, "invalid", str(exc)) from exc
        await auth.end_sessions(db, user.id, keep=actor.session_id)
        changed.append("password")
    if not given:
        raise ApiError(422, "invalid", "nothing to change")
    if changed:
        await audit.record(db, action="profile.updated", actor=actor.label, workspace_id=actor.workspace_id,
                           target=user.username, detail={"changed": changed})
    return {**await _profile(db, user), "changed": changed}


@router.post("/profile/email/confirm", status_code=202)
async def send_confirmation_again(actor: Actor = Depends(require_member), db: AsyncSession = Depends(get_session)) -> dict:
    """Mail the confirmation link again for the account's address."""
    user = await db.get(User, actor.user_id)
    if not mail.enabled():
        raise ApiError(409, "email_off", "this server does not send email")
    if not user.email:
        raise ApiError(422, "invalid", "add an address first")
    if user.email_confirmed_at is not None:
        return {"detail": "this address is confirmed already"}
    recent = (await db.execute(select(func.count(EmailToken.id)).where(
        EmailToken.user_id == user.id, EmailToken.purpose == "confirm",
        EmailToken.created_at >= utcnow() - timedelta(hours=1)))).scalar_one()
    if recent >= 3:
        raise ApiError(429, "throttled", "three links in an hour: look for the ones already sent")
    await email_flows.send_confirmation(db, user)
    return {"detail": "a confirmation link is on its way to " + user.email}
