"""A person's own account: their name, email and password.

Changing the password needs the current one, ends every other session of the
account, and clears the "choose a new password" flag an admin's reset sets.
"""
from __future__ import annotations

import re

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import User, Workspace
from ..platform import audit, auth
from ..platform.auth import Actor
from ..platform.deps import require_member
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
        "role": user.role, "owner": user.owner, "must_change_password": user.must_change_password,
        "workspace": {"id": workspace.id, "name": workspace.name, "kind": workspace.kind} if workspace else None,
    }


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
            user.email = email
            user.email_confirmed_at = None
            changed.append("email")
    if given.get("new_password"):
        current = given.get("current_password") or ""
        if await auth.check_login(db, user.username, current) is None:
            raise ApiError(403, "wrong_password", "the current password is not right")
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
