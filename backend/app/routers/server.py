"""The server's own settings (spec 9.3, Server pane): the owner's alone."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import SERVER
from ..platform import audit, server_settings
from ..platform import settings_store as store
from ..platform.auth import Actor
from ..platform.deps import require_session_owner
from ..platform.errors import ApiError

router = APIRouter(tags=["server"])


class ServerUpdate(BaseModel):
    """Send only what changes."""

    model_config = {"extra": "forbid"}
    signup: bool | None = None
    signup_daily_cap: int | None = Field(None, ge=server_settings.CAP_RANGE[0], le=server_settings.CAP_RANGE[1])


@router.get("/server")
async def read_server(_owner: Actor = Depends(require_session_owner),
                      db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Whether sign-up is open, the daily cap of new workspaces and today's count, and how many
    workspaces and accounts the server holds. Nothing of any workspace's cases."""
    return await server_settings.describe(db)


@router.patch("/server")
async def update_server(body: ServerUpdate, actor: Actor = Depends(require_session_owner),
                        db: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    given = body.model_dump(include=body.model_fields_set, exclude_none=True)
    if not given:
        raise ApiError(422, "invalid", "nothing to change: send signup or signup_daily_cap")
    changed = {}
    if "signup" in given and given["signup"] != await server_settings.signup_open(db):
        await store.set_value(db, SERVER, server_settings.SIGNUP, given["signup"])
        changed["signup"] = given["signup"]
    if "signup_daily_cap" in given and given["signup_daily_cap"] != await server_settings.signup_cap(db):
        await store.set_value(db, SERVER, server_settings.SIGNUP_CAP, given["signup_daily_cap"])
        changed["signup_daily_cap"] = given["signup_daily_cap"]
    if changed:
        await audit.record(db, action="server.updated", actor=actor.label, workspace_id=SERVER, detail=changed)
    return {**await server_settings.describe(db), "changed": sorted(changed)}
