"""The server's own settings, the owner's to change: whether anyone may sign up, and how many
new workspaces a day the server takes. Kept in the settings store under workspace SERVER."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DEFAULT_WORKSPACE_ID, SERVER, User, Workspace, utcnow
from . import settings_store as store

SIGNUP = "signup_enabled"
SIGNUP_CAP = "signup_daily_cap"
CAP_DEFAULT = 100
CAP_RANGE = (0, 100_000)


async def signup_open(db: AsyncSession) -> bool:
    """Off until the owner turns it on."""
    return await store.get_value(db, SERVER, SIGNUP, False) is True


async def signup_cap(db: AsyncSession) -> int:
    value = await store.get_value(db, SERVER, SIGNUP_CAP, CAP_DEFAULT)
    return value if isinstance(value, int) and not isinstance(value, bool) and CAP_RANGE[0] <= value <= CAP_RANGE[1] \
        else CAP_DEFAULT


async def signups_today(db: AsyncSession) -> int:
    """Workspaces made in the last 24 hours, the default organization aside."""
    since = utcnow() - timedelta(days=1)
    return (await db.execute(
        select(func.count(Workspace.id)).where(Workspace.created_at >= since, Workspace.id != DEFAULT_WORKSPACE_ID)
    )).scalar_one()


async def describe(db: AsyncSession) -> dict[str, Any]:
    return {
        "signup": await signup_open(db),
        "signup_daily_cap": await signup_cap(db),
        "signups_today": await signups_today(db),
        "workspaces": (await db.execute(select(func.count(Workspace.id)))).scalar_one(),
        "users": (await db.execute(select(func.count(User.id)))).scalar_one(),
    }
