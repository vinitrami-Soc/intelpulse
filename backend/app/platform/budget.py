"""Triage budgets (spec 11.2): so one person, or one workspace, cannot spend the whole server's
provider quota.

On top of the per-address buckets every request already passes: each caller (a
person, a token, the 1.x token) runs at most RATE_LIMIT_USER_TRIAGE triages a
minute, and each workspace at most the owner's daily budget of triages and pushed
alerts (500 until the owner sets another). In-process, like the address buckets:
one API container is the deployment this targets.
"""
from __future__ import annotations

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..security import limiter
from . import server_settings
from .auth import Actor
from .deps import require_actor
from .errors import ApiError

DAY = 86_400


def caller_key(actor: Actor) -> str:
    """One bucket for each person, each token, and the 1.x token: never shared across workspaces."""
    if actor.via == "session":
        return f"triage-user:{actor.user_id}"
    if actor.via == "token":
        return f"triage-token:{actor.token_id}"
    return f"triage-legacy:{actor.workspace_id}"


async def spend_triage(actor: Actor = Depends(require_actor), db: AsyncSession = Depends(get_session)) -> None:
    """A dependency: refuse with 429 when the caller or its workspace is out of triages, else count one."""
    if not settings.rate_limit_enabled:
        return
    budget = await server_settings.triage_budget(db)
    # no await from here to the records: two requests at once cannot both take the last triage
    mine, theirs = caller_key(actor), f"triage-workspace:{actor.workspace_id}"
    per_minute = settings.rate_limit_user_triage
    wait = limiter.wait(mine, per_minute, 60)
    if wait:
        raise ApiError(429, "user_rate", f"{per_minute} triages a minute at most: try again in {wait} s",
                       {"Retry-After": str(wait)})
    wait = limiter.wait(theirs, budget, DAY)
    if wait:
        raise ApiError(429, "workspace_budget",
                       f"this workspace has used its {budget} triages and pushed alerts for today: "
                       f"try again in {wait // 3600 + 1} h, or ask the server's owner for a larger budget",
                       {"Retry-After": str(wait)})
    limiter.record(mine, 60)
    limiter.record(theirs, DAY)
