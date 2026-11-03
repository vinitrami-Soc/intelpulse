"""The data behind the console's views (spec 9.2), each read from the caller's workspace.

Reads only: a session of any role, an API token of any scope that reads, and the
1.x API_TOKEN (in the default organization) all reach them.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..enrichment import PROVIDERS, credentials
from ..platform.auth import Actor
from ..platform.box import server_box
from ..platform.deps import require_actor
from ..services import feeds, views
from ..services import workspace_settings as ws_settings

router = APIRouter(tags=["views"])

Verdict = Literal["informational", "low", "medium", "high", "critical"]


@router.get("/indicators")
async def list_indicators(
    q: str = Query("", max_length=200, description="part of the indicator"),
    type: str | None = Query(None, max_length=16, pattern=r"^[a-z0-9_]+$", description="ip, domain, url, sha256, ..."),
    verdict: Verdict | None = Query(None, description="the latest verdict"),
    sort: Literal["last_seen", "score", "cases"] = "last_seen",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=2**63 - 1),
    actor: Actor = Depends(require_actor),
    db: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """Each indicator once: its latest verdict and score, first and last seen, how many
    cases name it, and the providers that flagged it the last time it was triaged."""
    return await views.indicators(db, actor.workspace_id, q=q, ioc_type=type, verdict=verdict, sort=sort,
                                  limit=limit, offset=offset)


@router.get("/campaigns")
async def list_campaigns(
    days: int = Query(90, ge=1, le=365),
    actor: Actor = Depends(require_actor),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Cases of the last `days` days joined when they share a malware family or
    infrastructure (an indicator, or a relation's target such as an ASN). Only an
    indicator scored low or above joins cases. The newest 500 cases are considered."""
    return await views.campaigns(db, actor.workspace_id, days=days)


@router.get("/assets")
async def list_assets(
    kind: str | None = Query(None, max_length=20, pattern=r"^[A-Za-z_-]+$", description="host, user, or another kind"),
    q: str = Query("", max_length=200, description="part of the name"),
    limit: int = Query(100, ge=1, le=500),
    actor: Actor = Depends(require_actor),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """The hosts and people pushed alerts named, each with its cases and highest verdict.
    Empty until an integration pushes alerts to POST /api/alerts."""
    return await views.attack_surface(db, actor.workspace_id, kind=kind, q=q, limit=limit)


@router.get("/sources")
async def list_sources(
    days: int = Query(7, ge=1, le=90),
    actor: Actor = Depends(require_actor),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """The workspace's providers (on or off, key set or not) and how each behaved over
    the last `days` days; and the shared offline feeds, with their last refresh."""
    creds = await ws_settings.credentials_for(db, server_box(), actor.workspace_id)
    with credentials.using(creds):
        providers = [{
            "name": p.name, "label": p.label, "supported_types": sorted(p.supported_types),
            "enabled": p.name not in creds.disabled,
            "needs_key": p.requires_key,
            "key_set": bool(p.key()) if p.requires_key else None,
            "ready": p.name not in creds.disabled and p.configured(),
        } for p in PROVIDERS]
    answer = await views.sources(db, actor.workspace_id, providers, days=days)
    answer["feeds"] = await feeds.feed_status()
    return answer


@router.get("/tickets")
async def list_tickets(
    sink: Literal["jira", "servicenow"] | None = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0, le=2**63 - 1),
    actor: Actor = Depends(require_actor),
    db: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    """Every Jira or ServiceNow ticket raised for one of the workspace's cases, newest
    first, with who raised it and where its report downloads."""
    return await views.tickets(db, actor.workspace_id, sink=sink, limit=limit, offset=offset)


@router.get("/narratives")
async def list_narratives(
    days: int = Query(90, ge=1, le=365),
    limit: int = Query(25, ge=1, le=100),
    actor: Actor = Depends(require_actor),
    db: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Each recent case's ATT&CK techniques in tactic order, with the indicators that
    evidence them. Cases with no technique tell no story and are left out."""
    return await views.narratives(db, actor.workspace_id, days=days, limit=limit)
