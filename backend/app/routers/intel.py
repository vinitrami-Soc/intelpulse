"""Offline dataset status, refresh triggers and direct CVE lookup."""
from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from ..cache import cache
from ..db import get_session
from ..models import AuditLog, CveRecord
from ..services import feeds

router = APIRouter(tags=["intel"])

_REFRESHERS = {
    "feodo-tracker": feeds.refresh_feodo,
    "threatfox-dump": feeds.refresh_threatfox_dump,
    "firehol-level1": feeds.refresh_firehol,
    "cisa-kev": feeds.refresh_kev,
    "nvd": feeds.refresh_nvd,
}


@router.get("/intel/feeds")
async def feed_status() -> list[dict]:
    return await feeds.feed_status()


@router.post("/intel/feeds/{feed}/refresh", status_code=202)
async def refresh_feed(
    feed: str, background: BackgroundTasks, session: AsyncSession = Depends(get_session)
) -> dict:
    """Kick a refresh without Celery — useful for a single-container demo."""
    if feed not in _REFRESHERS:
        raise HTTPException(status_code=404, detail=f"unknown feed: {feed}")
    background.add_task(_run_refresh, feed)
    session.add(AuditLog(action="feed.refresh.requested", target=feed, detail={}))
    return {"status": "scheduled", "feed": feed}


async def _run_refresh(feed: str) -> None:
    await _REFRESHERS[feed]()


@router.get("/intel/cve/{cve_id}")
async def cve_lookup(cve_id: str, session: AsyncSession = Depends(get_session)) -> dict:
    record = await session.get(CveRecord, cve_id.upper())
    if record is None:
        raise HTTPException(
            status_code=404,
            detail="CVE not in the local NVD slice — run the NVD feed import for a wider window",
        )
    return {
        "cve_id": record.cve_id,
        "description": record.description,
        "cvss_score": record.cvss_score,
        "cvss_vector": record.cvss_vector,
        "severity": record.severity,
        "published": record.published,
        "known_exploited": record.known_exploited,
        "references": record.references,
    }


@router.post("/intel/cache/invalidate")
async def invalidate_cache(ioc: str = Query(..., min_length=3)) -> dict:
    removed = await cache.invalidate(ioc)
    return {"invalidated": removed, "ioc": ioc}


@router.get("/intel/cache")
async def cache_status() -> dict:
    return cache.status()
