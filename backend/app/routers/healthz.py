"""`GET /healthz` for monitors (spec 12): is this server able to do its job right now?

200 when every check passes, 503 when any fails, so an uptime monitor needs only the status
code. Four checks:

- **database**: one query.
- **redis**: a ping, when REDIS_URL is set (skipped without it: then nothing needs Redis).
- **beat**: the last heartbeat the Celery worker wrote on beat's schedule. With Redis set, the
  retention sweep and the feed refreshes depend on it, so a heartbeat older than
  HEALTHZ_BEAT_MAX_AGE_SECONDS fails. A server that started less than that long ago and has
  not heard one yet is waiting, not failing.
- **disk**: free space where the server keeps its data, at least HEALTHZ_MIN_FREE_PERCENT.

It is open to anyone, so it says only pass or fail, how old the heartbeat is, and how much disk
is free: no error text, host name, path or version. The log has the reasons.
"""
from __future__ import annotations

import logging
import shutil
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text

from ..config import settings
from ..db import session_scope
from ..models import SERVER
from ..platform import settings_store as store

logger = logging.getLogger(__name__)
router = APIRouter(tags=["system"])

HEARTBEAT = "beat_heartbeat"
STARTED = time.monotonic()


async def record_heartbeat(db, now: datetime | None = None) -> None:
    """What the worker's heartbeat task writes, once a minute on beat's schedule."""
    await store.set_value(db, SERVER, HEARTBEAT, (now or datetime.now(UTC)).isoformat())


async def _database() -> dict[str, Any]:
    started = time.perf_counter()
    try:
        async with session_scope() as db:
            await db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001 - a monitor needs pass or fail; the log has why
        logger.exception("healthz: the database did not answer")
        return {"ok": False}
    return {"ok": True, "ms": round((time.perf_counter() - started) * 1000)}


async def _redis() -> dict[str, Any]:
    if not settings.redis_url:
        return {"ok": None, "detail": "not configured"}
    try:
        from redis import asyncio as aioredis

        client = aioredis.from_url(settings.redis_url, socket_connect_timeout=2, socket_timeout=2)
        try:
            await client.ping()
        finally:
            await client.aclose()
    except Exception:  # noqa: BLE001
        logger.exception("healthz: Redis did not answer")
        return {"ok": False}
    return {"ok": True}


async def _beat(now: datetime) -> dict[str, Any]:
    if not settings.redis_url:
        return {"ok": None, "detail": "not configured"}
    limit = settings.healthz_beat_max_age_seconds
    try:
        async with session_scope() as db:
            last = await store.get_value(db, SERVER, HEARTBEAT)
    except Exception:  # noqa: BLE001
        logger.exception("healthz: could not read the beat heartbeat")
        return {"ok": False}
    seen = None
    if isinstance(last, str):
        try:
            seen = datetime.fromisoformat(last)
        except ValueError:
            seen = None
    if seen is None:
        if time.monotonic() - STARTED < limit:
            return {"ok": True, "detail": "waiting for the first heartbeat"}
        return {"ok": False, "detail": "no heartbeat yet"}
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=UTC)
    age = max(0, round((now - seen).total_seconds()))
    return {"ok": age <= limit, "age_seconds": age, "max_age_seconds": limit}


def _disk() -> dict[str, Any]:
    try:
        usage = shutil.disk_usage(settings.data_dir if settings.data_dir.exists() else ".")
    except OSError:
        logger.exception("healthz: could not read free disk space")
        return {"ok": False}
    free = round(100 * usage.free / usage.total, 1) if usage.total else 0.0
    return {"ok": free >= settings.healthz_min_free_percent, "free_percent": free,
            "min_free_percent": settings.healthz_min_free_percent}


@router.get("/healthz", include_in_schema=True, summary="Health for monitors: 200 or 503")
async def healthz() -> JSONResponse:
    now = datetime.now(UTC)
    checks = {"database": await _database(), "redis": await _redis(), "beat": await _beat(now), "disk": _disk()}
    ok = all(check["ok"] is not False for check in checks.values())
    return JSONResponse({"status": "ok" if ok else "fail", "checks": checks}, status_code=200 if ok else 503,
                        headers={"Cache-Control": "no-store"})
