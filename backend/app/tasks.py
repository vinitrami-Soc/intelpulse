"""Celery worker: scheduled feed refreshes and background bulk triage.

Celery is optional — the API runs standalone and can refresh feeds inline via
`POST /api/intel/feeds/{feed}/refresh`. In compose, the beat schedule keeps the
offline datasets current so the platform keeps working when API quotas run out.
"""
from __future__ import annotations

import asyncio
import logging

from celery import Celery
from celery.schedules import crontab

from .config import settings
from .services import feeds

logger = logging.getLogger(__name__)

BROKER = settings.redis_url or "redis://localhost:6379/0"

celery_app = Celery("intelpulse", broker=BROKER, backend=BROKER)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    task_time_limit=900,
    task_soft_time_limit=840,
    worker_max_tasks_per_child=200,
    beat_schedule={
        "feodo-hourly": {"task": "intelpulse.refresh_feodo", "schedule": crontab(minute=7)},
        "threatfox-6h": {
            "task": "intelpulse.refresh_threatfox",
            "schedule": crontab(minute=17, hour="*/6"),
        },
        "firehol-daily": {
            "task": "intelpulse.refresh_firehol",
            "schedule": crontab(minute=25, hour=3),
        },
        "kev-daily": {"task": "intelpulse.refresh_kev", "schedule": crontab(minute=35, hour=4)},
        "nvd-daily": {"task": "intelpulse.refresh_nvd", "schedule": crontab(minute=45, hour=5)},
    },
)


def _run(coro):
    """Celery workers are synchronous; give each task its own event loop."""
    return asyncio.run(coro)


@celery_app.task(name="intelpulse.refresh_feodo")
def refresh_feodo_task() -> int:
    return _run(feeds.refresh_feodo())


@celery_app.task(name="intelpulse.refresh_threatfox")
def refresh_threatfox_task() -> int:
    return _run(feeds.refresh_threatfox_dump())


@celery_app.task(name="intelpulse.refresh_firehol")
def refresh_firehol_task() -> int:
    return _run(feeds.refresh_firehol())


@celery_app.task(name="intelpulse.refresh_kev")
def refresh_kev_task() -> int:
    return _run(feeds.refresh_kev())


@celery_app.task(name="intelpulse.refresh_nvd")
def refresh_nvd_task(days: int = 30) -> int:
    return _run(feeds.refresh_nvd(days=days))


@celery_app.task(name="intelpulse.bulk_triage")
def bulk_triage_task(text: str, title: str = "Scheduled bulk triage") -> dict:
    """Used for large pastes an analyst does not want to wait on."""
    from .db import session_scope
    from .ioc import extract
    from .services.triage import persist_case, triage

    async def _job() -> dict:
        indicators = extract(text, limit=settings.max_iocs_per_request)
        outcome = await triage(indicators, title=title)
        async with session_scope() as session:
            await persist_case(session, outcome, raw_input=text, source="celery")
        return {"case_id": outcome.case_id, "verdict": outcome.verdict, "score": outcome.score}

    return _run(_job())
