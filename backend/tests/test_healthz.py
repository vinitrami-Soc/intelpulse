"""GET /healthz (spec 12): 200 when the database, Redis, the worker's heartbeat and the disk are
all well, 503 when one is not, and nothing in it a stranger could use."""
from __future__ import annotations

from collections import namedtuple
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest

from app.config import settings
from app.db import session_scope
from app.routers import healthz
from app.tasks import celery_app

Usage = namedtuple("Usage", "total used free")


@pytest.fixture
def with_redis(monkeypatch):
    """A server with REDIS_URL set, whose Redis answers (or not, with ok=False)."""
    def given(ok: bool = True) -> None:
        monkeypatch.setattr(settings, "redis_url", "redis://redis:6379/0")

        async def ping() -> dict:
            return {"ok": ok}
        monkeypatch.setattr(healthz, "_redis", ping)
    return given


async def _beat(at: datetime) -> None:
    async with session_scope() as db:
        await healthz.record_heartbeat(db, at)


async def test_a_development_server_is_healthy_without_redis(browser):
    answer = await browser.get("/healthz")
    assert answer.status_code == 200 and answer.headers["cache-control"] == "no-store"
    body = answer.json()
    assert body["status"] == "ok"
    assert body["checks"]["database"]["ok"] is True
    assert body["checks"]["redis"] == {"ok": None, "detail": "not configured"}
    assert body["checks"]["beat"] == {"ok": None, "detail": "not configured"}
    assert body["checks"]["disk"]["ok"] is True and 0 < body["checks"]["disk"]["free_percent"] <= 100


async def test_a_database_that_does_not_answer_is_a_503_that_says_no_more(browser, monkeypatch, caplog):
    @asynccontextmanager
    async def broken():
        raise ConnectionRefusedError("could not connect to db.internal:5432 as intelpulse")
        yield  # pragma: no cover

    monkeypatch.setattr(healthz, "session_scope", broken)
    answer = await browser.get("/healthz")
    assert answer.status_code == 503 and answer.json()["status"] == "fail"
    assert answer.json()["checks"]["database"] == {"ok": False}
    assert "db.internal" not in answer.text and "intelpulse" not in answer.text
    assert "db.internal" in caplog.text          # the reason is in the log, for whoever runs it


async def test_redis_that_does_not_answer_fails(browser, with_redis):
    with_redis(ok=False)
    await _beat(datetime.now(UTC))
    answer = await browser.get("/healthz")
    assert answer.status_code == 503 and answer.json()["checks"]["redis"] == {"ok": False}


async def test_the_real_redis_check_fails_quietly_when_nothing_listens(monkeypatch):
    monkeypatch.setattr(settings, "redis_url", "redis://127.0.0.1:1/0")
    assert await healthz._redis() == {"ok": False}


async def test_a_fresh_heartbeat_passes_and_a_stale_one_fails(browser, with_redis):
    with_redis()
    await _beat(datetime.now(UTC) - timedelta(seconds=90))
    fresh = await browser.get("/healthz")
    assert fresh.status_code == 200
    assert fresh.json()["checks"]["beat"]["ok"] is True and 85 <= fresh.json()["checks"]["beat"]["age_seconds"] <= 120
    await _beat(datetime.now(UTC) - timedelta(minutes=10))
    stale = await browser.get("/healthz")
    assert stale.status_code == 503
    assert stale.json()["checks"]["beat"] == {"ok": False, "age_seconds": stale.json()["checks"]["beat"]["age_seconds"],
                                             "max_age_seconds": 300}


async def test_no_heartbeat_yet_is_waiting_at_first_and_failing_later(browser, with_redis, monkeypatch):
    with_redis()
    first = await browser.get("/healthz")
    assert first.status_code == 200 and first.json()["checks"]["beat"]["detail"] == "waiting for the first heartbeat"
    monkeypatch.setattr(healthz, "STARTED", healthz.STARTED - 3600)
    later = await browser.get("/healthz")
    assert later.status_code == 503 and later.json()["checks"]["beat"] == {"ok": False, "detail": "no heartbeat yet"}


async def test_a_full_disk_fails(browser, monkeypatch):
    monkeypatch.setattr(healthz.shutil, "disk_usage", lambda _path: Usage(1000, 970, 30))
    answer = await browser.get("/healthz")
    assert answer.status_code == 503
    assert answer.json()["checks"]["disk"] == {"ok": False, "free_percent": 3.0, "min_free_percent": 5.0}


async def test_the_worker_beats_every_minute_on_beat_s_schedule(browser, with_redis):
    from app import tasks

    job = celery_app.conf.beat_schedule["heartbeat-minute"]
    assert job["task"] == "intelpulse.heartbeat" and job["schedule"] == 60.0
    with_redis()
    await tasks._heartbeat()
    beat = (await browser.get("/healthz")).json()["checks"]["beat"]
    assert beat["ok"] is True and beat["age_seconds"] <= 5


async def test_it_is_open_to_anyone_and_shows_nothing_of_a_workspace(people):
    owner = await people.set_up("ada", "Acme SOC")
    await owner.post("/api/triage", json={"indicators": ["185.220.101.34"], "title": "Acme's own"})
    stranger = people._client()
    answer = await stranger.get("/healthz")
    assert answer.status_code == 200
    assert set(answer.json()) == {"status", "checks"}
    assert "Acme" not in answer.text and "185.220" not in answer.text and "ada" not in answer.text
