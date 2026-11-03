"""Triage budgets (spec 11.2): each person or token runs RATE_LIMIT_USER_TRIAGE triages a minute,
and each workspace the owner's daily budget of triages and pushed alerts, so nobody spends the
whole server's provider quota."""
from __future__ import annotations

from collections import deque

import pytest

from app.config import settings
from app.platform.budget import DAY
from app.security import limiter
from tests.test_alerts import incident

ASK = {"indicators": ["185.220.101.34"], "title": "budget"}


def _age(seconds: float) -> None:
    """Every hit so far happened `seconds` earlier: the clock moves on without the tests waiting."""
    for key, hits in limiter._hits.items():
        limiter._hits[key] = deque(at - seconds for at in hits)


@pytest.fixture
async def acme(people, monkeypatch):
    """(ada the owner, bea an analyst) in Acme SOC, three triages a minute each."""
    monkeypatch.setattr(settings, "rate_limit_user_triage", 3)
    ada = await people.set_up("ada", "Acme SOC")
    await people.member("bea")
    bea = await people.signed_in("bea")
    limiter._hits.clear()
    return ada, bea


async def _triage(client) -> int:
    return (await client.post("/api/triage", json=ASK)).status_code


async def test_each_person_runs_so_many_triages_a_minute(acme):
    ada, bea = acme
    assert [await _triage(ada) for _ in range(3)] == [200, 200, 200]
    refused = await ada.post("/api/triage", json=ASK)
    assert refused.status_code == 429 and refused.json()["error"] == "user_rate"
    assert 1 <= int(refused.headers["Retry-After"]) <= 61
    assert await _triage(bea) == 200            # bea has a bucket of her own
    _age(61)
    assert await _triage(ada) == 200            # and a minute later ada has hers back


async def test_uploads_and_reports_spend_the_same_triages(acme):
    ada, _ = acme
    assert (await ada.post("/api/triage", json=ASK)).status_code == 200
    upload = await ada.post("/api/triage/upload", files={"file": ("ioc.txt", b"185.220.101.34\n", "text/plain")})
    assert upload.status_code == 200, upload.text
    report = await ada.post("/api/triage/report", json=ASK)
    assert report.status_code == 200, report.text
    assert (await ada.post("/api/triage", json=ASK)).json()["error"] == "user_rate"


async def test_the_workspace_has_a_daily_budget_its_alerts_spend_too(acme, people):
    ada, bea = acme
    assert (await ada.patch("/api/server", json={"triage_daily_budget": 4})).status_code == 200
    script = await people.token(ada, "ingest")
    assert await _triage(ada) == 200 and await _triage(ada) == 200
    assert (await script.post("/api/alerts", json=incident())).status_code == 201
    assert await _triage(bea) == 200
    refused = await bea.post("/api/triage", json=ASK)
    assert refused.status_code == 429 and refused.json()["error"] == "workspace_budget"
    assert "4 triages" in refused.json()["detail"] and int(refused.headers["Retry-After"]) > 3600
    pushed = await script.post("/api/alerts", json=incident(alert_id="dw-2"))
    assert pushed.status_code == 429 and pushed.json()["error"] == "workspace_budget"
    _age(DAY + 1)
    assert await _triage(bea) == 200            # a day later the budget is whole again


async def test_one_workspace_spending_its_budget_leaves_the_others_theirs(acme, people):
    ada, _ = acme
    await ada.patch("/api/server", json={"triage_daily_budget": 1})
    assert await _triage(ada) == 200 and (await ada.post("/api/triage", json=ASK)).status_code == 429
    fjord = await people.workspace("Fjord CERT")
    await people.member("finn", role="admin", workspace_id=fjord)
    assert await _triage(await people.signed_in("finn")) == 200


async def test_each_token_has_a_bucket_of_its_own_whatever_its_name(acme, people):
    ada, _ = acme
    first, second = await people.token(ada, "triage", "script"), await people.token(ada, "triage", "script")
    assert [await _triage(first) for _ in range(3)] == [200, 200, 200]
    assert (await first.post("/api/triage", json=ASK)).json()["error"] == "user_rate"
    assert await _triage(second) == 200 and await _triage(ada) == 200


async def test_a_refused_call_spends_nothing(acme, people):
    ada, _ = acme
    reader = await people.token(ada, "read")
    for _ in range(5):
        assert await _triage(reader) == 403      # its scope does not cover triage
        assert await _triage(people._client()) == 401
    assert [await _triage(ada) for _ in range(3)] == [200, 200, 200]


async def test_only_the_owner_sets_the_budget_within_its_range(acme, people):
    ada, _ = acme
    await people.member("adam", role="admin")
    adam = await people.signed_in("adam")
    assert (await adam.patch("/api/server", json={"triage_daily_budget": 9})).status_code == 403
    for bad in (0, 1_000_001, "lots"):
        assert (await ada.patch("/api/server", json={"triage_daily_budget": bad})).status_code == 422, bad
    changed = await ada.patch("/api/server", json={"triage_daily_budget": 50})
    assert changed.json()["triage_daily_budget"] == 50 and changed.json()["changed"] == ["triage_daily_budget"]
    assert (await ada.get("/api/server")).json()["triage_daily_budget"] == 50


async def test_the_1x_token_has_its_own_bucket(client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_user_triage", 2)
    assert [await _triage(client) for _ in range(2)] == [200, 200]
    assert (await client.post("/api/triage", json=ASK)).json()["error"] == "user_rate"


async def test_no_limits_when_rate_limiting_is_off(acme, monkeypatch):
    ada, _ = acme
    monkeypatch.setattr(settings, "rate_limit_enabled", False)
    assert [await _triage(ada) for _ in range(5)] == [200] * 5


def test_a_daily_key_outlives_the_minute_sweep():
    limiter._hits.clear()
    limiter.record("daily", DAY)
    limiter.check("minute", 10, 60)
    _age(120)
    limiter._last_sweep = 0.0
    limiter.check("someone-else", 10, 60)      # the middleware's check sweeps with its 60 s window
    assert "daily" in limiter._hits and "minute" not in limiter._hits
    _age(DAY)
    limiter._last_sweep = 0.0
    limiter.check("someone-else", 10, 60)
    assert "daily" not in limiter._hits
