"""The data behind the console's views (spec 9.2): each one reads its own workspace only.

The cases here are written straight into the database with the shape a triage
stores, so every number a view reports can be worked out by hand. Addresses are
RFC 5737, names RFC 2606, families invented.
"""
from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from uuid import uuid4

import pytest

from app.db import session_scope
from app.enrichment import PROVIDERS
from app.models import Case, CaseTicket, IndicatorResult, User, utcnow
from app.services import views

NOW = utcnow()


def source(provider: str, *, status: str = "ok", signal: float = 0.9, latency: int = 120, cached: bool = False,
           error: str | None = None, relations=(), attack_ids=(), label: str | None = None) -> dict:
    return {"provider": provider, "label": label or provider.title(), "status": status, "cached": cached,
            "latency_ms": latency, "error": error, "attack_ids": list(attack_ids),
            "signals": [{"key": provider, "value": signal, "rationale": "test"}] if status == "ok" else [],
            "relations": [{"target": t, "target_type": k, "relation": "related", "confidence": 0.7}
                          for k, t in relations]}


def ioc(value: str, *, verdict: str = "high", score: int = 70, type: str = "ip", families=(), attack_ids=(),
        sources=()) -> dict:
    return {"value": value, "ioc_type": type, "verdict": verdict, "score": score,
            "malware_families": list(families), "attack_ids": list(attack_ids),
            "payload": {"value": value, "sources": list(sources)}}


async def seed(workspace_id: int, *, title: str = "A case", verdict: str = "high", score: int = 70,
               status: str = "new", age: timedelta = timedelta(0), closed_after: timedelta | None = None,
               assignee_id: int | None = None, indicators=()) -> str:
    created = NOW - age
    async with session_scope() as db:
        case = Case(id=str(uuid4()), workspace_id=workspace_id, title=title, verdict=verdict, max_score=score,
                    status=status, created_at=created, assignee_id=assignee_id, indicator_count=len(indicators),
                    closed_reason="true_positive" if status == "closed" else None,
                    closed_at=created + closed_after if closed_after is not None else None)
        db.add(case)
        for row in indicators:
            db.add(IndicatorResult(workspace_id=workspace_id, case_id=case.id, created_at=created, **row))
    return case.id


async def user_id(username: str) -> int:
    async with session_scope() as db:
        return next(u.id for u in (await db.execute(User.__table__.select())).all() if u.username == username)


@pytest.fixture
async def two(people):
    """(ada, olga, olga's workspace): the owner of Acme SOC, and the admin of a second workspace."""
    ada = await people.set_up("ada", "Acme SOC")
    other = await people.workspace("Other SOC")
    await people.member("olga", role="admin", workspace_id=other)
    return ada, await people.signed_in("olga"), other


VIEWS = ["/api/indicators", "/api/campaigns", "/api/assets", "/api/sources", "/api/tickets", "/api/narratives",
         "/api/stats"]


# -- the overview --------------------------------------------------------------------
def test_the_trend_counts_each_utc_day_and_keeps_the_empty_ones():
    today = date(2026, 11, 3)
    at = lambda d, h: datetime(2026, 11, d, h, tzinfo=UTC)  # noqa: E731
    days = views.trend([at(3, 1), at(3, 23), at(1, 12), datetime(2026, 11, 2, 23, 30)], [at(3, 2)],
                       days=3, today=today)
    assert days == [{"date": "2026-11-01", "opened": 1, "closed": 0},
                    {"date": "2026-11-02", "opened": 1, "closed": 0},   # a naive time is UTC
                    {"date": "2026-11-03", "opened": 2, "closed": 1}]


def test_time_to_close_is_the_mean_and_the_median():
    opened = datetime(2026, 11, 1, tzinfo=UTC)
    pairs = [(opened, opened + timedelta(hours=h)) for h in (1, 2, 9)]
    assert views.time_to_close(pairs) == {"cases": 3, "mean_seconds": 4 * 3600, "median_seconds": 2 * 3600}
    assert views.time_to_close([]) == {"cases": 0, "mean_seconds": None, "median_seconds": None}


async def test_the_overview_counts_each_band_by_status(two):
    ada, _, _ = two
    ada_id = await user_id("ada")
    await seed(1, verdict="critical", score=95, status="new", assignee_id=ada_id)
    await seed(1, verdict="critical", score=90, status="in_progress")
    await seed(1, verdict="high", status="closed", age=timedelta(days=2), closed_after=timedelta(hours=4))
    # both closed before today's midnight UTC, whatever the hour the test runs at
    await seed(1, verdict="informational", score=0, status="closed", age=timedelta(days=2),
               closed_after=timedelta(hours=2))
    stats = (await ada.get("/api/stats")).json()
    bands = {band["verdict"]: band for band in stats["bands"]}
    assert [band["verdict"] for band in stats["bands"]] == ["critical", "high", "medium", "low", "informational"]
    assert bands["critical"] == {"verdict": "critical", "new": 1, "in_progress": 1, "closed": 0}
    assert bands["high"]["closed"] == 1 and bands["informational"]["closed"] == 1
    assert stats["by_status"] == {"new": 1, "in_progress": 1, "closed": 2} and stats["open"] == 2
    assert stats["unassigned_open"] == 1 and stats["assigned_to_me_open"] == 1
    assert stats["time_to_close"] == {"cases": 2, "mean_seconds": 3 * 3600, "median_seconds": 3 * 3600}
    assert len(stats["trend"]) == 90 and stats["trend"][-1]["date"] == NOW.date().isoformat()
    assert sum(day["opened"] for day in stats["trend"]) == 4
    # what 1.x clients read is still there
    assert stats["cases"] == 4 and stats["cases_by_verdict"]["critical"] == 2
    assert len((await ada.get("/api/stats", params={"days": 7})).json()["trend"]) == 7
    # one day is today since midnight UTC: the case closed yesterday is not in it
    today = (await ada.get("/api/stats", params={"days": 1})).json()
    assert today["trend"] == [{"date": NOW.date().isoformat(), "opened": 2, "closed": 0}]
    assert today["time_to_close"]["cases"] == 0


async def test_a_token_has_no_cases_of_its_own(two, people):
    ada, _, _ = two
    reader = await people.token(ada, "read")
    stats = (await reader.get("/api/stats")).json()
    assert stats["assigned_to_me_open"] is None


# -- every indicator once ------------------------------------------------------------
def test_a_provider_flags_an_indicator_when_its_answer_leans_malicious():
    payload = {"sources": [source("abuseipdb", signal=0.96, label="AbuseIPDB"),
                           source("geoip", signal=0.3, label="GeoIP"),          # context, not a flag
                           source("otx", status="clean"), source("greynoise", status="skipped"),
                           source("threatfox", status="error", error="HTTP 500")]}
    assert views.flagged_by(payload) == ["AbuseIPDB"]
    assert views.flagged_by({}) == []


async def test_each_indicator_once_with_its_latest_verdict(two):
    ada, _, _ = two
    await seed(1, age=timedelta(days=3), indicators=[
        ioc("192.0.2.10", verdict="medium", score=45, sources=[source("otx", signal=0.6, label="OTX")]),
        ioc("bad.example", type="domain", verdict="low", score=25)])
    await seed(1, age=timedelta(days=1), indicators=[
        ioc("192.0.2.10", verdict="critical", score=92, families=["SampleBot"],
            sources=[source("threatfox", label="ThreatFox")])])
    rows = (await ada.get("/api/indicators")).json()
    assert [row["value"] for row in rows] == ["192.0.2.10", "bad.example"]   # last seen first
    first = rows[0]
    assert first["cases"] == 2 and first["verdict"] == "critical" and first["score"] == 92
    assert first["flagged_by"] == ["ThreatFox"] and first["malware_families"] == ["SampleBot"]
    assert first["first_seen"] < first["last_seen"]
    assert [r["value"] for r in (await ada.get("/api/indicators", params={"verdict": "low"})).json()] == ["bad.example"]
    assert [r["value"] for r in (await ada.get("/api/indicators", params={"type": "domain"})).json()] == ["bad.example"]
    assert [r["value"] for r in (await ada.get("/api/indicators", params={"q": "2.10"})).json()] == ["192.0.2.10"]
    assert (await ada.get("/api/indicators", params={"q": "%"})).json() == []   # a wildcard is a character
    by_score = (await ada.get("/api/indicators", params={"sort": "score", "limit": 1})).json()
    assert [r["value"] for r in by_score] == ["192.0.2.10"]
    assert (await ada.get("/api/indicators", params={"sort": "newest"})).status_code == 422


# -- campaigns -----------------------------------------------------------------------
def brief(case_id: str, day: int, verdict: str = "high", score: int = 70) -> dict:
    return {"id": case_id, "title": case_id, "verdict": verdict, "score": score, "status": "new",
            "created_at": f"2026-11-0{day}T00:00:00+00:00"}


def row(case_id: str, value: str, **fields) -> dict:
    out = {"case_id": case_id, "value": value, "type": "ip", "verdict": "high", "malware_families": [],
           "payload": {}}
    out.update(fields)
    return out


def test_cases_that_share_a_family_or_infrastructure_are_one_campaign():
    cases = [brief("a", 1), brief("b", 2, "critical", 95), brief("c", 3), brief("d", 4), brief("e", 5)]
    asn = {"sources": [source("geoip", relations=[("asn", "AS64500"), ("country", "NL")])]}
    rows = [
        row("a", "192.0.2.1", malware_families=["SampleBot"]),
        row("b", "192.0.2.2", malware_families=["samplebot"], payload=asn),   # a family's case does not matter
        row("c", "198.51.100.3", payload=asn),                                # the same ASN as b
        row("d", "198.51.100.4", payload={"sources": [source("geoip", relations=[("country", "NL")])]}),
        row("e", "192.0.2.1", verdict="informational"),                       # scored nothing: joins nothing
    ]
    campaigns = views.join_campaigns(cases, rows)
    assert len(campaigns) == 1
    campaign = campaigns[0]
    assert [c["id"] for c in campaign["cases"]] == ["a", "b", "c"] and campaign["case_count"] == 3
    assert campaign["id"] == "a" and campaign["label"] == "SampleBot"
    assert campaign["verdict"] == "critical" and campaign["score"] == 95
    assert campaign["first_seen"] < campaign["last_seen"]
    links = {(link["kind"], link["value"]): link for link in campaign["links"]}
    assert set(links) == {("malware", "SampleBot"), ("infrastructure", "AS64500")}
    assert links[("infrastructure", "AS64500")]["cases"] == ["b", "c"]


def test_one_case_alone_is_not_a_campaign():
    assert views.join_campaigns([brief("a", 1)], [row("a", "192.0.2.1", malware_families=["SampleBot"])]) == []
    assert views.join_campaigns([], []) == []


async def test_campaigns_from_the_workspace_s_own_cases(two):
    ada, olga, other = two
    for _ in range(2):
        await seed(1, indicators=[ioc("192.0.2.50", families=["SampleLoader"])])
    await seed(other, indicators=[ioc("192.0.2.50", families=["SampleLoader"])])
    await seed(1, age=timedelta(days=200), indicators=[ioc("192.0.2.50", families=["SampleLoader"])])
    body = (await ada.get("/api/campaigns")).json()
    assert body["cases_considered"] == 2 and body["truncated"] is False
    assert [(c["label"], c["case_count"]) for c in body["campaigns"]] == [("SampleLoader", 2)]
    assert (await ada.get("/api/campaigns", params={"days": 365})).json()["campaigns"][0]["case_count"] == 3
    assert (await olga.get("/api/campaigns")).json()["campaigns"] == []   # one case of its own


# -- the attack surface ---------------------------------------------------------------
def test_assets_are_named_once_whatever_the_alert_called_them():
    case = lambda i, verdict, status="new": {"id": i, "verdict": verdict, "score": 10 * len(verdict),  # noqa: E731
                                             "status": status}
    alerts = [  # newest first
        {"case": case("c3", "low", "closed"), "received_at": "3",
         "entities": [{"kind": "hostname", "name": "WS-0442"}, {"kind": "user", "name": "j.doe"}]},
        {"case": case("c2", "critical"), "received_at": "2",
         "entities": [{"kind": "Host", "name": "ws-0442"}, {"kind": "host", "name": "WS-0442"},
                      {"kind": "account", "name": "j.doe"}, {"kind": "ip", "name": "192.0.2.9"}]},
        {"case": case("c1", "medium"), "received_at": "1", "entities": [{"kind": "host", "name": " "}]},
    ]
    assets = {(a["kind"], a["name"]): a for a in views.gather_assets(alerts)}
    assert set(assets) == {("host", "WS-0442"), ("user", "j.doe"), ("ip", "192.0.2.9")}
    host = assets[("host", "WS-0442")]
    assert host["alerts"] == 2 and host["cases"] == 2 and host["case_ids"] == ["c3", "c2"]
    assert host["verdict"] == "critical" and host["open_cases"] == 1
    assert host["first_seen"] == "2" and host["last_seen"] == "3"
    assert list(assets)[0] == ("host", "WS-0442")   # the most severe first


async def test_the_attack_surface_comes_from_pushed_alerts(two):
    ada, olga, _ = two
    assert (await ada.get("/api/assets")).json() == {"alerts_considered": 0, "truncated": False, "assets": []}
    for n, user in enumerate(["j.doe", "a.smith"]):
        response = await ada.post("/api/alerts", json={
            "source": "siem", "alert_id": f"A-{n}", "title": "Suspicious logon", "severity": "high",
            "entities": [{"kind": "host", "name": "LON-WS-0442"}, {"kind": "user", "name": user}]})
        assert response.status_code == 201, response.text
    body = (await ada.get("/api/assets")).json()
    assert body["alerts_considered"] == 2
    host = next(a for a in body["assets"] if a["kind"] == "host")
    assert host["name"] == "LON-WS-0442" and host["cases"] == 2 and host["open_cases"] == 2
    users = (await ada.get("/api/assets", params={"kind": "account"})).json()["assets"]
    assert sorted(a["name"] for a in users) == ["a.smith", "j.doe"]
    assert [a["name"] for a in (await ada.get("/api/assets", params={"q": "smith"})).json()["assets"]] == ["a.smith"]
    assert (await olga.get("/api/assets")).json()["assets"] == []


# -- intelligence sources ------------------------------------------------------------
def test_source_health_over_the_results_given():
    at = datetime(2026, 11, 3, tzinfo=UTC)
    payloads = [  # newest first
        ({"sources": [source("otx", status="rate_limited", error="429 from OTX"),
                      source("abuseipdb", latency=300)]}, at, "c2"),
        ({"sources": [source("otx", status="error", error="timeout"), source("abuseipdb", latency=100),
                      source("abuseipdb", latency=5, cached=True), source("greynoise", status="skipped")]},
         at - timedelta(days=1), "c1"),
    ]
    health = views.source_health(payloads)
    assert health["abuseipdb"] == {"queries": 3, "answered": 3, "errors": 0, "rate_limited": 0, "skipped": 0,
                                   "last_error": None, "median_latency_ms": 200}   # a cached answer took no time
    assert health["otx"]["errors"] == 1 and health["otx"]["rate_limited"] == 1
    assert health["otx"]["last_error"] == {"status": "rate_limited", "message": "429 from OTX",
                                           "at": at.isoformat(), "case_id": "c2"}
    assert health["greynoise"]["queries"] == 0 and health["greynoise"]["skipped"] == 1


async def test_the_sources_view_lists_the_workspace_s_providers(two):
    ada, olga, _ = two
    assert (await ada.patch("/api/settings", json={"providers": {"otx": {"enabled": False}}})).status_code == 200
    await seed(1, indicators=[ioc("192.0.2.70", sources=[source("abuseipdb", status="error", error="HTTP 401")])])
    await seed(1, age=timedelta(days=30),
               indicators=[ioc("192.0.2.71", sources=[source("abuseipdb", status="error", error="old")])])
    body = (await ada.get("/api/sources")).json()
    assert body["days"] == 7 and body["results_considered"] == 1
    providers = {p["name"]: p for p in body["providers"]}
    assert set(providers) == {p.name for p in PROVIDERS}
    assert providers["otx"]["enabled"] is False and providers["otx"]["ready"] is False
    assert providers["abuseipdb"]["needs_key"] is True and providers["abuseipdb"]["key_set"] is False
    assert providers["abuseipdb"]["errors"] == 1 and providers["abuseipdb"]["last_error"]["message"] == "HTTP 401"
    keyless = next(p for p in PROVIDERS if not p.requires_key)
    assert providers[keyless.name]["key_set"] is None
    assert isinstance(body["feeds"], list)
    theirs = {p["name"]: p for p in (await olga.get("/api/sources")).json()["providers"]}
    assert theirs["otx"]["enabled"] is True and theirs["abuseipdb"]["errors"] == 0


# -- SOC tickets ---------------------------------------------------------------------
async def test_the_tickets_view_lists_the_workspace_s_tickets(two):
    ada, olga, other = two
    ada_id = await user_id("ada")
    mine = await seed(1, title="Ours")
    theirs = await seed(other, title="Theirs")
    async with session_scope() as db:
        db.add(CaseTicket(workspace_id=1, case_id=mine, sink="jira", key="SOC-1",
                          url="https://jira.example.com/browse/SOC-1", created_by=ada_id,
                          created_at=NOW - timedelta(hours=1)))
        db.add(CaseTicket(workspace_id=1, case_id=mine, sink="servicenow", key="INC0010001",
                          url="https://sn.example.com/inc", created_at=NOW))
        db.add(CaseTicket(workspace_id=other, case_id=theirs, sink="jira", key="OTH-1",
                          url="https://jira.example.net/browse/OTH-1"))
    rows = (await ada.get("/api/tickets")).json()
    assert [r["key"] for r in rows] == ["INC0010001", "SOC-1"]
    jira = rows[1]
    assert jira["case"]["title"] == "Ours" and jira["created_by"]["username"] == "ada"
    assert jira["report"] == {"markdown": f"/api/cases/{mine}/report?fmt=markdown",
                              "json": f"/api/cases/{mine}/report?fmt=json"}
    assert [r["key"] for r in (await ada.get("/api/tickets", params={"sink": "jira"})).json()] == ["SOC-1"]
    assert [r["key"] for r in (await olga.get("/api/tickets")).json()] == ["OTH-1"]
    assert (await ada.get("/api/tickets", params={"sink": "email"})).status_code == 422


# -- attack narratives ---------------------------------------------------------------
def test_a_narrative_runs_in_tactic_order_with_its_evidence():
    rows = [
        {"value": "192.0.2.1", "type": "ip", "verdict": "critical", "score": 92, "attack_ids": ["T1071", "T1110"],
         "payload": {"sources": [source("threatfox", attack_ids=["T1071"], label="ThreatFox")]}},
        {"value": "bad.example", "type": "domain", "verdict": "high", "score": 70, "attack_ids": ["T1071"],
         "payload": {}},
    ]
    steps = views.narrative(rows, ["T1566", "T1071"])
    assert [step["tactic"] for step in steps] == ["Initial Access", "Credential Access", "Command and Control"]
    c2 = steps[-1]["techniques"][0]
    assert c2["id"] == "T1071" and c2["name"] == "Application Layer Protocol" and c2["from_alert"] is True
    assert [(e["indicator"], e["named_by"], e["inferred"]) for e in c2["evidence"]] == [
        ("192.0.2.1", ["ThreatFox"], False), ("bad.example", [], True)]
    phishing = steps[0]["techniques"][0]
    assert phishing["id"] == "T1566" and phishing["evidence"] == [] and phishing["from_alert"] is True
    assert views.narrative([], []) == []


async def test_narratives_leave_out_cases_with_no_technique(two):
    ada, olga, other = two
    await seed(1, title="Quiet", indicators=[ioc("192.0.2.80")])
    told = await seed(1, title="Told", indicators=[ioc("192.0.2.81", attack_ids=["T1110"])])
    await seed(other, indicators=[ioc("192.0.2.81", attack_ids=["T1110"])])
    body = (await ada.get("/api/narratives")).json()
    assert body["cases_considered"] == 2
    assert [(n["case"]["id"], n["steps"][0]["tactic"]) for n in body["narratives"]] == [(told, "Credential Access")]
    assert len((await olga.get("/api/narratives")).json()["narratives"]) == 1


# -- who reaches them ----------------------------------------------------------------
async def test_a_read_token_reads_the_views_and_an_ingest_token_does_not(two, people):
    ada, _, _ = two
    reader, ingest = await people.token(ada, "read"), await people.token(ada, "ingest", "siem")
    for path in VIEWS:
        assert (await reader.get(path)).status_code == 200, path
        assert (await ingest.get(path)).status_code == 403, path


async def test_a_new_workspace_s_views_show_only_its_own_work(two):
    """M2's done-when, through the API: 20 triages and 5 pushed alerts in a new
    workspace, and every view counts exactly those; the other workspace sees none."""
    ada, olga, _ = two
    for n in range(20):
        response = await olga.post("/api/triage", json={"indicators": [f"185.220.101.{n + 1}"], "title": f"T{n}"})
        assert response.status_code == 200, response.text
    for n in range(5):
        response = await olga.post("/api/alerts", json={
            "source": "siem", "alert_id": f"OLGA-{n}", "title": "Pushed", "entities": [{"kind": "host", "name": f"H{n}"}],
            "indicators": [f"185.220.102.{n + 1}"]})
        assert response.status_code == 201, response.text
    stats = (await olga.get("/api/stats")).json()
    assert stats["cases"] == 25 and stats["pushed_alerts"] == 5 and stats["by_status"]["new"] == 25
    assert sum(sum(band[s] for s in ("new", "in_progress", "closed")) for band in stats["bands"]) == 25
    assert stats["trend"][-1]["opened"] == 25 and stats["distinct_indicators"] == 25
    assert len((await olga.get("/api/indicators", params={"limit": 200})).json()) == 25
    assert len((await olga.get("/api/assets")).json()["assets"]) == 5
    assert len((await olga.get("/api/cases", params={"limit": 200})).json()) == 25

    empty = (await ada.get("/api/stats")).json()
    assert empty["cases"] == 0 and empty["pushed_alerts"] == 0 and empty["distinct_indicators"] == 0
    assert all(day["opened"] == 0 for day in empty["trend"])
    assert (await ada.get("/api/indicators")).json() == []
    assert (await ada.get("/api/assets")).json()["assets"] == []
    assert (await ada.get("/api/campaigns")).json()["campaigns"] == []
    assert (await ada.get("/api/narratives")).json()["narratives"] == []
    assert (await ada.get("/api/tickets")).json() == []
    assert all(p["queries"] == 0 for p in (await ada.get("/api/sources")).json()["providers"])
