"""The diff an analyst sees when they re-triage an address days later."""
from __future__ import annotations

import pytest

from app import cache as cache_module
from app.enrichment.base import STATUS_OK, Provider, Signal
from app.ioc import Indicator
from app.services import triage as triage_service

ADDR = "185.220.101.34"   # routable: the extractor drops RFC 5737 documentation space


class SwingProvider(Provider):
    """A provider whose answer can be changed between triages, like reality."""

    name = "threatfox"
    label = "ThreatFox"
    supported_types = {"ip"}
    requires_key = False
    cacheable = False          # every triage asks again, as a re-scan would

    def __init__(self) -> None:
        self.signal = 0.2
        self.families: list[str] = []
        self.attack: list[str] = []
        self.status = STATUS_OK

    def configured(self) -> bool:
        return True

    def reference_for(self, indicator: Indicator) -> str | None:
        return None

    async def fetch(self, client, indicator: Indicator):
        return self._result(
            indicator,
            status=self.status,
            signals=[Signal(key="threatfox", value=self.signal, rationale="stub")],
            malware_families=list(self.families),
            attack_ids=list(self.attack),
        )


@pytest.fixture
async def swing(monkeypatch, clean_db):
    provider = SwingProvider()
    monkeypatch.setattr(triage_service, "PROVIDERS", [provider])
    await cache_module.cache.invalidate("")
    yield provider
    await cache_module.cache.invalidate("")


async def run(client, **kw):
    body = {"indicators": [ADDR], "persist": True, "use_cache": False}
    body.update(kw)
    response = await client.post("/api/triage", json=body)
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.anyio
async def test_the_first_triage_reports_a_first_sighting(client, swing):
    body = await run(client)
    assert len(body["diffs"]) == 1
    diff = body["diffs"][0]
    assert diff["value"] == ADDR
    assert diff["first_seen"] is True
    assert diff["previous_score"] is None
    assert "First time" in diff["summary"]


@pytest.mark.anyio
async def test_an_unchanged_re_triage_says_so(client, swing):
    await run(client)
    body = await run(client)
    diff = body["diffs"][0]
    assert diff["first_seen"] is False
    assert diff["changed"] is False
    assert diff["score_delta"] == 0
    assert diff["summary"] == "No change since the last triage."


@pytest.mark.anyio
async def test_a_worse_verdict_five_days_later_is_an_escalation(client, swing):
    await run(client)
    swing.signal = 0.98
    swing.families = ["SampleBot"]
    swing.attack = ["T1071.001"]
    body = await run(client)

    diff = body["diffs"][0]
    assert diff["first_seen"] is False
    assert diff["changed"] is True
    assert diff["score_delta"] > 0
    assert diff["escalated"] is True
    assert diff["new_malware_families"] == ["SampleBot"]
    assert diff["new_attack_ids"] == ["T1071.001"]
    assert diff["summary"].startswith("Escalated")


@pytest.mark.anyio
async def test_a_source_going_quiet_is_reported(client, swing):
    await run(client)
    swing.status = "error"          # the vendor is down on the second pass
    body = await run(client)
    diff = body["diffs"][0]
    assert diff["sources_removed"] == ["threatfox"]
    assert "stopped answering" in diff["summary"]


@pytest.mark.anyio
async def test_the_diff_never_compares_a_case_against_itself(client, swing):
    """The current case is written after the history is read, not before."""
    body = await run(client)
    assert body["diffs"][0]["previous_case_id"] != body["case_id"]


@pytest.mark.anyio
async def test_without_persistence_there_is_no_history_to_compare(client, swing):
    body = await run(client, persist=False)
    assert body["diffs"][0]["first_seen"] is True
    body = await run(client, persist=False)
    assert body["diffs"][0]["first_seen"] is True, "an unpersisted case became history"
