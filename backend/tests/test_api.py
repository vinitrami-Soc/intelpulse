"""API tests. No provider is allowed to touch the network: PROVIDERS is patched
with deterministic stubs so the assertions describe pipeline behaviour, not
whatever AbuseIPDB happens to say today.
"""
from __future__ import annotations

import pytest

from app.enrichment.base import STATUS_CLEAN, STATUS_OK, Provider, ProviderResult, Relation, Signal
from app.ioc import Indicator


class StubThreatFox(Provider):
    name = "threatfox"
    label = "ThreatFox (stub)"
    supported_types = {"ip", "domain", "url", "hash"}
    requires_key = False
    cacheable = False

    async def fetch(self, client, indicator: Indicator) -> ProviderResult:
        if indicator.value == "185.220.101.34":
            return self._result(
                indicator,
                status=STATUS_OK,
                facts={"matches": 1, "confidence_level": 100},
                tags=["botnet_cc"],
                malware_families=["QakBot"],
                attack_ids=["T1071"],
                relations=[Relation("QakBot", "malware", "attributed_to", 0.9)],
                signals=[Signal("threatfox", 0.95, "confirmed QakBot C2")],
            )
        return self._result(
            indicator,
            status=STATUS_CLEAN,
            signals=[Signal("threatfox", 0.0, "no ThreatFox match")],
        )


class StubAbuseIPDB(Provider):
    name = "abuseipdb"
    label = "AbuseIPDB (stub)"
    supported_types = {"ip"}
    cacheable = False

    def configured(self) -> bool:
        return True

    async def fetch(self, client, indicator: Indicator) -> ProviderResult:
        return self._result(
            indicator,
            status=STATUS_OK,
            facts={"abuse_confidence": 84, "isp": "Example Hosting", "country": "RU"},
            tags=["Port Scan"],
            signals=[Signal("abuseipdb", 0.84, "84% abuse confidence from 40 reports")],
        )


@pytest.fixture(autouse=True)
def stub_providers(monkeypatch):
    stubs = [StubAbuseIPDB(), StubThreatFox()]
    monkeypatch.setattr("app.services.triage.PROVIDERS", stubs)
    return stubs


@pytest.mark.asyncio
async def test_health_reports_provider_configuration(client):
    response = await client.get("/api/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    names = {p["name"] for p in body["providers"]}
    assert {"abuseipdb", "otx", "greynoise", "threatfox", "urlhaus", "geoip"} <= names
    # No keys are set in the test environment, so live providers must self-report
    # as unconfigured rather than pretending to have answered.
    assert not any(p["configured"] for p in body["providers"] if p["name"] == "abuseipdb")


@pytest.mark.asyncio
async def test_extract_endpoint_costs_no_api_calls(client):
    response = await client.post(
        "/api/extract", json={"text": "check 185.220.101.34 and hxxp://bad[.]site/x.exe"}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 3
    assert body["counts_by_type"]["ip"] == 1


@pytest.mark.asyncio
async def test_triage_scores_correlates_and_persists(client):
    response = await client.post(
        "/api/triage",
        json={"text": "SRC=185.220.101.34 blocked at perimeter", "title": "Firewall alert"},
    )
    assert response.status_code == 200
    body = response.json()

    assert body["verdict"] in ("high", "critical")
    assert body["indicator_count"] == 1
    indicator = body["indicators"][0]
    assert indicator["value"] == "185.220.101.34"
    assert "QakBot" in indicator["malware_families"]
    assert any(t["id"] == "T1071" for t in indicator["attack_techniques"])
    assert len(indicator["evidence"]) == 2          # both stubs contributed
    assert indicator["containment"]                  # actionable verdict -> actions
    assert any(n["data"]["kind"] == "malware" for n in body["graph"]["nodes"])
    assert body["persisted"] is True

    listing = await client.get("/api/cases")
    assert listing.status_code == 200
    assert listing.json()[0]["title"] == "Firewall alert"

    stored = await client.get(f"/api/cases/{body['case_id']}")
    assert stored.json()["indicator_count"] == 1


@pytest.mark.asyncio
async def test_report_endpoint_returns_pasteable_markdown(client):
    response = await client.post(
        "/api/triage/report?fmt=markdown",
        json={"indicators": ["185.220.101.34"], "title": "IR-2026-004"},
    )
    assert response.status_code == 200
    report = response.text
    assert "# SOC Triage Report: IR-2026-004" in report
    assert "## 1. Executive summary" in report
    assert "## 4. Recommended containment actions" in report
    assert "185[.]220[.]101[.]34" in report   # defanged for safe pasting
    assert "Block the address at the perimeter firewall" in report


@pytest.mark.asyncio
async def test_report_endpoint_returns_json_ticket(client):
    response = await client.post(
        "/api/triage/report?fmt=json", json={"indicators": ["185.220.101.34"]}
    )
    body = response.json()
    assert body["severity"] in ("high", "critical")
    assert body["indicators"][0]["defanged"] == "185[.]220[.]101[.]34"
    assert body["priority"].startswith(("P1", "P2"))


@pytest.mark.asyncio
async def test_allowlist_overrides_vendor_verdict(client):
    await client.post(
        "/api/lists",
        json={
            "value": "185.220.101.34",
            "ioc_type": "ip",
            "list_type": "allow",
            "reason": "lab egress",
        },
    )
    response = await client.post("/api/triage", json={"indicators": ["185.220.101.34"]})
    indicator = response.json()["indicators"][0]
    assert indicator["score"] == 0
    assert indicator["verdict"] == "allowlisted"
    assert any("allowlist" in m for m in indicator["modifiers"])


@pytest.mark.asyncio
async def test_empty_input_is_rejected(client):
    response = await client.post("/api/triage", json={"text": "nothing useful here"})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_scoring_model_is_auditable(client):
    body = (await client.get("/api/scoring/model")).json()
    assert body["weights"]["threatfox"] > body["weights"]["geoip"]
    assert body["thresholds"]["high"] > body["thresholds"]["medium"]


@pytest.mark.asyncio
async def test_case_report_regenerates_from_stored_results(client):
    case_id = (
        await client.post("/api/triage", json={"indicators": ["185.220.101.34"], "title": "stored"})
    ).json()["case_id"]
    report = await client.get(f"/api/cases/{case_id}/report?fmt=markdown")
    assert report.status_code == 200
    assert "stored" in report.text
    assert "185[.]220[.]101[.]34" in report.text


@pytest.mark.asyncio
async def test_audit_trail_records_every_triage(client):
    await client.post("/api/triage", json={"indicators": ["185.220.101.34"]})
    audit = (await client.get("/api/audit")).json()
    assert any(entry["action"] == "triage.completed" for entry in audit)
