"""Raising a case directly in Jira or ServiceNow.

The step this replaces is an analyst downloading Markdown at 2am and pasting it
into a tracker, which is the step that gets skipped. These tests cover the
three things that matter about doing it over the wire: the right request
reaches the vendor, a refusal comes back as a usable message, and the
credential never appears in that message.
"""
from __future__ import annotations

import base64

import httpx
import pytest

from app.config import settings
from app.services import tickets

TOKEN = "super-secret-token-value"


@pytest.fixture
def jira(monkeypatch):
    monkeypatch.setattr(settings, "jira_base_url", "https://example.atlassian.net")
    monkeypatch.setattr(settings, "jira_email", "soc@example.com")
    monkeypatch.setattr(settings, "jira_api_token", TOKEN)
    monkeypatch.setattr(settings, "jira_project_key", "SOC")
    monkeypatch.setattr(settings, "servicenow_base_url", None)
    monkeypatch.setattr(settings, "servicenow_password", None)


@pytest.fixture
def snow(monkeypatch):
    monkeypatch.setattr(settings, "servicenow_base_url", "https://example.service-now.com")
    monkeypatch.setattr(settings, "servicenow_user", "svc_intelpulse")
    monkeypatch.setattr(settings, "servicenow_password", TOKEN)
    monkeypatch.setattr(settings, "jira_base_url", None)
    monkeypatch.setattr(settings, "jira_api_token", None)


def stub(monkeypatch, status: int, payload):
    """Replace the outbound POST, recording what would have gone over the wire."""
    seen: dict = {}

    async def fake_post(url, *, headers, json):
        seen["url"] = url
        seen["headers"] = headers
        seen["json"] = json
        return httpx.Response(status, json=payload, request=httpx.Request("POST", url))

    monkeypatch.setattr(tickets, "_post", fake_post)
    return seen


CASE = {
    "case_id": "c-1",
    "title": "Perimeter block burst",
    "verdict": "critical",
    "score": 90,
    "indicators": [{"value": "185.220.101.34"}, {"value": "cdn.example.org"}],
}
BODY = "# IntelPulse case\n\nEvidence goes here."


def test_no_sink_is_configured_by_default(monkeypatch):
    for name in ("jira_base_url", "jira_api_token", "jira_project_key",
                 "servicenow_base_url", "servicenow_password"):
        monkeypatch.setattr(settings, name, None)
    assert tickets.configured_sinks() == []


def test_a_sink_needs_its_credential_not_just_a_url(monkeypatch):
    monkeypatch.setattr(settings, "jira_base_url", "https://example.atlassian.net")
    monkeypatch.setattr(settings, "jira_api_token", None)
    monkeypatch.setattr(settings, "jira_project_key", "SOC")
    monkeypatch.setattr(settings, "servicenow_base_url", None)
    monkeypatch.setattr(settings, "servicenow_password", None)
    assert tickets.configured_sinks() == []


@pytest.mark.anyio
async def test_jira_gets_the_issue_at_the_v3_endpoint(monkeypatch, jira):
    seen = stub(monkeypatch, 201, {"key": "SOC-42", "id": "10001"})
    ticket = await tickets.create_ticket(CASE, BODY, "jira")

    assert seen["url"] == "https://example.atlassian.net/rest/api/3/issue"
    fields = seen["json"]["fields"]
    assert fields["project"] == {"key": "SOC"}
    assert fields["issuetype"] == {"name": "Task"}
    assert "verdict-critical" in fields["labels"]
    assert "CRITICAL" in fields["summary"] and "Perimeter block burst" in fields["summary"]
    # Jira Cloud takes Atlassian Document Format, not Markdown.
    assert fields["description"]["type"] == "doc"
    assert fields["description"]["content"][0]["content"][0]["text"] == BODY

    assert ticket.sink == "jira"
    assert ticket.key == "SOC-42"
    assert ticket.url == "https://example.atlassian.net/browse/SOC-42"


@pytest.mark.anyio
async def test_jira_is_authenticated_with_the_configured_token(monkeypatch, jira):
    seen = stub(monkeypatch, 201, {"key": "SOC-1"})
    await tickets.create_ticket(CASE, BODY, "jira")
    expected = base64.b64encode(f"soc@example.com:{TOKEN}".encode()).decode()
    assert seen["headers"]["Authorization"] == "Basic " + expected


@pytest.mark.anyio
async def test_servicenow_gets_an_incident_with_an_inverted_urgency(monkeypatch, snow):
    seen = stub(monkeypatch, 201, {"result": {"number": "INC0012345", "sys_id": "abc123"}})
    ticket = await tickets.create_ticket(CASE, BODY, "servicenow")

    assert seen["url"] == "https://example.service-now.com/api/now/table/incident"
    # ServiceNow runs 1 (high) to 3 (low) — the inverse of how a verdict reads.
    assert seen["json"]["urgency"] == "1"
    assert seen["json"]["correlation_id"] == "c-1"
    assert seen["json"]["description"] == BODY
    assert ticket.key == "INC0012345"
    assert "abc123" in ticket.url


@pytest.mark.anyio
async def test_a_quiet_verdict_maps_to_the_lowest_urgency(monkeypatch, snow):
    seen = stub(monkeypatch, 201, {"result": {"number": "INC1", "sys_id": "x"}})
    await tickets.create_ticket({**CASE, "verdict": "low"}, BODY, "servicenow")
    assert seen["json"]["urgency"] == "3"


@pytest.mark.anyio
async def test_an_unconfigured_sink_is_refused_before_any_request(monkeypatch, jira):
    called = stub(monkeypatch, 201, {})
    with pytest.raises(tickets.TicketError) as exc:
        await tickets.create_ticket(CASE, BODY, "servicenow")
    assert exc.value.status == 409
    assert "not configured" in str(exc.value)
    assert called == {}, "a request went out for a sink that is not set up"


@pytest.mark.anyio
async def test_a_vendor_refusal_carries_the_vendor_message(monkeypatch, jira):
    stub(monkeypatch, 400, {"errorMessages": ["issue type is required"], "errors": {}})
    with pytest.raises(tickets.TicketError) as exc:
        await tickets.create_ticket(CASE, BODY, "jira")
    assert exc.value.status == 400
    assert "issue type is required" in str(exc.value)


@pytest.mark.anyio
async def test_a_field_level_refusal_is_readable_too(monkeypatch, jira):
    stub(monkeypatch, 400, {"errorMessages": [], "errors": {"project": "does not exist"}})
    with pytest.raises(tickets.TicketError) as exc:
        await tickets.create_ticket(CASE, BODY, "jira")
    assert "project" in str(exc.value) and "does not exist" in str(exc.value)


@pytest.mark.anyio
async def test_an_error_never_leaks_the_credential(monkeypatch, jira):
    """The message goes to an analyst's screen and into a log line."""
    stub(monkeypatch, 401, {"errorMessages": ["Client must be authenticated"]})
    with pytest.raises(tickets.TicketError) as exc:
        await tickets.create_ticket(CASE, BODY, "jira")
    assert TOKEN not in str(exc.value)
    assert "Basic " not in str(exc.value)


@pytest.mark.anyio
async def test_an_unreachable_sink_is_a_502_not_a_crash(monkeypatch, jira):
    async def boom(url, *, headers, json):
        raise httpx.ConnectError("name or service not known")

    monkeypatch.setattr(tickets, "_post", boom)
    with pytest.raises(tickets.TicketError) as exc:
        await tickets.create_ticket(CASE, BODY, "jira")
    assert exc.value.status == 502
    assert "could not reach jira" in str(exc.value)


@pytest.mark.anyio
async def test_a_vendor_that_answers_with_html_still_gives_a_message(monkeypatch, jira):
    async def html(url, *, headers, json):
        return httpx.Response(
            502, text="<html>bad gateway</html>", request=httpx.Request("POST", url)
        )

    monkeypatch.setattr(tickets, "_post", html)
    with pytest.raises(tickets.TicketError) as exc:
        await tickets.create_ticket(CASE, BODY, "jira")
    assert "502" in str(exc.value)


@pytest.mark.anyio
async def test_the_report_body_is_truncated_rather_than_rejected(monkeypatch, jira):
    seen = stub(monkeypatch, 201, {"key": "SOC-9"})
    await tickets.create_ticket(CASE, "x" * 50_000, "jira")
    text = seen["json"]["fields"]["description"]["content"][0]["content"][0]["text"]
    assert len(text) == 30_000


# ── the egress policy still owns which hosts the server may reach ───────────

@pytest.mark.anyio
async def test_a_configured_sink_host_is_allowed_through_the_egress_policy(jira):
    from app import net

    assert "example.atlassian.net" in net.ticket_sink_hosts()


@pytest.mark.anyio
async def test_a_host_nobody_configured_is_still_refused(jira, monkeypatch):
    """Widening the allowlist for a sink must not widen it for anything else."""
    from app import net

    with pytest.raises(net.EgressBlocked) as exc:
        await net.assert_allowed(httpx.URL("https://attacker.example/steal"))
    assert "non-allowlisted" in str(exc.value)


@pytest.mark.anyio
async def test_a_sink_is_still_refused_over_plain_http(monkeypatch):
    from app import net

    monkeypatch.setattr(settings, "jira_base_url", "http://jira.internal")
    with pytest.raises(net.EgressBlocked) as exc:
        await net.assert_allowed(httpx.URL("http://jira.internal/rest/api/3/issue"))
    assert "non-HTTPS" in str(exc.value)


@pytest.mark.anyio
async def test_a_self_hosted_sink_on_private_space_needs_an_explicit_opt_in(monkeypatch):
    """Off by default: a sink resolving into reserved space is usually a typo."""
    from app import net

    monkeypatch.setattr(settings, "jira_base_url", "https://jira.internal")
    monkeypatch.setattr(settings, "ticket_allow_private_host", False)

    async def resolves_private(host):
        return ("10.0.0.5",)

    monkeypatch.setattr(net, "resolve", resolves_private)
    with pytest.raises(net.EgressBlocked) as exc:
        await net.assert_allowed(httpx.URL("https://jira.internal/rest/api/3/issue"))
    assert "non-routable" in str(exc.value)

    monkeypatch.setattr(settings, "ticket_allow_private_host", True)
    await net.assert_allowed(httpx.URL("https://jira.internal/rest/api/3/issue"))


@pytest.mark.anyio
async def test_the_opt_in_never_applies_to_an_intelligence_provider(monkeypatch):
    """A vendor redirecting into the metadata service is refused regardless."""
    from app import net

    monkeypatch.setattr(settings, "ticket_allow_private_host", True)
    monkeypatch.setattr(settings, "jira_base_url", "https://jira.internal")

    async def metadata(host):
        return ("169.254.169.254",)

    monkeypatch.setattr(net, "resolve", metadata)
    with pytest.raises(net.EgressBlocked) as exc:
        await net.assert_allowed(httpx.URL("https://api.abuseipdb.com/api/v2/check"))
    assert "non-routable" in str(exc.value)
