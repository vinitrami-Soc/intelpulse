"""Jira and ServiceNow per workspace: each workspace raises tickets in its own tracker."""
from __future__ import annotations

import base64

import httpx
import pytest
from sqlalchemy import select

from app.config import settings
from app.db import session_scope
from app.models import DEFAULT_WORKSPACE_ID, AuditLog
from app.platform.box import server_box
from app.services import tickets
from app.services import workspace_settings as ws_settings

ACME_TOKEN = "acme-jira-token-0001"
GLOBEX_TOKEN = "globex-jira-token-0002"
TRIAGE = {"indicators": ["185.220.101.34"], "title": "Perimeter block burst"}


def jira(base: str, token: str) -> dict:
    return {"tickets": {"jira": {"base_url": base, "email": "soc@example.com", "project_key": "SOC",
                                 "api_token": token}}}


@pytest.fixture
def wire(monkeypatch):
    """What would have gone out: one entry per ticket request."""
    sent: list[dict] = []

    async def fake_post(url, *, headers, json, host=""):
        sent.append({"url": url, "auth": headers["Authorization"], "host": host})
        return httpx.Response(201, json={"key": "SOC-7"}, request=httpx.Request("POST", url))

    monkeypatch.setattr(tickets, "_post", fake_post)
    return sent


@pytest.fixture
async def two(people):
    ada = await people.set_up("ada", "Acme SOC")
    other = await people.workspace("Globex SOC")
    await people.member("bob", role="admin", workspace_id=other)
    return ada, await people.signed_in("bob")


async def _ticket(client, sink="jira"):
    case_id = (await client.post("/api/triage", json=TRIAGE)).json()["case_id"]
    return await client.post(f"/api/cases/{case_id}/ticket", params={"sink": sink})


async def test_a_workspace_raises_tickets_in_its_own_tracker_with_its_own_token(two, wire):
    ada, bob = two
    assert (await ada.patch("/api/settings", json=jira("https://acme.atlassian.net", ACME_TOKEN))).status_code == 200
    assert (await bob.patch("/api/settings", json=jira("https://globex.atlassian.net/", GLOBEX_TOKEN))).status_code == 200
    assert (await _ticket(ada)).status_code == 200
    assert (await _ticket(bob)).status_code == 200
    acme, globex = wire
    assert acme["url"].startswith("https://acme.atlassian.net/") and acme["host"] == "acme.atlassian.net"
    assert globex["url"].startswith("https://globex.atlassian.net/") and globex["host"] == "globex.atlassian.net"
    assert base64.b64decode(acme["auth"].split()[1]).decode().endswith(ACME_TOKEN)
    assert base64.b64decode(globex["auth"].split()[1]).decode().endswith(GLOBEX_TOKEN)


async def test_a_workspace_without_a_tracker_gets_a_clear_409(two, wire):
    ada, bob = two
    await ada.patch("/api/settings", json=jira("https://acme.atlassian.net", ACME_TOKEN))
    refused = await _ticket(bob)
    assert refused.status_code == 409 and "not configured for this workspace" in refused.json()["detail"]
    assert wire == []
    assert (await bob.get("/api/workspace")).json()["ticket_sinks"] == []
    assert (await ada.get("/api/workspace")).json()["ticket_sinks"] == ["jira"]


async def test_the_token_never_comes_back(two):
    ada, _bob = two
    answer = await ada.patch("/api/settings", json=jira("https://acme.atlassian.net", ACME_TOKEN))
    shown = answer.json()["tickets"]["jira"]
    assert shown["base_url"] == "https://acme.atlassian.net" and shown["project_key"] == "SOC"
    assert shown["api_token"] == {"set": True, "hint": "•" * 8 + "0001"}
    assert ACME_TOKEN not in answer.text and ACME_TOKEN not in (await ada.get("/api/settings")).text
    async with session_scope() as db:
        detail = [r.detail for r in (await db.execute(select(AuditLog))).scalars() if r.action == "settings.updated"]
    assert ACME_TOKEN not in str(detail)
    assert detail[-1]["tickets"]["jira"] == ["base_url", "email", "project_key", "api_token set"]


async def test_removing_the_token_turns_the_tracker_off(two, wire):
    ada, _bob = two
    await ada.patch("/api/settings", json=jira("https://acme.atlassian.net", ACME_TOKEN))
    await ada.patch("/api/settings", json={"tickets": {"jira": {"api_token": ""}}})
    assert (await _ticket(ada)).status_code == 409


@pytest.mark.parametrize("change", [
    {"base_url": "http://acme.atlassian.net"},                      # not https
    {"base_url": "https://user:pass@acme.atlassian.net"},          # credentials in the address
    {"base_url": "https://acme.atlassian.net/?next=evil"},         # a query
    {"base_url": "https://acme.atlassian.net/#x"},                 # a fragment
    {"base_url": "not an address"},
    {"email": "soc\r\nBcc: x@example.com"},
    {"project_key": "SOC DROP"},
    {"api_token": "tab\tinside"},
    {"issue": "Task"},
])
async def test_tracker_settings_that_cannot_be(two, change):
    ada, _bob = two
    assert (await ada.patch("/api/settings", json={"tickets": {"jira": change}})).status_code == 422


@pytest.mark.parametrize("table", ["incident/../sys_user", "incident?sysparm=x", "Incident"])
async def test_a_servicenow_table_is_a_plain_name(two, table):
    ada, _bob = two
    body = {"tickets": {"servicenow": {"base_url": "https://acme.service-now.com", "table": table}}}
    assert (await ada.patch("/api/settings", json=body)).status_code == 422


async def test_servicenow_per_workspace(two, monkeypatch):
    ada, _bob = two
    sent = []

    async def fake_post(url, *, headers, json, host=""):
        sent.append((url, host))
        return httpx.Response(201, json={"result": {"number": "INC0001", "sys_id": "abc"}},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(tickets, "_post", fake_post)
    body = {"tickets": {"servicenow": {"base_url": "https://acme.service-now.com", "user": "svc",
                                       "table": "sn_si_incident", "password": "a pass phrase"}}}
    assert (await ada.patch("/api/settings", json=body)).status_code == 200
    assert (await _ticket(ada, "servicenow")).status_code == 200
    assert sent == [("https://acme.service-now.com/api/now/table/sn_si_incident", "acme.service-now.com")]


async def test_only_an_admin_sets_a_tracker(people):
    await people.set_up()
    await people.member("bea", role="analyst")
    bea = await people.signed_in("bea")
    assert (await bea.patch("/api/settings", json=jira("https://acme.atlassian.net", ACME_TOKEN))).status_code == 403


async def test_1x_tracker_settings_move_once_and_never_overwrite(clean_db, monkeypatch):
    monkeypatch.setattr(settings, "jira_base_url", "https://old.atlassian.net")
    monkeypatch.setattr(settings, "jira_email", "soc@example.com")
    monkeypatch.setattr(settings, "jira_api_token", "token-from-the-environment")
    monkeypatch.setattr(settings, "jira_project_key", "OLD")
    monkeypatch.setattr(settings, "servicenow_base_url", None)
    monkeypatch.setattr(settings, "servicenow_password", None)
    async with session_scope() as db:
        assert await ws_settings.import_env_sinks(db, server_box()) == ["jira"]
        assert await ws_settings.import_env_sinks(db, server_box()) == []
        config = await ws_settings.sink_config(db, server_box(), DEFAULT_WORKSPACE_ID)
    assert (config.jira_base_url, config.jira_project_key, config.jira_api_token) == (
        "https://old.atlassian.net", "OLD", "token-from-the-environment")
    assert config.sinks() == ["jira"]
