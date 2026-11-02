"""The case workflow: status, assignee, closing, tickets, and finding a case again."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import update

from app.db import session_scope
from app.models import Case, User, utcnow
from app.services import tickets as tickets_service
from app.services.tickets import Ticket

TRIAGE = {"indicators": ["185.220.101.34"], "title": "Perimeter block burst"}


async def _case(client, **body) -> str:
    response = await client.post("/api/triage", json={**TRIAGE, **body})
    assert response.status_code == 200, response.text
    return response.json()["case_id"]


async def _member_id(username: str) -> int:
    async with session_scope() as db:
        return next(u.id for u in (await db.execute(User.__table__.select())).all() if u.username == username)


@pytest.fixture
async def team(people):
    """(owner, bea, bea's id): the owner and an analyst in Acme SOC."""
    owner = await people.set_up("ada", "Acme SOC")
    await people.member("bea", role="analyst")
    bea = await people.signed_in("bea")
    return owner, bea, await _member_id("bea")


async def test_a_new_case_is_new_and_unassigned(team):
    owner, _bea, _ = team
    case = (await owner.get(f"/api/cases/{await _case(owner)}")).json()
    assert case["status"] == "new" and case["assignee"] is None
    assert case["closed_at"] is None and case["tickets"] == []


async def test_an_analyst_takes_a_case_and_works_it(team):
    owner, bea, bea_id = team
    case_id = await _case(owner)
    answer = await bea.patch(f"/api/cases/{case_id}", json={"status": "in_progress", "assignee_id": bea_id})
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert body["status"] == "in_progress" and body["assignee"]["username"] == "bea"
    assert sorted(body["changed"]) == ["assignee_id", "status"]


async def test_closing_needs_a_reason_and_stamps_the_time(team):
    owner, _bea, _ = team
    case_id = await _case(owner)
    refused = await owner.patch(f"/api/cases/{case_id}", json={"status": "closed"})
    assert refused.status_code == 422 and "reason" in refused.json()["detail"]
    closed = (await owner.patch(f"/api/cases/{case_id}", json={"status": "closed", "closed_reason": "false_positive"})).json()
    assert closed["status"] == "closed" and closed["closed_reason"] == "false_positive" and closed["closed_at"]
    # the reason can be corrected without reopening, and the time stays
    again = (await owner.patch(f"/api/cases/{case_id}", json={"closed_reason": "benign"})).json()
    assert again["closed_reason"] == "benign" and again["closed_at"] == closed["closed_at"]


async def test_reopening_clears_the_reason_and_the_time(team):
    owner, _bea, _ = team
    case_id = await _case(owner)
    await owner.patch(f"/api/cases/{case_id}", json={"status": "closed", "closed_reason": "true_positive"})
    reopened = (await owner.patch(f"/api/cases/{case_id}", json={"status": "in_progress"})).json()
    assert reopened["closed_reason"] is None and reopened["closed_at"] is None
    refused = await owner.patch(f"/api/cases/{case_id}", json={"closed_reason": "benign"})
    assert refused.status_code == 422


@pytest.mark.parametrize("body", [
    {"status": "done"}, {"closed_reason": "because"}, {"assignee_id": 0}, {"priority": "high"}, {},
])
async def test_what_a_case_cannot_become(team, body):
    owner, _bea, _ = team
    case_id = await _case(owner)
    assert (await owner.patch(f"/api/cases/{case_id}", json=body)).status_code == 422


async def test_only_an_active_member_of_the_workspace_is_assigned(team, people):
    owner, _bea, bea_id = team
    other = await people.workspace("Globex SOC")
    await people.member("bob", role="admin", workspace_id=other)
    case_id = await _case(owner)
    for assignee in (await _member_id("bob"), 999_999):
        answer = await owner.patch(f"/api/cases/{case_id}", json={"assignee_id": assignee})
        assert answer.status_code == 422 and "member" in answer.json()["detail"]
    async with session_scope() as db:
        await db.execute(update(User).where(User.id == bea_id).values(disabled=True))
    assert (await owner.patch(f"/api/cases/{case_id}", json={"assignee_id": bea_id})).status_code == 422
    assert (await owner.patch(f"/api/cases/{case_id}", json={"assignee_id": None})).status_code == 200


async def test_every_change_is_audited_with_before_and_after(team):
    owner, bea, bea_id = team
    case_id = await _case(owner)
    await bea.patch(f"/api/cases/{case_id}", json={"status": "in_progress", "assignee_id": bea_id})
    record = next(r for r in (await owner.get("/api/audit")).json() if r["action"] == "case.updated")
    assert record["actor"] == "bea" and record["target"] == case_id
    assert record["detail"]["status"] == {"from": "new", "to": "in_progress"}
    assert record["detail"]["assignee_id"] == {"from": None, "to": bea_id}


async def test_only_a_person_moves_a_case(team, people, client):
    owner, _bea, _ = team
    case_id = await _case(owner)
    script = await people.token(owner, "triage")
    assert (await script.patch(f"/api/cases/{case_id}", json={"status": "in_progress"})).status_code == 403
    assert (await client.patch(f"/api/cases/{case_id}", json={"status": "in_progress"})).status_code == 403


async def test_another_workspace_cannot_move_it(team, people):
    owner, _bea, _ = team
    other = await people.workspace("Globex SOC")
    await people.member("bob", role="admin", workspace_id=other)
    bob = await people.signed_in("bob")
    case_id = await _case(owner)
    assert (await bob.patch(f"/api/cases/{case_id}", json={"status": "closed", "closed_reason": "benign"})).status_code == 404
    assert (await owner.get(f"/api/cases/{case_id}")).json()["status"] == "new"


# -- finding a case again ----------------------------------------------------------
async def test_search_and_filters(team):
    owner, bea, bea_id = team
    perimeter = await _case(owner, title="Perimeter block burst")
    phishing = await _case(owner, indicators=["evil-login.example.com"], title="Reported phish")
    await bea.patch(f"/api/cases/{phishing}", json={"status": "in_progress", "assignee_id": bea_id})
    await owner.patch(f"/api/cases/{perimeter}", json={"status": "closed", "closed_reason": "benign"})

    async def ids(**params) -> set[str]:
        response = await bea.get("/api/cases", params=params)
        assert response.status_code == 200, response.text
        return {c["id"] for c in response.json()}

    assert await ids(q="perimeter") == {perimeter}               # a word of the title, any case
    assert await ids(q="EVIL-LOGIN") == {phishing}               # part of an indicator
    assert await ids(q="%") == set()                              # a wildcard is a character
    assert await ids(status="closed") == {perimeter}
    assert await ids(status="open") == {phishing}
    assert await ids(assignee="me") == {phishing}
    assert await ids(assignee="none") == {perimeter}
    assert await ids(assignee=str(bea_id)) == {phishing}
    assert await ids(source="api") == {perimeter, phishing}
    assert await ids(since=(utcnow() + timedelta(hours=1)).isoformat()) == set()
    assert await ids(until=(utcnow() + timedelta(hours=1)).isoformat()) == {perimeter, phishing}
    listed = {c["id"]: c for c in (await bea.get("/api/cases")).json()}
    assert listed[phishing]["assignee"]["username"] == "bea" and listed[perimeter]["closed_reason"] == "benign"


@pytest.mark.parametrize("params", [{"status": "done"}, {"assignee": "everyone"}, {"since": "yesterday"}])
async def test_a_filter_that_makes_no_sense_is_refused(team, params):
    owner, _bea, _ = team
    assert (await owner.get("/api/cases", params=params)).status_code == 422


async def test_the_1x_list_still_answers_as_it_did(client):
    """A 1.x script reads the same fields it always did; the workflow fields are extra."""
    await client.post("/api/triage", json=TRIAGE)
    row = (await client.get("/api/cases")).json()[0]
    for field in ("id", "title", "verdict", "max_score", "indicator_count", "source", "duration_ms", "created_at"):
        assert field in row
    assert row["status"] == "new" and row["ticket_count"] == 0


# -- tickets are kept with the case --------------------------------------------------
async def test_a_ticket_is_kept_with_its_case(team, monkeypatch):
    owner, _bea, _ = team

    async def filed(meta, body, sink):
        return Ticket(sink=sink, key="SOC-42", url="https://jira.example.com/browse/SOC-42")

    monkeypatch.setattr("app.routers.cases.create_ticket", filed)
    case_id = await _case(owner)
    assert (await owner.post(f"/api/cases/{case_id}/ticket", params={"sink": "jira"})).status_code == 200
    case = (await owner.get(f"/api/cases/{case_id}")).json()
    assert [(t["sink"], t["key"], t["created_by"]) for t in case["tickets"]] == [("jira", "SOC-42", "ada")]
    assert (await owner.get("/api/cases")).json()[0]["ticket_count"] == 1
    assert tickets_service  # the real sink is untouched


async def test_old_cases_without_a_status_read_as_new(team):
    owner, _bea, _ = team
    case_id = await _case(owner)
    async with session_scope() as db:
        assert (await db.get(Case, case_id)).status == "new"
