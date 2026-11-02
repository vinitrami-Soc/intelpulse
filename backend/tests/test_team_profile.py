"""Team (members and roles), Profile (one's own account), and the audit log's filters and check."""
from __future__ import annotations

import pytest
from sqlalchemy import update

from app.db import session_scope
from app.models import AuditLog, Case, User

from .conftest import PASSWORD

NEW_PASSWORD = "a brand new passphrase"


async def _id(username: str) -> int:
    async with session_scope() as db:
        rows = (await db.execute(User.__table__.select())).all()
    return next(row.id for row in rows if row.username == username)


@pytest.fixture
async def team(people):
    """(ada the owner, adam an admin, bea an analyst), all in Acme SOC, all signed in."""
    ada = await people.set_up("ada", "Acme SOC")
    await people.member("adam", role="admin")
    await people.member("bea", role="analyst")
    return ada, await people.signed_in("adam"), await people.signed_in("bea")


# -- the member list ------------------------------------------------------------------
async def test_every_member_sees_the_team_and_only_an_admin_sees_more(team):
    ada, _adam, bea = team
    seen_by_bea = (await bea.get("/api/users")).json()
    assert [m["username"] for m in seen_by_bea] == ["ada", "adam", "bea"]
    assert "email" not in seen_by_bea[0] and "last_login_at" not in seen_by_bea[0]
    assert "email" in (await ada.get("/api/users")).json()[0]


async def test_another_workspaces_members_are_neither_listed_nor_reachable(team, people):
    ada, _adam, _bea = team
    other = await people.workspace("Globex SOC")
    await people.member("bob", role="admin", workspace_id=other)
    bob = await people.signed_in("bob")
    assert [m["username"] for m in (await bob.get("/api/users")).json()] == ["bob"]
    bea_id = await _id("bea")
    assert (await bob.patch(f"/api/users/{bea_id}", json={"disabled": True})).status_code == 404
    assert (await bob.delete(f"/api/users/{bea_id}")).status_code == 404


async def test_tokens_and_the_1x_token_cannot_reach_the_team(team, people, client):
    ada, _adam, _bea = team
    script = await people.token(ada, "read")
    assert (await script.get("/api/users")).status_code == 403
    assert (await client.get("/api/users")).status_code == 403


# -- an admin manages members ----------------------------------------------------------
async def test_an_admin_adds_a_member_who_must_choose_a_password(team, people):
    _ada, adam, _bea = team
    made = await adam.post("/api/users", json={"username": "carl", "display_name": "Carl", "password": PASSWORD})
    assert made.status_code == 201 and made.json()["must_change_password"] is True
    carl = await people.signed_in("carl")
    blocked = await carl.get("/api/cases")
    assert blocked.status_code == 403 and blocked.json()["error"] == "password_change_required"
    assert (await carl.get("/api/profile")).json()["must_change_password"] is True
    refused = await carl.patch("/api/profile", json={"display_name": "C"})
    assert refused.status_code == 403
    changed = await carl.patch("/api/profile", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert changed.status_code == 200 and changed.json()["must_change_password"] is False
    assert (await carl.get("/api/cases")).status_code == 200


async def test_an_analyst_manages_nobody(team):
    _ada, _adam, bea = team
    adam_id = await _id("adam")
    assert (await bea.post("/api/users", json={"username": "eve", "password": PASSWORD})).status_code == 403
    assert (await bea.patch(f"/api/users/{adam_id}", json={"disabled": True})).status_code == 403


async def test_disabling_a_member_signs_them_out(team):
    _ada, adam, bea = team
    assert (await bea.get("/api/cases")).status_code == 200
    assert (await adam.patch(f"/api/users/{await _id('bea')}", json={"disabled": True})).status_code == 200
    assert (await bea.get("/api/cases")).status_code == 401


async def test_a_reset_password_ends_their_sessions_and_must_be_changed(team, people):
    _ada, adam, bea = team
    answer = await adam.patch(f"/api/users/{await _id('bea')}", json={"password": NEW_PASSWORD})
    assert answer.status_code == 200 and answer.json()["changed"] == ["password"]
    assert (await bea.get("/api/cases")).status_code == 401
    again = people._client()
    signed = await again.post("/api/session", json={"username": "bea", "password": NEW_PASSWORD})
    assert signed.status_code == 200 and signed.json()["user"]["must_change_password"] is True


async def test_only_the_owner_sets_an_admins_password_or_touches_the_owner(team):
    ada, adam, _bea = team
    await adam.post("/api/users", json={"username": "abe", "role": "admin", "password": PASSWORD})
    abe_id = await _id("abe")
    assert (await adam.patch(f"/api/users/{abe_id}", json={"password": NEW_PASSWORD})).status_code == 403
    assert (await ada.patch(f"/api/users/{abe_id}", json={"password": NEW_PASSWORD})).status_code == 200
    owner_id = await _id("ada")
    for body in ({"disabled": True}, {"role": "analyst"}, {"display_name": "Mallory"}):
        assert (await adam.patch(f"/api/users/{owner_id}", json=body)).status_code == 403
    assert (await adam.delete(f"/api/users/{owner_id}")).status_code == 403


async def test_nobody_demotes_disables_or_removes_themselves(team):
    _ada, adam, _bea = team
    me = await _id("adam")
    for body in ({"role": "analyst"}, {"disabled": True}):
        assert (await adam.patch(f"/api/users/{me}", json=body)).status_code == 403
    assert (await adam.delete(f"/api/users/{me}")).status_code == 403


async def test_removing_a_member_keeps_their_work(team):
    _ada, adam, bea = team
    bea_id = await _id("bea")
    case_id = (await bea.post("/api/triage", json={"indicators": ["185.220.101.34"]})).json()["case_id"]
    await adam.patch(f"/api/cases/{case_id}", json={"assignee_id": bea_id})
    assert (await adam.delete(f"/api/users/{bea_id}")).status_code == 204
    case = (await adam.get(f"/api/cases/{case_id}")).json()
    assert case["assignee"] is None and case["title"]
    async with session_scope() as db:
        row = await db.get(Case, case_id)
    assert row.created_by is None and row.assignee_id is None
    assert (await bea.get("/api/cases")).status_code == 401


@pytest.mark.parametrize("body", [
    {"username": "Bad Name", "password": PASSWORD}, {"username": "eve", "password": "short"},
    {"username": "eve", "password": PASSWORD, "role": "owner"}, {"username": "ada", "password": PASSWORD},
])
async def test_members_that_cannot_be_added(team, body):
    _ada, adam, _bea = team
    assert (await adam.post("/api/users", json=body)).status_code == 422


# -- one's own profile ---------------------------------------------------------------
async def test_a_member_changes_their_name_and_email(team):
    _ada, _adam, bea = team
    answer = await bea.patch("/api/profile", json={"display_name": "Bea Torres", "email": "bea@acme.example"})
    assert answer.status_code == 200 and answer.json()["display_name"] == "Bea Torres"
    assert (await bea.patch("/api/profile", json={"email": "not-an-address"})).status_code == 422


async def test_a_new_password_needs_the_current_one_and_ends_other_sessions(team, people):
    _ada, _adam, bea = team
    elsewhere = await people.signed_in("bea")
    wrong = await bea.patch("/api/profile", json={"current_password": "not it at all", "new_password": NEW_PASSWORD})
    assert wrong.status_code == 403 and wrong.json()["error"] == "wrong_password"
    same = await bea.patch("/api/profile", json={"current_password": PASSWORD, "new_password": PASSWORD})
    assert same.status_code == 422
    ok = await bea.patch("/api/profile", json={"current_password": PASSWORD, "new_password": NEW_PASSWORD})
    assert ok.status_code == 200 and ok.json()["changed"] == ["password"]
    assert (await bea.get("/api/cases")).status_code == 200          # this session stays
    assert (await elsewhere.get("/api/cases")).status_code == 401    # every other one ends


# -- the audit log: filters and the check ------------------------------------------------
async def test_the_audit_log_filters(team):
    ada, adam, bea = team
    case_id = (await bea.post("/api/triage", json={"indicators": ["185.220.101.34"]})).json()["case_id"]
    await adam.patch(f"/api/cases/{case_id}", json={"status": "in_progress"})
    actions = {r["action"] for r in (await ada.get("/api/audit", params={"action": "case."})).json()}
    assert actions == {"case.updated"}
    assert {r["actor"] for r in (await ada.get("/api/audit", params={"by": "bea"})).json()} == {"bea"}
    assert (await ada.get("/api/audit", params={"action": "%"})).json() == []   # a wildcard is a character


async def test_verifying_the_chain_tells_the_owner_what_broke_and_an_admin_whether(team):
    ada, adam, bea = team
    await bea.post("/api/triage", json={"indicators": ["185.220.101.34"]})
    intact = (await adam.get("/api/audit/verify")).json()
    assert intact["intact"] is True and intact["problems"] == 0 and "details" not in intact
    async with session_scope() as db:
        first = (await db.execute(AuditLog.__table__.select().order_by(AuditLog.id))).first()
        await db.execute(update(AuditLog).where(AuditLog.id == first.id).values(actor="someone else"))
    broken_for_admin = (await adam.get("/api/audit/verify")).json()
    broken_for_owner = (await ada.get("/api/audit/verify")).json()
    assert broken_for_admin["intact"] is False and "details" not in broken_for_admin
    assert broken_for_owner["intact"] is False and f"record {first.id} was changed" in broken_for_owner["details"]
    assert (await bea.get("/api/audit/verify")).status_code == 403
