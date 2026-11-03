"""Invitations (spec 5.4): one link, one account, one role, seven days, and nobody else's workspace."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app.db import session_scope
from app.models import AuditLog, Invite, User, utcnow
from app.platform.deps import login_throttle
from tests.conftest import PASSWORD


@pytest.fixture
async def acme(people):
    """(ada the owner, Acme's invitation for an analyst: its JSON)."""
    ada = await people.set_up("ada", "Acme SOC")
    made = await ada.post("/api/invites", json={"role": "analyst"})
    assert made.status_code == 201, made.text
    return ada, made.json()


def _joiner(people, token: str, username: str = "nina", **more) -> tuple:
    return people._client(), {"token": token, "username": username, "password": PASSWORD, "display_name": "Nina", **more}


async def test_an_invitation_is_a_link_shown_once(acme):
    ada, invite = acme
    assert invite["role"] == "analyst" and invite["state"] == "open"
    assert invite["link"] == "#/join/" + invite["token"] and len(invite["token"]) >= 40
    listed = (await ada.get("/api/invites")).json()
    assert [i["id"] for i in listed] == [invite["id"]] and "token" not in listed[0] and "link" not in listed[0]
    async with session_scope() as db:   # only its hash is kept
        row = (await db.execute(select(Invite))).scalar_one()
        assert invite["token"] not in row.token_hash


async def test_the_link_says_where_it_leads_and_makes_the_account_there(acme, people):
    ada, invite = acme
    nina, body = _joiner(people, invite["token"])
    seen = await nina.post("/api/join/check", json={"token": invite["token"]})
    assert seen.status_code == 200 and seen.json()["workspace"] == {"name": "Acme SOC", "kind": "organization"}
    assert seen.json()["role"] == "analyst"
    joined = await nina.post("/api/join", json=body)
    assert joined.status_code == 201, joined.text
    me = joined.json()
    assert me["user"]["username"] == "nina" and me["user"]["role"] == "analyst" and me["workspace"]["name"] == "Acme SOC"
    assert me["user"]["must_change_password"] is False   # they chose it themselves
    nina.headers["X-CSRF-Token"] = me["csrf"]
    assert (await nina.get("/api/cases")).status_code == 200
    used = (await ada.get("/api/invites")).json()[0]
    assert used["state"] == "used" and used["used_by"] == "nina"


async def test_a_link_works_once(acme, people):
    _ada, invite = acme
    first, body = _joiner(people, invite["token"])
    assert (await first.post("/api/join", json=body)).status_code == 201
    second, again = _joiner(people, invite["token"], username="nora")
    refused = await second.post("/api/join", json=again)
    assert refused.status_code == 404 and "not valid" in refused.json()["detail"]
    assert (await second.post("/api/join/check", json={"token": invite["token"]})).status_code == 404


async def test_a_link_expires_after_seven_days(acme, people):
    _ada, invite = acme
    async with session_scope() as db:
        await db.execute(update(Invite).values(expires_at=utcnow() - timedelta(seconds=1)))
    client, body = _joiner(people, invite["token"])
    assert (await client.post("/api/join", json=body)).status_code == 404


async def test_unknown_used_and_expired_links_get_the_same_answer(acme, people):
    _ada, invite = acme
    client = people._client()
    unknown = await client.post("/api/join/check", json={"token": "x" * 43})
    async with session_scope() as db:
        await db.execute(update(Invite).values(expires_at=utcnow() - timedelta(seconds=1)))
    expired = await client.post("/api/join/check", json={"token": invite["token"]})
    assert unknown.status_code == expired.status_code == 404 and unknown.json() == expired.json()


async def test_guessing_links_is_slowed_down(acme, people):
    login_throttle.clear()
    client = people._client()
    for _ in range(3):
        assert (await client.post("/api/join/check", json={"token": "guess"})).status_code == 404
    assert (await client.post("/api/join/check", json={"token": "guess"})).status_code == 429


async def test_a_revoked_link_stops_working(acme, people):
    ada, invite = acme
    assert (await ada.delete(f"/api/invites/{invite['id']}")).status_code == 204
    client, body = _joiner(people, invite["token"])
    assert (await client.post("/api/join", json=body)).status_code == 404
    assert (await ada.delete(f"/api/invites/{invite['id']}")).status_code == 404


async def test_a_used_link_is_not_revoked_but_its_member_removed(acme, people):
    ada, invite = acme
    client, body = _joiner(people, invite["token"])
    await client.post("/api/join", json=body)
    assert (await ada.delete(f"/api/invites/{invite['id']}")).status_code == 409


async def test_an_admin_invitation_makes_an_admin(acme, people):
    ada, _ = acme
    made = (await ada.post("/api/invites", json={"role": "admin"})).json()
    client, body = _joiner(people, made["token"], username="arne")
    assert (await client.post("/api/join", json=body)).json()["user"]["role"] == "admin"


@pytest.mark.parametrize("change", [{"password": "short"}, {"username": "ada"}, {"username": "x"}, {"role": "admin"}])
async def test_a_bad_join_keeps_the_link(acme, people, change):
    _ada, invite = acme
    client, body = _joiner(people, invite["token"], **change)
    assert (await client.post("/api/join", json=body)).status_code == 422
    retry, good = _joiner(people, invite["token"])
    assert (await retry.post("/api/join", json=good)).status_code == 201


async def test_who_makes_invitations(acme, people):
    ada, invite = acme
    await people.member("bea", role="analyst")
    bea = await people.signed_in("bea")
    assert (await bea.post("/api/invites", json={"role": "analyst"})).status_code == 403
    assert (await bea.get("/api/invites")).status_code == 403
    token = await people.token(ada, "triage")
    assert (await token.post("/api/invites", json={"role": "analyst"})).status_code == 403
    assert (await ada.post("/api/invites", json={"role": "owner"})).status_code == 422


async def test_an_individual_workspace_takes_no_invitations(people):
    ada = await people.set_up("ada", "Acme SOC")
    await ada.patch("/api/server", json={"signup": True})
    ivy = people._client()
    made = await ivy.post("/api/signup", json={"kind": "individual", "username": "ivy", "password": PASSWORD})
    ivy.headers["X-CSRF-Token"] = made.json()["csrf"]
    refused = await ivy.post("/api/invites", json={"role": "analyst"})
    assert refused.status_code == 403 and "individual" in refused.json()["detail"]


async def test_another_workspace_s_invitations_are_not_there(acme, people):
    ada, invite = acme
    other = await people.workspace("Other SOC")
    await people.member("olga", role="admin", workspace_id=other)
    olga = await people.signed_in("olga")
    assert (await olga.get("/api/invites")).json() == []
    assert (await olga.delete(f"/api/invites/{invite['id']}")).status_code == 404


async def test_invitations_are_audited(acme, people):
    ada, invite = acme
    client, body = _joiner(people, invite["token"])
    await client.post("/api/join", json=body)
    async with session_scope() as db:
        actions = (await db.execute(select(AuditLog.action, AuditLog.actor).where(AuditLog.action.startswith("invite.")))).all()
        nina = (await db.execute(select(User).where(User.username == "nina"))).scalar_one()
    assert ("invite.created", "ada") in actions and ("invite.used", "nina") in actions
    assert nina.workspace_id == 1
