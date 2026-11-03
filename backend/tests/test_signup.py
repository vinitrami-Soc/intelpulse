"""Sign-up (spec 5.3) and the owner's server settings: off until the owner allows it,
capped per day for the whole server and per address, and a new workspace starts empty."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app.db import session_scope
from app.models import AuditLog, User, Workspace, utcnow
from app.security import limiter
from tests.conftest import PASSWORD

JUST_ME = {"kind": "individual", "username": "ivy", "display_name": "Ivy", "password": PASSWORD}
ORG = {"kind": "organization", "username": "olaf", "password": PASSWORD, "organization": "Fjord CERT"}


@pytest.fixture
async def owner(people):
    owner = await people.set_up("ada", "Acme SOC")
    limiter._hits.clear()
    return owner


async def _open_signup(owner, **more) -> None:
    answer = await owner.patch("/api/server", json={"signup": True, **more})
    assert answer.status_code == 200, answer.text


async def test_sign_up_is_closed_until_the_owner_opens_it(owner, people):
    stranger = people._client()
    assert (await stranger.get("/api/session")).json()["signup"] is False
    refused = await stranger.post("/api/signup", json=JUST_ME)
    assert refused.status_code == 403 and refused.json()["error"] == "signup_closed"
    await _open_signup(owner)
    assert (await stranger.get("/api/session")).json()["signup"] is True


async def test_just_me_makes_an_individual_workspace_and_signs_in(owner, people):
    await _open_signup(owner)
    ivy = people._client()
    made = await ivy.post("/api/signup", json=JUST_ME)
    assert made.status_code == 201, made.text
    body = made.json()
    assert body["user"]["username"] == "ivy" and body["user"]["role"] == "admin" and body["user"]["owner"] is False
    assert body["workspace"]["kind"] == "individual" and body["workspace"]["name"] == "Ivy"
    ivy.headers["X-CSRF-Token"] = body["csrf"]
    assert (await ivy.get("/api/session")).json()["user"]["username"] == "ivy"
    # a new workspace starts empty: none of Acme's cases, members or settings
    await owner.post("/api/triage", json={"indicators": ["185.220.101.34"], "title": "Acme's own"})
    assert (await ivy.get("/api/cases")).json() == []
    assert [m["username"] for m in (await ivy.get("/api/users")).json()] == ["ivy"]
    assert (await ivy.get("/api/stats")).json()["cases"] == 0


async def test_my_organization_needs_its_name(owner, people):
    await _open_signup(owner)
    client = people._client()
    nameless = await client.post("/api/signup", json={**ORG, "organization": "  "})
    assert nameless.status_code == 422 and "name" in nameless.json()["detail"]
    made = await client.post("/api/signup", json=ORG)
    assert made.status_code == 201, made.text
    assert made.json()["workspace"] == {"id": made.json()["workspace"]["id"], "name": "Fjord CERT", "kind": "organization"}


@pytest.mark.parametrize("body", [
    {**JUST_ME, "password": "too short"},
    {**JUST_ME, "username": "x"},
    {**JUST_ME, "username": "ada"},          # taken
    {**JUST_ME, "kind": "family"},
    {**JUST_ME, "email": "not an address"},
    {**JUST_ME, "owner": True},              # nobody signs themselves up as the owner
])
async def test_what_a_sign_up_cannot_be(owner, people, body):
    await _open_signup(owner)
    answer = await people._client().post("/api/signup", json=body)
    assert answer.status_code == 422, answer.text
    async with session_scope() as db:   # and nothing is left behind
        assert (await db.execute(select(Workspace.id))).scalars().all() == [1]


async def test_the_daily_cap_is_the_whole_server_s(owner, people):
    await _open_signup(owner, signup_daily_cap=1)
    assert (await people._client().post("/api/signup", json=JUST_ME)).status_code == 201
    capped = await people._client().post("/api/signup", json=ORG)
    assert capped.status_code == 429 and capped.json()["error"] == "signup_cap"
    # yesterday's sign-ups no longer count
    async with session_scope() as db:
        await db.execute(update(Workspace).where(Workspace.id != 1).values(created_at=utcnow() - timedelta(days=2)))
    assert (await people._client().post("/api/signup", json=ORG)).status_code == 201


async def test_one_address_signs_up_three_times_a_day(owner, people):
    await _open_signup(owner)
    for n in range(3):
        made = await people._client().post("/api/signup", json={**JUST_ME, "username": f"ivy{n}"})
        assert made.status_code == 201, made.text
    refused = await people._client().post("/api/signup", json={**JUST_ME, "username": "ivy9"})
    assert refused.status_code == 429 and "Retry-After" in refused.headers


async def test_a_refused_sign_up_costs_no_attempt(owner, people):
    await _open_signup(owner)
    for _ in range(5):
        assert (await people._client().post("/api/signup", json={**JUST_ME, "password": "short"})).status_code == 422
    assert (await people._client().post("/api/signup", json=JUST_ME)).status_code == 201


async def test_sign_up_waits_for_the_setup(browser):
    answer = await browser.post("/api/signup", json=JUST_ME)
    assert answer.status_code == 409 and answer.json()["error"] == "not_set_up"


async def test_only_the_owner_reads_and_changes_the_server(owner, people):
    await people.member("adam", role="admin")
    adam = await people.signed_in("adam")
    assert (await adam.get("/api/server")).status_code == 403
    assert (await adam.patch("/api/server", json={"signup": True})).status_code == 403
    reader = await people.token(owner, "read")
    assert (await reader.get("/api/server")).status_code == 403
    server = (await owner.get("/api/server")).json()
    assert server == {"signup": False, "signup_daily_cap": 100, "signups_today": 0, "triage_daily_budget": 500,
                      "workspaces": 1, "users": 2}
    assert (await owner.patch("/api/server", json={})).status_code == 422
    assert (await owner.patch("/api/server", json={"signup_daily_cap": -1})).status_code == 422
    assert (await owner.patch("/api/server", json={"colour": "red"})).status_code == 422


async def test_the_1x_token_cannot_change_the_server(client):
    assert (await client.patch("/api/server", json={"signup": True})).status_code == 403


async def test_each_sign_up_is_audited_for_its_workspace_and_for_the_owner(owner, people):
    await _open_signup(owner)
    made = (await people._client().post("/api/signup", json=ORG)).json()
    async with session_scope() as db:
        rows = (await db.execute(select(AuditLog.workspace_id, AuditLog.action, AuditLog.actor))).all()
        olaf = (await db.execute(select(User).where(User.username == "olaf"))).scalar_one()
    assert (made["workspace"]["id"], "workspace.created", "olaf") in rows
    assert (0, "server.signup", "olaf") in rows and (0, "server.updated", "ada") in rows
    assert olaf.workspace_id == made["workspace"]["id"] and not olaf.must_change_password
