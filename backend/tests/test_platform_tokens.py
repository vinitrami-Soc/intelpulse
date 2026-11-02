"""API tokens: made by an admin, shown once, scoped, revocable, and with an end date."""
from __future__ import annotations

import importlib
from datetime import timedelta

from sqlalchemy import select, update

from app.db import session_scope
from app.models import ApiToken, utcnow
from app.platform import deps

TRIAGE = {"indicators": ["185.220.101.34"], "title": "token test"}
ALERT = {"source": "dwellwatch", "alert_id": "dw-tok-1", "title": "Ransomware staging",
         "severity": "high", "indicators": ["185.220.101.34"]}


async def test_a_token_is_shown_once_and_stored_only_as_a_hash(people):
    owner = await people.set_up()
    made = (await owner.post("/api/tokens", json={"name": "dwellwatch", "scope": "ingest"})).json()
    assert made["token"].startswith("ipt_") and made["scope"] == "ingest"
    listed = (await owner.get("/api/tokens")).json()
    assert [t["name"] for t in listed] == ["dwellwatch"]
    assert "token" not in listed[0] and made["token"] not in str(listed)
    async with session_scope() as db:
        row = (await db.execute(select(ApiToken))).scalars().one()
    assert made["token"] not in row.token_hash and len(row.token_hash) == 64


async def test_only_a_signed_in_admin_manages_tokens(people, client):
    owner = await people.set_up()
    await people.member("bea", role="analyst")
    bea = await people.signed_in("bea")
    script = await people.token(owner, "read")
    body = {"name": "x", "scope": "read"}
    assert (await bea.post("/api/tokens", json=body)).status_code == 403
    assert (await script.post("/api/tokens", json=body)).status_code == 403
    assert (await client.post("/api/tokens", json=body)).status_code == 403  # the 1.x API_TOKEN
    assert (await client.get("/api/tokens")).status_code == 403


async def test_a_read_token_reads_and_nothing_else(people):
    owner = await people.set_up()
    script = await people.token(owner, "read")
    assert (await script.get("/api/cases")).status_code == 200
    assert (await script.get("/api/stats")).status_code == 200
    assert (await script.post("/api/triage", json=TRIAGE)).status_code == 403
    assert (await script.post("/api/alerts", json=ALERT)).status_code == 403


async def test_a_triage_token_triages_but_changes_nothing_else(people):
    owner = await people.set_up()
    script = await people.token(owner, "triage")
    triaged = await script.post("/api/triage", json=TRIAGE)
    assert triaged.status_code == 200
    assert (await script.post("/api/extract", json={"text": "185.220.101.34"})).status_code == 200
    case_id = triaged.json()["case_id"]
    assert (await script.get(f"/api/cases/{case_id}")).status_code == 200
    assert (await script.delete(f"/api/cases/{case_id}")).status_code == 403
    assert (await script.post("/api/lists", json={"value": "8.8.4.4", "list_type": "block"})).status_code == 403
    assert (await script.post(f"/api/cases/{case_id}/ticket", params={"sink": "jira"})).status_code == 403


async def test_an_ingest_token_only_pushes_alerts(people):
    owner = await people.set_up()
    dwellwatch = await people.token(owner, "ingest", name="dwellwatch")
    pushed = await dwellwatch.post("/api/alerts", json=ALERT)
    assert pushed.status_code == 201
    assert (await dwellwatch.get("/api/cases")).status_code == 403
    assert (await dwellwatch.post("/api/triage", json=TRIAGE)).status_code == 403
    # the case is the owner's workspace's, and the audit log names the token
    assert (await owner.get(f"/api/cases/{pushed.json()['case_id']}")).status_code == 200
    actors = {r["actor"] for r in (await owner.get("/api/audit")).json() if r["action"] == "alert.received"}
    assert actors == {"token:dwellwatch"}


async def test_a_revoked_token_stops_working(people):
    owner = await people.set_up()
    made = (await owner.post("/api/tokens", json={"name": "old", "scope": "read"})).json()
    script = people._client()
    script.headers["Authorization"] = f"Bearer {made['token']}"
    assert (await script.get("/api/cases")).status_code == 200
    assert (await owner.delete(f"/api/tokens/{made['id']}")).status_code == 204
    assert (await script.get("/api/cases")).status_code == 401
    listed = (await owner.get("/api/tokens")).json()
    assert listed[0]["revoked_at"] is not None and listed[0]["last_used_at"] is not None


async def test_an_expired_token_stops_working(people):
    owner = await people.set_up()
    made = (await owner.post("/api/tokens", json={"name": "week", "scope": "read", "expires_in_days": 7})).json()
    assert made["expires_at"] is not None
    script = people._client()
    script.headers["Authorization"] = f"Bearer {made['token']}"
    assert (await script.get("/api/cases")).status_code == 200
    async with session_scope() as db:
        await db.execute(update(ApiToken).values(expires_at=utcnow() - timedelta(seconds=1)))
    assert (await script.get("/api/cases")).status_code == 401


async def test_a_token_needs_a_known_scope_and_a_name(people):
    owner = await people.set_up()
    assert (await owner.post("/api/tokens", json={"name": "x", "scope": "admin"})).status_code == 422
    assert (await owner.post("/api/tokens", json={"name": "   ", "scope": "read"})).status_code == 422


def test_the_scoped_endpoints_exist():
    """The scope lists name endpoint functions: a rename must fail here, not quietly lock tokens out."""
    for name in deps.TRIAGE_WRITES | deps.INGEST_WRITES:
        module, _, function = name.rpartition(".")
        assert callable(getattr(importlib.import_module(module), function, None)), name
