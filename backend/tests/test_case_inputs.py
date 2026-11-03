"""Tier 1 (spec 6.3): a case's input is sealed in case_inputs, bound to its case, read by whom it
should be, named by its SHA-256, and moved there from 1.x rows by migration 0007."""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy import delete, select, update

from app.db import alembic_config, session_scope
from app.models import Case, CaseInput, PushedAlert, User, utcnow
from app.platform.box import server_box
from app.platform.crypto import DecryptError
from app.services import case_inputs

PASTE = "Sep 18 02:14:11 fw-edge-01 kernel: [UFW BLOCK] SRC=185.220.101.34 DST=10.20.4.15 DPT=445"
ALERT = {
    "source": "dwellwatch", "alert_id": "DW-1", "title": "Ransomware staging", "severity": "high",
    "description": "Shadow copies deleted on LON-WS-0442 by svc_backup",
    "entities": [{"kind": "host", "name": "LON-WS-0442"}],
    "evidence": [{"label": "vssadmin", "text": "vssadmin delete shadows /all /quiet from 185.220.101.34"},
                 {"label": "beacon", "text": "outbound 443 to 185.220.101.35"}],
}


@pytest.fixture
async def team(people):
    """(ada the owner, bea an analyst, cal another analyst), all in Acme SOC."""
    ada = await people.set_up("ada", "Acme SOC")
    for name in ("bea", "cal"):
        await people.member(name)
    return ada, await people.signed_in("bea"), await people.signed_in("cal")


async def _triage(client, title="Perimeter") -> str:
    answer = await client.post("/api/triage", json={"text": PASTE, "title": title})
    assert answer.status_code == 200, answer.text
    return answer.json()["case_id"]


async def test_a_paste_is_sealed_apart_from_the_case(team):
    _ada, bea, _cal = team
    case_id = await _triage(bea)
    async with session_scope() as db:
        row = await db.get(CaseInput, case_id)
        columns = [c["name"] for c in await db.run_sync(lambda s: sa.inspect(s.connection()).get_columns("cases"))]
    assert row is not None and PASTE.encode() not in row.sealed and b"185.220" not in row.sealed
    plain = server_box().open(row.sealed, case_inputs.bound_to(case_id))
    assert json.loads(plain) == {"raw_input": PASTE}
    assert row.sha256 == hashlib.sha256(plain).hexdigest()
    assert "raw_input" not in columns


async def test_the_paste_is_read_by_its_analyst_and_an_admin_only(team, people):
    ada, bea, cal = team
    case_id = await _triage(bea)
    assert (await bea.get(f"/api/cases/{case_id}")).json()["raw_input"] == PASTE
    assert (await ada.get(f"/api/cases/{case_id}")).json()["raw_input"] == PASTE
    seen = (await cal.get(f"/api/cases/{case_id}")).json()
    assert seen["raw_input"] is None and seen["verdict"] and seen["indicators"]   # the rest of the case is theirs too
    reader = await people.token(ada, "read")
    assert (await reader.get(f"/api/cases/{case_id}")).json()["raw_input"] == PASTE


async def test_a_pushed_alert_keeps_its_text_sealed_and_shows_it_to_the_team(team):
    ada, _bea, cal = team
    answer = await ada.post("/api/alerts", json=ALERT)
    assert answer.status_code == 201, answer.text
    case_id = answer.json()["case_id"]
    async with session_scope() as db:
        stored = (await db.execute(select(PushedAlert).where(PushedAlert.case_id == case_id))).scalar_one().payload
        sealed = (await db.get(CaseInput, case_id)).sealed
    assert "description" not in stored and all("text" not in item for item in stored["evidence"])
    assert [item["label"] for item in stored["evidence"]] == ["vssadmin", "beacon"]   # tier 2 stays
    assert b"vssadmin delete" not in sealed
    # the analyst working the case sees what the alert said
    alert = (await cal.get(f"/api/cases/{case_id}")).json()["alert"]
    assert alert["description"] == ALERT["description"]
    assert [item["text"] for item in alert["evidence"]] == [item["text"] for item in ALERT["evidence"]]
    report = (await cal.get(f"/api/cases/{case_id}/report")).text
    assert "Shadow copies deleted" in report and "vssadmin delete shadows" in report


async def test_a_sealed_input_opens_only_for_its_own_case(team):
    _ada, bea, _cal = team
    first, second = await _triage(bea, "one"), await _triage(bea, "two")
    async with session_scope() as db:
        sealed = (await db.get(CaseInput, first)).sealed
    with pytest.raises(DecryptError):
        server_box().open(sealed, case_inputs.bound_to(second))


async def test_a_report_says_when_the_input_was_deleted(team):
    ada, _bea, _cal = team
    case_id = (await ada.post("/api/alerts", json=ALERT)).json()["case_id"]
    async with session_scope() as db:   # what the retention sweep will do
        await db.execute(delete(CaseInput).where(CaseInput.case_id == case_id))
        await db.execute(update(Case).where(Case.id == case_id).values(input_deleted_at=datetime(2026, 10, 1, tzinfo=UTC)))
    report = (await ada.get(f"/api/cases/{case_id}/report")).text
    assert "deleted on 2026-10-01 under the retention policy" in report
    assert "vssadmin delete shadows" not in report and "Shadow copies deleted" not in report
    as_json = (await ada.get(f"/api/cases/{case_id}/report", params={"fmt": "json"})).json()
    assert as_json["input_deleted_at"] == "2026-10-01"
    case = (await ada.get(f"/api/cases/{case_id}")).json()
    assert case["raw_input"] is None and case["input_deleted_at"].startswith("2026-10-01")


async def test_deleting_a_case_deletes_its_input(team):
    ada, bea, _cal = team
    case_id = await _triage(bea)
    assert (await ada.delete(f"/api/cases/{case_id}")).status_code == 204
    async with session_scope() as db:
        assert await db.get(CaseInput, case_id) is None


async def test_a_case_with_no_input_stores_none(team):
    ada, _bea, _cal = team
    answer = await ada.post("/api/triage", json={"indicators": ["185.220.101.34"], "title": "No paste"})
    async with session_scope() as db:
        assert await db.get(CaseInput, answer.json()["case_id"]) is None


# -- migration 0007 ------------------------------------------------------------------
CASES_0006 = sa.table(
    "cases", *(sa.column(n) for n in ("id", "workspace_id", "title", "source", "verdict", "max_score",
                                      "indicator_count", "duration_ms", "created_at", "status", "raw_input")))
ALERTS_0006 = sa.table("pushed_alerts", *(sa.column(n) for n in ("workspace_id", "case_id", "source", "alert_id",
                                                                 "severity", "payload", "received_at")))


def test_migration_0007_seals_what_was_there_and_0006_gets_it_back(tmp_path):
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'tier1.db'}")
    now = datetime(2026, 9, 1, tzinfo=UTC)
    with engine.begin() as conn:
        command.upgrade(alembic_config(conn), "0006")
        for case_id, raw in (("c-paste", PASTE), ("c-alert", "joined evidence"), ("c-empty", None)):
            conn.execute(CASES_0006.insert().values(id=case_id, workspace_id=1, title=case_id, source="api",
                                                    verdict="high", max_score=70, indicator_count=1, duration_ms=5,
                                                    created_at=now, status="new", raw_input=raw))
        conn.execute(ALERTS_0006.insert().values(
            workspace_id=1, case_id="c-alert", source="dwellwatch", alert_id="DW-1", severity="high", received_at=now,
            payload=json.dumps({**ALERT, "ticket": None})))
        command.upgrade(alembic_config(conn), "head")

    with engine.connect() as conn:
        rows = {r.case_id: r for r in conn.execute(sa.text("SELECT case_id, sealed, sha256 FROM case_inputs"))}
        payload = json.loads(conn.execute(sa.text("SELECT payload FROM pushed_alerts")).scalar_one())
        columns = [c["name"] for c in sa.inspect(conn).get_columns("cases")]
    assert set(rows) == {"c-paste", "c-alert"} and "raw_input" not in columns and "input_deleted_at" in columns
    paste = json.loads(server_box().open(rows["c-paste"].sealed, case_inputs.bound_to("c-paste")))
    assert paste == {"raw_input": PASTE}
    alert = json.loads(server_box().open(rows["c-alert"].sealed, case_inputs.bound_to("c-alert")))
    assert alert["alert"]["description"] == ALERT["description"]
    assert alert["alert"]["evidence"] == [item["text"] for item in ALERT["evidence"]]
    assert "description" not in payload and all("text" not in item for item in payload["evidence"])

    with engine.begin() as conn:
        command.downgrade(alembic_config(conn), "0006")
    with engine.connect() as conn:
        back = dict(conn.execute(sa.text("SELECT id, raw_input FROM cases")).all())
        payload = json.loads(conn.execute(sa.text("SELECT payload FROM pushed_alerts")).scalar_one())
    assert back == {"c-paste": PASTE, "c-alert": "joined evidence", "c-empty": None}
    assert payload["description"] == ALERT["description"]
    assert [item["text"] for item in payload["evidence"]] == [item["text"] for item in ALERT["evidence"]]


async def test_who_created_a_case_is_who_reads_its_paste(team):
    _ada, bea, _cal = team
    case_id = await _triage(bea)
    async with session_scope() as db:
        bea_id = (await db.execute(select(User.id).where(User.username == "bea"))).scalar_one()
        assert (await db.get(Case, case_id)).created_by == bea_id
    assert utcnow()   # the clock the sweep will read
