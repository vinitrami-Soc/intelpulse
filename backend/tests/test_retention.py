"""Retention, hold and both deletes (spec 6.5), with a fake clock: `sweep(now=...)`.

M3's done-when: a case past retention loses its input and keeps its verdict and
indicators; a held case keeps both.
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db import session_scope
from app.models import AuditLog, Case, CaseInput, IndicatorResult, utcnow
from app.services import retention

PASTE = "Sep 18 02:14:11 fw-edge-01 kernel: [UFW BLOCK] SRC=185.220.101.34 DST=10.20.4.15 DPT=445"


@pytest.fixture
async def team(people):
    """(ada the owner, bea an analyst, cal another analyst), all in Acme SOC."""
    ada = await people.set_up("ada", "Acme SOC")
    for name in ("bea", "cal"):
        await people.member(name)
    return ada, await people.signed_in("bea"), await people.signed_in("cal")


async def _case(client, title="Perimeter") -> str:
    answer = await client.post("/api/triage", json={"text": PASTE, "title": title})
    assert answer.status_code == 200, answer.text
    return answer.json()["case_id"]


async def _sweep(days_later: int) -> dict[int, int]:
    async with session_scope() as db:
        return await retention.sweep(db, now=utcnow() + timedelta(days=days_later))


async def _has_input(case_id: str) -> bool:
    async with session_scope() as db:
        return await db.get(CaseInput, case_id) is not None


async def test_a_case_past_retention_loses_its_input_and_keeps_its_verdict(team):
    ada, bea, _cal = team
    case_id = await _case(bea)
    before = (await ada.get(f"/api/cases/{case_id}")).json()
    assert await _sweep(29) == {} and await _has_input(case_id)       # 30 days by default: not yet
    assert await _sweep(31) == {1: 1}
    assert not await _has_input(case_id)
    after = (await ada.get(f"/api/cases/{case_id}")).json()
    assert after["raw_input"] is None and after["input_deleted_at"]
    assert after["verdict"] == before["verdict"] and after["score"] == before["score"]
    assert after["indicators"] == before["indicators"] and after["title"] == before["title"]
    async with session_scope() as db:
        assert (await db.execute(select(IndicatorResult).where(IndicatorResult.case_id == case_id))).scalars().all()


async def test_a_held_case_keeps_both(team):
    ada, bea, _cal = team
    case_id = await _case(bea)
    held = await ada.post(f"/api/cases/{case_id}/hold")
    assert held.status_code == 200 and held.json()["held"] is True
    assert await _sweep(400) == {}
    case = (await ada.get(f"/api/cases/{case_id}")).json()
    assert case["raw_input"] == PASTE and case["held"] is True and case["input_deleted_at"] is None
    # released, the next sweep takes it
    assert (await ada.delete(f"/api/cases/{case_id}/hold")).json()["held"] is False
    assert await _sweep(400) == {1: 1}


async def test_each_workspace_keeps_its_own_days(team, people):
    ada, bea, _cal = team
    assert (await ada.patch("/api/settings", json={"retention_days": 7})).status_code == 200
    mine = await _case(bea)
    other = await people.workspace("Other SOC")
    await people.member("olga", role="admin", workspace_id=other)
    olga = await people.signed_in("olga")
    theirs = await _case(olga)
    assert await _sweep(8) == {1: 1}
    assert not await _has_input(mine) and await _has_input(theirs)   # Other SOC keeps 30 days
    assert await _sweep(31) == {other: 1}


async def test_the_sweep_writes_one_record_per_workspace_and_no_inputs(team):
    _ada, bea, _cal = team
    for n in range(3):
        await _case(bea, f"case {n}")
    await _sweep(31)
    async with session_scope() as db:
        rows = (await db.execute(select(AuditLog).where(AuditLog.action == "retention.swept"))).scalars().all()
    assert len(rows) == 1 and rows[0].detail == {"inputs_deleted": 3, "retention_days": 30}
    assert rows[0].actor == "retention-sweep" and PASTE not in str(rows[0].detail)
    assert await _sweep(32) == {}   # nothing left to sweep, nothing recorded
    async with session_scope() as db:
        assert len((await db.execute(select(AuditLog).where(AuditLog.action == "retention.swept"))).all()) == 1


async def test_a_report_after_the_sweep_says_so(team):
    ada, _bea, _cal = team
    case_id = (await ada.post("/api/alerts", json={
        "source": "dwellwatch", "alert_id": "DW-9", "title": "Staging", "description": "vssadmin delete shadows",
        "evidence": [{"label": "vss", "text": "vssadmin delete shadows /all"}]})).json()["case_id"]
    await _sweep(31)
    report = (await ada.get(f"/api/cases/{case_id}/report")).text
    assert "under the retention policy" in report and "vssadmin" not in report


async def test_an_analyst_deletes_their_own_case_s_input_now(team):
    ada, bea, cal = team
    mine, other = await _case(bea, "bea's"), await _case(cal, "cal's")
    assert (await bea.delete(f"/api/cases/{other}/input")).status_code == 403
    assert (await bea.delete(f"/api/cases/{mine}/input")).status_code == 204
    assert not await _has_input(mine) and await _has_input(other)
    assert (await bea.delete(f"/api/cases/{mine}/input")).status_code == 404   # nothing left
    assert (await ada.delete(f"/api/cases/{other}/input")).status_code == 204  # an admin, any
    case = (await bea.get(f"/api/cases/{mine}")).json()
    assert case["input_deleted_at"] and case["verdict"]
    async with session_scope() as db:
        record = (await db.execute(select(AuditLog).where(AuditLog.action == "case.input_deleted")
                                   .order_by(AuditLog.id))).scalars().first()
    assert record.target == mine and len(record.detail["input_sha256"]) == 64


async def test_a_held_case_s_input_is_not_deleted_by_hand_either(team):
    ada, bea, _cal = team
    case_id = await _case(bea)
    await ada.post(f"/api/cases/{case_id}/hold")
    refused = await bea.delete(f"/api/cases/{case_id}/input")
    assert refused.status_code == 409 and refused.json()["error"] == "held"


async def test_only_an_admin_holds_and_releases(team, people):
    ada, bea, _cal = team
    case_id = await _case(bea)
    assert (await bea.post(f"/api/cases/{case_id}/hold")).status_code == 403
    token = await people.token(ada, "triage")
    assert (await token.post(f"/api/cases/{case_id}/hold")).status_code == 403
    assert (await token.delete(f"/api/cases/{case_id}/input")).status_code == 403
    await ada.post(f"/api/cases/{case_id}/hold")
    await ada.delete(f"/api/cases/{case_id}/hold")
    async with session_scope() as db:
        actions = (await db.execute(select(AuditLog.action).where(AuditLog.target == case_id))).scalars().all()
    assert "case.held" in actions and "case.released" in actions


async def test_another_workspace_s_case_is_not_there(team, people):
    _ada, bea, _cal = team
    case_id = await _case(bea)
    other = await people.workspace("Other SOC")
    await people.member("olga", role="admin", workspace_id=other)
    olga = await people.signed_in("olga")
    assert (await olga.post(f"/api/cases/{case_id}/hold")).status_code == 404
    assert (await olga.delete(f"/api/cases/{case_id}/input")).status_code == 404


async def test_deleting_completely_keeps_the_case_s_name_and_input_hash(team):
    ada, bea, _cal = team
    case_id = await _case(bea)
    async with session_scope() as db:
        digest = (await db.get(CaseInput, case_id)).sha256
    assert (await ada.delete(f"/api/cases/{case_id}")).status_code == 204
    async with session_scope() as db:
        assert await db.get(Case, case_id) is None and await db.get(CaseInput, case_id) is None
        record = (await db.execute(select(AuditLog).where(AuditLog.action == "case.deleted"))).scalars().one()
    assert record.target == case_id and record.detail == {"input_sha256": digest}


async def test_the_history_says_which_cases_are_held_or_swept(team):
    ada, bea, _cal = team
    kept, swept = await _case(bea, "kept"), await _case(bea, "swept")
    await ada.post(f"/api/cases/{kept}/hold")
    await _sweep(31)
    rows = {row["id"]: row for row in (await ada.get("/api/cases")).json()}
    assert rows[kept]["held"] is True and rows[kept]["input_deleted_at"] is None
    assert rows[swept]["held"] is False and rows[swept]["input_deleted_at"]
    assert rows[swept]["created_by"] == rows[kept]["created_by"] is not None


async def test_the_sweep_runs_hourly_and_from_the_terminal(team, capsys):
    from app import cli
    from app.tasks import celery_app

    job = celery_app.conf.beat_schedule["retention-hourly"]
    assert job["task"] == "intelpulse.retention_sweep"
    await cli._sweep(None)
    assert "0 case input(s) past retention deleted" in capsys.readouterr().out
