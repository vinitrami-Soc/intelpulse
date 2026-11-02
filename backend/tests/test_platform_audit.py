"""The audit log is a hash chain: any change, removal, reordering or cut is reported."""
from __future__ import annotations

from sqlalchemy import delete, select, update

from app.db import session_scope
from app.models import DEFAULT_WORKSPACE_ID, SERVER, AuditHead, AuditLog
from app.platform import audit


async def _three_records() -> list[int]:
    async with session_scope() as db:
        ids = []
        for n in range(3):
            entry = await audit.record(db, action=f"test.{n}", actor="tester",
                                       workspace_id=DEFAULT_WORKSPACE_ID, target=f"t{n}", detail={"n": n})
            ids.append(entry.id)
        return ids


async def _problems() -> list[str]:
    async with session_scope() as db:
        return await audit.verify(db)


async def test_an_untouched_log_verifies(clean_db):
    await _three_records()
    assert await _problems() == []


async def test_an_empty_log_verifies(clean_db):
    assert await _problems() == []


async def test_each_record_follows_the_one_before(clean_db):
    ids = await _three_records()
    async with session_scope() as db:
        rows = (await db.execute(select(AuditLog).order_by(AuditLog.id))).scalars().all()
        head = (await db.execute(select(AuditHead))).scalars().one()
    assert [row.id for row in rows] == ids
    assert rows[0].prev_hash == audit.GENESIS
    assert rows[1].prev_hash == rows[0].hash and rows[2].prev_hash == rows[1].hash
    assert (head.hash, head.count) == (rows[2].hash, 3)


async def test_an_edited_record_is_reported(clean_db):
    ids = await _three_records()
    async with session_scope() as db:
        await db.execute(update(AuditLog).where(AuditLog.id == ids[1]).values(actor="someone else"))
    assert f"record {ids[1]} was changed" in await _problems()


async def test_a_removed_record_is_reported(clean_db):
    ids = await _three_records()
    async with session_scope() as db:
        await db.execute(delete(AuditLog).where(AuditLog.id == ids[1]))
    assert f"record {ids[2]} does not follow the one before it" in await _problems()


async def test_a_log_cut_off_at_the_end_is_reported(clean_db):
    ids = await _three_records()
    async with session_scope() as db:
        await db.execute(delete(AuditLog).where(AuditLog.id == ids[2]))
    assert any("newest records are missing" in problem for problem in await _problems())


async def test_a_server_record_belongs_to_no_workspace(clean_db):
    async with session_scope() as db:
        entry = await audit.record(db, action="feed.refresh.requested", actor="owner",
                                   workspace_id=SERVER, target="kev")
    assert entry.workspace_id == SERVER
    assert await _problems() == []


async def test_a_triage_through_the_api_keeps_the_chain(client):
    response = await client.post("/api/triage", json={"indicators": ["185.220.101.34"], "title": "chain"})
    assert response.status_code == 200
    async with session_scope() as db:
        actions = (await db.execute(select(AuditLog.action))).scalars().all()
    assert "triage.completed" in actions
    assert await _problems() == []
