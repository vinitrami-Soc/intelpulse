"""Settings: plain values per workspace, secrets only sealed and bound to their place."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.db import session_scope
from app.models import SERVER, Setting, Workspace
from app.platform import settings_store as store
from app.platform.box import server_box
from app.platform.crypto import DecryptError


async def _workspace(name: str) -> int:
    async with session_scope() as db:
        workspace = Workspace(name=name, kind="organization")
        db.add(workspace)
        await db.flush()
        return workspace.id


async def test_a_value_belongs_to_one_workspace(clean_db):
    first, second = await _workspace("A"), await _workspace("B")
    async with session_scope() as db:
        await store.set_value(db, first, "retention_days", 14)
    async with session_scope() as db:
        assert await store.get_value(db, first, "retention_days") == 14
        assert await store.get_value(db, second, "retention_days", 30) == 30
        assert await store.get_value(db, SERVER, "retention_days") is None


async def test_setting_a_value_again_replaces_it(clean_db):
    workspace = await _workspace("A")
    async with session_scope() as db:
        await store.set_value(db, workspace, "retention_days", 14)
        await store.set_value(db, workspace, "retention_days", 60)
    async with session_scope() as db:
        rows = (await db.execute(select(Setting).where(Setting.key == "retention_days"))).scalars().all()
        assert [row.value for row in rows] == [60]


async def test_a_secret_is_stored_only_sealed(clean_db):
    workspace = await _workspace("A")
    async with session_scope() as db:
        await store.set_secret(db, server_box(), workspace, "otx_api_key", "otx-secret-1234")
    async with session_scope() as db:
        row = (await db.execute(select(Setting).where(Setting.key == "otx_api_key"))).scalars().one()
        assert row.value is None
        assert b"otx-secret-1234" not in row.sealed
        assert await store.get_secret(db, server_box(), workspace, "otx_api_key") == "otx-secret-1234"


async def test_a_sealed_secret_moved_to_another_workspace_does_not_open(clean_db):
    first, second = await _workspace("A"), await _workspace("B")
    async with session_scope() as db:
        await store.set_secret(db, server_box(), first, "otx_api_key", "otx-secret-1234")
    async with session_scope() as db:
        row = (await db.execute(select(Setting).where(Setting.key == "otx_api_key"))).scalars().one()
        row.workspace_id = second
    async with session_scope() as db:
        with pytest.raises(DecryptError):
            await store.get_secret(db, server_box(), second, "otx_api_key")


async def test_an_empty_secret_removes_it(clean_db):
    workspace = await _workspace("A")
    async with session_scope() as db:
        await store.set_secret(db, server_box(), workspace, "otx_api_key", "otx-secret-1234")
        await store.set_secret(db, server_box(), workspace, "otx_api_key", "")
    async with session_scope() as db:
        assert await store.get_secret(db, server_box(), workspace, "otx_api_key") is None


def test_a_secret_is_shown_masked():
    assert store.mask(None) is None
    assert store.mask("otx-secret-1234") == "•" * 8 + "1234"
    assert store.mask("short") == "•" * 8
