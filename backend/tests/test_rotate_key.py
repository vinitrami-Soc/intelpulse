"""Rotating ENCRYPTION_KEY (spec 6.4): `rotate-key` opens every sealed value with the old key and
seals it with the new one, all or nothing, and the server started on the new key reads it all."""
from __future__ import annotations

import argparse

import pytest
from pydantic import SecretStr
from sqlalchemy import select, update

from app import cli
from app.config import settings
from app.db import session_scope
from app.models import SERVER, AuditLog, CaseInput, Setting
from app.platform import audit, rotation
from app.platform import settings_store as store
from app.platform.box import server_box
from app.platform.crypto import Box, DecryptError, new_key
from app.services import case_inputs
from tests.test_case_inputs import PASTE

OTX_KEY = "otx-key-for-acme-1234"
NEW = new_key()


@pytest.fixture
async def sealed(people):
    """Acme with a provider key and one triaged paste: (ada, the case's id)."""
    ada = await people.set_up("ada", "Acme SOC")
    assert (await ada.patch("/api/settings", json={"keys": {"otx": OTX_KEY}})).status_code == 200
    made = await ada.post("/api/triage", json={"text": PASTE, "title": "Perimeter"})
    assert made.status_code == 200, made.text
    return ada, made.json()["case_id"]


@pytest.fixture
def started_on(monkeypatch):
    """Restart the server on another key: server_box() is built once, so clear it both ways."""
    def restart(key: str) -> None:
        monkeypatch.setattr(settings, "encryption_key", SecretStr(key))
        server_box.cache_clear()
    yield restart
    monkeypatch.undo()
    server_box.cache_clear()


async def _rotate(old: Box, new: Box) -> dict[str, int]:
    async with session_scope() as db:
        return await rotation.rotate(db, old, new)


async def test_everything_sealed_opens_with_the_new_key_and_not_the_old(sealed):
    _, case_id = sealed
    old, new = server_box(), Box.from_b64(NEW)
    counts = await _rotate(old, new)
    async with session_scope() as db:
        settings_rows = (await db.execute(select(Setting).where(Setting.sealed.is_not(None)))).scalars().all()
        inputs = (await db.execute(select(CaseInput))).scalars().all()
    assert counts == {"settings": len(settings_rows), "case_inputs": 1} and counts["settings"] >= 1
    for row in settings_rows:
        bound = f"settings:{row.workspace_id}:{row.key}"
        new.open(row.sealed, bound)
        with pytest.raises(DecryptError):
            old.open(row.sealed, bound)
    (row,) = inputs
    assert PASTE in new.open(row.sealed, case_inputs.bound_to(case_id)).decode()
    with pytest.raises(DecryptError):
        old.open(row.sealed, case_inputs.bound_to(case_id))


async def test_the_server_started_on_the_new_key_reads_it_all(sealed, started_on):
    ada, case_id = sealed
    await _rotate(server_box(), Box.from_b64(NEW))
    started_on(NEW)
    assert (await ada.get(f"/api/cases/{case_id}")).json()["raw_input"].startswith("Sep 18")
    async with session_scope() as db:
        assert await store.get_secret(db, server_box(), 1, "provider_key:otx") == OTX_KEY


async def test_the_rotation_is_audited_with_its_counts(sealed):
    await _rotate(server_box(), Box.from_b64(NEW))
    async with session_scope() as db:
        (row,) = (await db.execute(select(AuditLog).where(AuditLog.action == "server.key_rotated"))).scalars().all()
        assert row.workspace_id == SERVER and row.actor == "rotate-key"
        assert row.detail["case_inputs"] == 1
        assert await audit.verify(db) == []


async def test_a_value_the_old_key_does_not_open_changes_nothing(sealed):
    _, case_id = sealed
    old, new = server_box(), Box.from_b64(NEW)
    async with session_scope() as db:
        before = {row.key: row.sealed for row in (await db.execute(select(Setting))).scalars() if row.sealed}
        await db.execute(update(CaseInput).values(sealed=Box.from_b64(new_key()).seal(b"{}", "elsewhere")))
    with pytest.raises(rotation.RotationError, match=f"case {case_id}"):
        await _rotate(old, new)
    async with session_scope() as db:
        after = {row.key: row.sealed for row in (await db.execute(select(Setting))).scalars() if row.sealed}
        assert after == before                       # the settings sealed first were rolled back
        assert not (await db.execute(select(AuditLog).where(AuditLog.action == "server.key_rotated"))).first()


async def test_the_current_key_is_not_a_new_one(sealed):
    with pytest.raises(rotation.RotationError, match="current key"):
        await _rotate(server_box(), server_box())


async def test_the_terminal_reads_the_new_key_from_the_environment(sealed, monkeypatch, capsys):
    monkeypatch.setenv("NEW_ENCRYPTION_KEY", NEW)
    await cli._rotate_key(argparse.Namespace(new_key_file=None))
    out = capsys.readouterr().out
    assert "1 case input(s) are sealed with the new key" in out and "Set ENCRYPTION_KEY" in out
    async with session_scope() as db:
        row = (await db.execute(select(CaseInput))).scalars().one()
    Box.from_b64(NEW).open(row.sealed, case_inputs.bound_to(row.case_id))


async def test_the_terminal_reads_the_new_key_from_a_file(sealed, monkeypatch, tmp_path, capsys):
    monkeypatch.delenv("NEW_ENCRYPTION_KEY", raising=False)
    key_file = tmp_path / "new.key"
    key_file.write_text(NEW + "\n", encoding="ascii")
    await cli._rotate_key(argparse.Namespace(new_key_file=str(key_file)))
    assert "sealed with the new key" in capsys.readouterr().out


@pytest.mark.parametrize("given, said", [
    ({}, "set NEW_ENCRYPTION_KEY"),
    ({"env": "not a key"}, "not usable"),
    ({"file": "/nowhere/new.key"}, "could not be read"),
])
async def test_the_terminal_refuses_without_a_usable_key(sealed, monkeypatch, capsys, given, said):
    monkeypatch.delenv("NEW_ENCRYPTION_KEY", raising=False)
    if "env" in given:
        monkeypatch.setenv("NEW_ENCRYPTION_KEY", given["env"])
    with pytest.raises(SystemExit) as stopped:
        await cli._rotate_key(argparse.Namespace(new_key_file=given.get("file")))
    assert stopped.value.code == 2 and said in capsys.readouterr().err


async def test_the_terminal_says_why_a_rotation_stopped(sealed, monkeypatch, capsys):
    async with session_scope() as db:
        await db.execute(update(CaseInput).values(sealed=b"IPB1" + b"\x00" * 40))
    monkeypatch.setenv("NEW_ENCRYPTION_KEY", NEW)
    with pytest.raises(SystemExit) as stopped:
        await cli._rotate_key(argparse.Namespace(new_key_file=None))
    assert stopped.value.code == 1 and "nothing was changed" in capsys.readouterr().err

