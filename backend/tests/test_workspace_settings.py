"""Workspace settings: each workspace's own provider keys, switches, cache and retention."""
from __future__ import annotations

import pytest
from sqlalchemy import select

from app.config import settings
from app.db import session_scope
from app.enrichment import PROVIDERS, credentials
from app.enrichment.base import STATUS_OK, Provider, Signal
from app.ioc import Indicator
from app.models import DEFAULT_WORKSPACE_ID, AuditLog, Setting
from app.platform.box import server_box
from app.services import workspace_settings as ws_settings

OTX_KEY = "otx-key-for-acme-1234"


class SpyProvider(Provider):
    """A keyed provider that answers instantly and remembers which key each call carried."""

    name = "spy"
    label = "Spy"
    supported_types = {"ip"}
    requires_key = True
    key_slot = "otx"
    cacheable = True

    def __init__(self) -> None:
        self.keys_seen: list[str | None] = []

    async def fetch(self, client, indicator: Indicator):
        self.keys_seen.append(self.key())
        return self._result(indicator, status=STATUS_OK, signals=[Signal("spy", 0.5, "stub")])


@pytest.fixture
async def spy(monkeypatch):
    from app.cache import cache

    provider = SpyProvider()
    for registry in ("app.services.triage.PROVIDERS", "app.services.workspace_settings.PROVIDERS",
                     "app.routers.settings.PROVIDERS"):
        monkeypatch.setattr(registry, [provider])
    await cache.invalidate("")
    yield provider
    await cache.invalidate("")


@pytest.fixture
async def two(people):
    """(ada, admin of Acme SOC, and bob, admin of Globex SOC)."""
    ada = await people.set_up("ada", "Acme SOC")
    other = await people.workspace("Globex SOC")
    await people.member("bob", role="admin", workspace_id=other)
    return ada, await people.signed_in("bob")


def sources(body: dict) -> dict[str, dict]:
    return {s["provider"]: s for s in body["indicators"][0]["sources"]}


TRIAGE = {"indicators": ["185.220.101.34"], "title": "settings"}


# -- who sees and changes settings ---------------------------------------------------
async def test_only_a_signed_in_admin_reads_or_changes_settings(people, client):
    ada = await people.set_up()
    await people.member("bea", role="analyst")
    bea = await people.signed_in("bea")
    script = await people.token(ada, "read")
    assert (await ada.get("/api/settings")).status_code == 200
    for caller in (bea, script, client):
        assert (await caller.get("/api/settings")).status_code == 403
        assert (await caller.patch("/api/settings", json={"retention_days": 7})).status_code == 403


async def test_a_key_goes_in_sealed_and_never_comes_back(people):
    ada = await people.set_up()
    answer = await ada.patch("/api/settings", json={"keys": {"otx": OTX_KEY}})
    assert answer.status_code == 200, answer.text
    assert OTX_KEY not in answer.text
    assert answer.json()["keys"]["otx"] == {**answer.json()["keys"]["otx"], "set": True, "hint": "•" * 8 + "1234"}
    assert OTX_KEY not in (await ada.get("/api/settings")).text
    async with session_scope() as db:
        row = (await db.execute(select(Setting).where(Setting.key == "provider_key:otx"))).scalars().one()
        audit_text = str([r.detail for r in (await db.execute(select(AuditLog))).scalars()])
    assert row.value is None and OTX_KEY.encode() not in row.sealed
    assert OTX_KEY not in audit_text and "'otx': 'set'" in audit_text


async def test_a_key_is_replaced_or_removed_and_each_is_audited(people):
    ada = await people.set_up()
    await ada.patch("/api/settings", json={"keys": {"otx": OTX_KEY}})
    await ada.patch("/api/settings", json={"keys": {"otx": OTX_KEY + "9"}})
    removed = (await ada.patch("/api/settings", json={"keys": {"otx": ""}})).json()
    assert removed["keys"]["otx"]["set"] is False
    actions = [r["detail"]["keys"]["otx"] for r in (await ada.get("/api/audit")).json() if r["action"] == "settings.updated"]
    assert actions == ["removed", "replaced", "set"]


@pytest.mark.parametrize("body", [
    {"keys": {"otx": "two words"}}, {"keys": {"otx": "line\r\nX-Injected: 1"}}, {"keys": {"otx": "x" * 513}},
    {"keys": {"virustotal": "abc"}}, {"retention_days": 0}, {"retention_days": 366},
    {"providers": {"otx": {"enabled": "maybe"}}}, {"colour": "red"},
])
async def test_settings_that_cannot_be(people, body):
    ada = await people.set_up()
    assert (await ada.patch("/api/settings", json=body)).status_code == 422


async def test_an_unknown_provider_is_404(people):
    ada = await people.set_up()
    assert (await ada.patch("/api/settings", json={"providers": {"nope": {"enabled": False}}})).status_code == 404
    assert (await ada.post("/api/settings/providers/nope/test")).status_code == 404


async def test_retention_days_are_kept(people):
    ada = await people.set_up()
    assert (await ada.get("/api/settings")).json()["retention_days"] == 30
    assert (await ada.patch("/api/settings", json={"retention_days": 14})).json()["retention_days"] == 14
    assert (await ada.get("/api/workspace")).json()["retention_days"] == 14


# -- the keys a lookup spends ----------------------------------------------------------
async def test_a_lookup_spends_only_its_own_workspaces_key(two, spy):
    ada, bob = two
    await ada.patch("/api/settings", json={"keys": {"otx": OTX_KEY}})
    acme = await ada.post("/api/triage", json=TRIAGE)
    globex = await bob.post("/api/triage", json=TRIAGE)
    assert spy.keys_seen == [OTX_KEY]                       # Globex never reached the provider
    assert sources(acme.json())["spy"]["status"] == "ok"
    assert sources(globex.json())["spy"]["status"] == "skipped"
    assert "not configured" in sources(globex.json())["spy"]["error"]


async def test_a_cached_answer_belongs_to_the_workspace_that_asked(two, spy):
    ada, bob = two
    await ada.patch("/api/settings", json={"keys": {"otx": OTX_KEY}})
    await bob.patch("/api/settings", json={"keys": {"otx": "otx-key-for-globex-5678"}})
    first = await ada.post("/api/triage", json=TRIAGE)
    theirs = await bob.post("/api/triage", json=TRIAGE)
    again = await ada.post("/api/triage", json=TRIAGE)
    assert spy.keys_seen == [OTX_KEY, "otx-key-for-globex-5678"]   # Globex paid for its own lookup
    assert sources(first.json())["spy"]["cached"] is False
    assert sources(theirs.json())["spy"]["cached"] is False       # nothing says Acme asked first
    assert sources(again.json())["spy"]["cached"] is True


async def test_a_provider_turned_off_is_skipped_before_any_request(two, spy):
    ada, bob = two
    answer = await ada.patch("/api/settings", json={"keys": {"otx": OTX_KEY}, "providers": {"spy": {"enabled": False}}})
    assert answer.status_code == 200, answer.text
    body = (await ada.post("/api/triage", json=TRIAGE)).json()
    assert (await bob.post("/api/triage", json=TRIAGE)).status_code == 200   # Globex's switch is its own
    assert spy.keys_seen == []
    assert sources(body)["spy"]["status"] == "skipped" and "turned off" in sources(body)["spy"]["error"]


async def test_a_real_provider_can_be_turned_off(people):
    ada = await people.set_up()
    answer = await ada.patch("/api/settings", json={"providers": {"threatfox": {"enabled": False}}})
    assert answer.status_code == 200
    states = {p["name"]: p for p in (await ada.get("/api/workspace")).json()["providers"]}
    assert states["threatfox"]["enabled"] is False and states["threatfox"]["ready"] is False
    assert states["urlhaus"]["enabled"] is True


async def test_outside_a_workspace_there_are_no_keys():
    otx = next(p for p in PROVIDERS if p.name == "otx")
    assert otx.key() is None and otx.configured() is False
    with credentials.using(credentials.Credentials(workspace_id=7, keys={"otx": OTX_KEY})):
        assert otx.key() == OTX_KEY and otx.configured() is True
        assert otx.cache_name() == "otx@7"
    assert otx.key() is None


# -- the one-time move from the environment -----------------------------------------------
async def test_1x_keys_move_from_the_environment_once(clean_db, monkeypatch):
    monkeypatch.setattr(settings, "otx_api_key", "otx-from-the-environment")
    monkeypatch.setattr(settings, "abusech_auth_key", "abusech-from-the-environment")
    async with session_scope() as db:
        assert sorted(await ws_settings.import_env_keys(db, server_box())) == ["abusech", "otx"]
    monkeypatch.setattr(settings, "otx_api_key", "a-later-environment-value")
    async with session_scope() as db:
        assert await ws_settings.import_env_keys(db, server_box()) == []
        creds = await ws_settings.credentials_for(db, server_box(), DEFAULT_WORKSPACE_ID)
        actions = [r.action for r in (await db.execute(select(AuditLog))).scalars()]
    assert creds.keys == {"otx": "otx-from-the-environment", "abusech": "abusech-from-the-environment"}
    assert actions == ["settings.keys_imported"]


async def test_an_upgrade_without_keys_imports_nothing(clean_db):
    async with session_scope() as db:
        assert await ws_settings.import_env_keys(db, server_box()) == []
        assert (await ws_settings.credentials_for(db, server_box(), DEFAULT_WORKSPACE_ID)).keys == {}


# -- testing a key, and what members may know ------------------------------------------
async def test_testing_a_provider_makes_one_lookup_with_the_workspaces_key(people, monkeypatch):
    ada = await people.set_up()
    otx = next(p for p in PROVIDERS if p.name == "otx")
    seen = []

    async def answer(client, indicator):
        seen.append((otx.key(), indicator.value))
        return otx._result(indicator, status=STATUS_OK)

    monkeypatch.setattr(otx, "fetch", answer)
    untested = (await ada.post("/api/settings/providers/otx/test")).json()
    assert untested["status"] == "skipped" and seen == []
    await ada.patch("/api/settings", json={"keys": {"otx": OTX_KEY}})
    tested = (await ada.post("/api/settings/providers/otx/test")).json()
    assert tested["status"] == "ok" and seen == [(OTX_KEY, "8.8.8.8")]
    assert OTX_KEY not in str(tested)


async def test_every_member_sees_which_sources_answer_but_no_key(people):
    ada = await people.set_up()
    await people.member("bea", role="analyst")
    bea = await people.signed_in("bea")
    await ada.patch("/api/settings", json={"keys": {"otx": OTX_KEY}})
    seen = await bea.get("/api/workspace")
    assert seen.status_code == 200 and OTX_KEY not in seen.text
    states = {p["name"]: p for p in seen.json()["providers"]}
    assert states["otx"]["ready"] is True and states["abuseipdb"]["ready"] is False
    assert seen.json()["name"] == "Acme SOC"
