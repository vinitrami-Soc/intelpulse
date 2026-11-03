"""Findings of the November 2026 security review (docs/SECURITY-REVIEW.md), each pinned by a test
that fails on the code as it was."""
from __future__ import annotations

from contextlib import asynccontextmanager

import pytest
import yaml
from httpx import ASGITransport, AsyncClient
from starlette.datastructures import Headers

from app.config import settings
from app.main import create_app
from app.routers import health
from app.security import client_ip
from tests.test_deploy_kit import DEPLOY


class _Request:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = Headers(headers)
        self.client = type("Peer", (), {"host": "10.0.0.2"})()


# R1 ---------------------------------------------------------------------------------------
@pytest.mark.parametrize(("sent", "client"), [
    ("198.51.100.9", "198.51.100.9"),                        # a proxy that replaces the header
    ("203.0.113.66, 198.51.100.9", "198.51.100.9"),          # one that appends: the first is forged
    ("203.0.113.66, 203.0.113.67, 198.51.100.9", "198.51.100.9"),
    (" , 198.51.100.9 ", "198.51.100.9"),
])
def test_the_trusted_forwarded_address_is_the_one_the_proxy_appended(monkeypatch, sent, client):
    monkeypatch.setattr(settings, "trust_forwarded_for", True)
    monkeypatch.setattr(settings, "client_ip_header", "")
    assert client_ip(_Request({"X-Forwarded-For": sent})) == client


def test_an_empty_forwarded_header_falls_back_to_the_socket(monkeypatch):
    monkeypatch.setattr(settings, "trust_forwarded_for", True)
    monkeypatch.setattr(settings, "client_ip_header", "")
    assert client_ip(_Request({"X-Forwarded-For": " , "})) == "10.0.0.2"


async def test_a_forged_first_entry_mints_no_fresh_identity(client, monkeypatch):
    monkeypatch.setattr(settings, "trust_forwarded_for", True)
    monkeypatch.setattr(settings, "client_ip_header", "")
    monkeypatch.setattr(settings, "rate_limit_write", 1)
    first = {"X-Forwarded-For": "203.0.113.1, 198.51.100.9"}
    assert (await client.post("/api/extract", json={"text": "8.8.8.8"}, headers=first)).status_code == 200
    again = {"X-Forwarded-For": "203.0.113.2, 198.51.100.9"}   # a new forged entry, the same proxy hop
    assert (await client.post("/api/extract", json={"text": "8.8.8.8"}, headers=again)).status_code == 429


# R2 ---------------------------------------------------------------------------------------
async def test_the_public_health_check_names_no_database_error(client, monkeypatch, caplog):
    @asynccontextmanager
    async def broken():
        raise ConnectionRefusedError("could not connect to db.internal:5432 as intelpulse")
        yield  # pragma: no cover

    monkeypatch.setattr(health, "session_scope", broken)
    answer = await client.get("/api/health")
    assert answer.status_code == 200 and answer.json()["status"] == "degraded"
    assert answer.json()["database"].endswith("(error)")
    assert "db.internal" not in answer.text and "db.internal" in caplog.text


# R3 ---------------------------------------------------------------------------------------
async def _paths(monkeypatch, **given) -> dict[str, int]:
    for key, value in given.items():
        monkeypatch.setattr(settings, key, value)
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost") as c:
        return {path: (await c.get(path)).status_code for path in ("/docs", "/redoc", "/openapi.json")}


async def test_in_production_no_page_loads_a_cdn_script_onto_this_origin(clean_db, monkeypatch):
    assert await _paths(monkeypatch, environment="production", api_docs=None) == \
        {"/docs": 404, "/redoc": 404, "/openapi.json": 200}


async def test_the_docs_are_there_in_development_and_when_asked_for(clean_db, monkeypatch):
    assert (await _paths(monkeypatch, environment="development", api_docs=None))["/docs"] == 200
    assert (await _paths(monkeypatch, environment="production", api_docs=True))["/docs"] == 200
    assert (await _paths(monkeypatch, environment="development", api_docs=False))["/docs"] == 404


# R4 ---------------------------------------------------------------------------------------
def test_the_tunnel_token_reaches_cloudflared_alone():
    compose = yaml.safe_load((DEPLOY / "compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    assert services["tunnel"]["env_file"] == [{"path": "tunnel.env", "required": False}]
    assert "environment" not in services["tunnel"]
    for name in ("app", "worker", "beat"):
        assert services[name]["env_file"] == [".env"], name
    setup = (DEPLOY / "setup.sh").read_text(encoding="utf-8")
    assert "CLOUDFLARE_TUNNEL_TOKEN=$token" not in setup    # not written into .env any more
    assert '"$here/tunnel.env"' in setup and 'chmod 600 "$here/tunnel.env"' in setup


# R5 ---------------------------------------------------------------------------------------
@pytest.fixture
async def bea(people):
    await people.set_up("ada", "Acme SOC")
    await people.member("bea")
    return await people.signed_in("bea")


async def test_a_new_address_for_the_reset_link_needs_the_current_password(bea):
    from tests.conftest import PASSWORD

    # a stolen session would otherwise point the reset link at its own mailbox, and keep the account
    refused = await bea.patch("/api/profile", json={"email": "attacker@evil.example"})
    assert refused.status_code == 403 and refused.json()["error"] == "wrong_password"
    wrong = await bea.patch("/api/profile", json={"email": "attacker@evil.example", "current_password": "guess " * 3})
    assert wrong.status_code == 403
    assert (await bea.get("/api/profile")).json()["email"] is None
    done = await bea.patch("/api/profile", json={"email": "bea@acme.example", "current_password": PASSWORD})
    assert done.status_code == 200 and done.json()["email"] == "bea@acme.example"


async def test_what_does_not_change_the_address_needs_no_password(bea):
    from tests.conftest import PASSWORD

    await bea.patch("/api/profile", json={"email": "bea@acme.example", "current_password": PASSWORD})
    assert (await bea.patch("/api/profile", json={"display_name": "Bea T"})).status_code == 200
    same = await bea.patch("/api/profile", json={"email": "bea@acme.example"})
    assert same.status_code == 200 and same.json()["changed"] == []


async def test_guessing_the_current_password_slows_down_as_at_sign_in(bea):
    for _ in range(3):
        assert (await bea.patch("/api/profile", json={"email": "x@evil.example", "current_password": "nope " * 3})).status_code == 403
    slowed = await bea.patch("/api/profile", json={"email": "x@evil.example", "current_password": "nope " * 3})
    assert slowed.status_code == 429 and "Retry-After" in slowed.headers
