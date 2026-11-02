"""Test fixtures: isolated SQLite file, no network, no API keys."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TMP_DB = Path(tempfile.gettempdir()) / "intelpulse-test.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TMP_DB}"
os.environ.pop("REDIS_URL", None)
# A fixed test key (32 bytes, base64): the server refuses to start without one.
os.environ["ENCRYPTION_KEY"] = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
os.environ.pop("ENCRYPTION_KEY_FILE", None)
# The 1.x token, so the tests written before accounts keep calling the API as they did:
# the `client` fixture sends it. Tests of sessions and API tokens use `browser`, which sends nothing.
LEGACY_TOKEN = "legacy-token-for-tests"
os.environ["API_TOKEN"] = LEGACY_TOKEN
# httpx keeps Secure cookies to itself over http://; browsers would send them on localhost.
os.environ["COOKIE_SECURE"] = "false"
for key in ("ABUSEIPDB_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY", "ABUSECH_AUTH_KEY"):
    os.environ.pop(key, None)

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from alembic import command  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.db import alembic_config, engine, init_db, session_scope  # noqa: E402
from app.main import app  # noqa: E402
from app.models import DEFAULT_WORKSPACE_ID, DEFAULT_WORKSPACE_NAME, Base, Workspace  # noqa: E402
from app.platform import accounts, auth  # noqa: E402
from app.platform.box import server_box  # noqa: E402
from app.platform.deps import login_throttle  # noqa: E402
from app.security import limiter  # noqa: E402


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


def _drop_everything(connection) -> None:
    Base.metadata.drop_all(connection)
    connection.exec_driver_sql("DROP TABLE IF EXISTS alembic_version")


def _build_at_head(connection) -> None:
    """The models' schema, stamped at the newest migration. Faster than running
    every migration for every test; tests/test_platform_migrations.py proves the
    migrations build exactly this schema."""
    Base.metadata.create_all(connection)
    # what migration 0002 inserts: the organization every pre-v2 row belongs to
    connection.execute(Workspace.__table__.insert().values(
        id=DEFAULT_WORKSPACE_ID, name=DEFAULT_WORKSPACE_NAME, kind="organization"))
    command.stamp(alembic_config(connection), "head")


@pytest_asyncio.fixture
async def clean_db():
    async with engine.begin() as conn:
        await conn.run_sync(_drop_everything)
        await conn.run_sync(_build_at_head)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(_drop_everything)


@pytest_asyncio.fixture
async def client(clean_db):
    """The API as a 1.x script calls it: with the API_TOKEN, in the default organization."""
    await init_db()
    login_throttle.clear()
    transport = ASGITransport(app=app)
    headers = {"Authorization": f"Bearer {LEGACY_TOKEN}"}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as async_client:
        yield async_client


@pytest_asyncio.fixture
async def browser(clean_db):
    """The API as a browser calls it: no credentials but the cookies it is given."""
    await init_db()
    login_throttle.clear()
    limiter._hits.clear()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost") as async_client:
        yield async_client


PASSWORD = "correct horse battery staple"


class Accounts:
    """People and workspaces for the v2 tests, made the way the server makes them."""

    def __init__(self) -> None:
        self._clients: list[AsyncClient] = []

    async def code(self) -> str | None:
        async with session_scope() as db:
            return await accounts.setup_code(db, server_box())

    async def set_up(self, username: str = "owner", organization: str = "Acme SOC") -> AsyncClient:
        """The owner's account through POST /api/setup; returns the owner, signed in."""
        client = self._client()
        response = await client.post("/api/setup", json={
            "code": await self.code(), "username": username, "password": PASSWORD,
            "organization": organization,
        })
        assert response.status_code == 201, response.text
        client.headers["X-CSRF-Token"] = response.json()["csrf"]
        return client

    async def workspace(self, name: str, kind: str = "organization") -> int:
        async with session_scope() as db:
            row = Workspace(name=name, kind=kind)
            db.add(row)
            await db.flush()
            return row.id

    async def member(self, username: str, *, role: str = "analyst",
                     workspace_id: int = DEFAULT_WORKSPACE_ID) -> None:
        async with session_scope() as db:
            await auth.create_user(db, username, PASSWORD, role=role, workspace_id=workspace_id)

    async def signed_in(self, username: str) -> AsyncClient:
        """A browser of its own (its own cookie jar), signed in, sending its CSRF token."""
        client = self._client()
        response = await client.post("/api/session", json={"username": username, "password": PASSWORD})
        assert response.status_code == 200, response.text
        client.headers["X-CSRF-Token"] = response.json()["csrf"]
        return client

    async def token(self, admin: AsyncClient, scope: str, name: str = "script") -> AsyncClient:
        """A script holding a new API token of this scope, made by `admin`."""
        response = await admin.post("/api/tokens", json={"name": name, "scope": scope})
        assert response.status_code == 201, response.text
        client = self._client()
        client.headers["Authorization"] = f"Bearer {response.json()['token']}"
        return client

    def _client(self) -> AsyncClient:
        client = AsyncClient(transport=ASGITransport(app=app), base_url="http://localhost")
        self._clients.append(client)
        return client

    async def close(self) -> None:
        for client in self._clients:
            await client.aclose()


@pytest_asyncio.fixture
async def people(browser):
    made = Accounts()
    yield made
    await made.close()
