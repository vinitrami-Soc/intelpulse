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
for key in ("ABUSEIPDB_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY", "ABUSECH_AUTH_KEY"):
    os.environ.pop(key, None)

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from alembic import command  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.db import alembic_config, engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402


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
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client
