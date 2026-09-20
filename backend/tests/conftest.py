"""Test fixtures: isolated SQLite file, no network, no API keys."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

TMP_DB = Path(tempfile.gettempdir()) / "intelpulse-test.db"
os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{TMP_DB}"
os.environ.pop("REDIS_URL", None)
for key in ("ABUSEIPDB_API_KEY", "OTX_API_KEY", "GREYNOISE_API_KEY", "ABUSECH_AUTH_KEY"):
    os.environ.pop(key, None)

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402

from app.db import engine, init_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest_asyncio.fixture
async def clean_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture
async def client(clean_db):
    await init_db()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client
