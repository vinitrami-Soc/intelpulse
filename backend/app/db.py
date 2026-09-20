"""Async engine/session plumbing. SQLite by default, Postgres in compose."""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings
from .models import Base

logger = logging.getLogger(__name__)


def _normalise_url(url: str) -> str:
    """Resolve the default relative SQLite path against the backend directory."""
    prefix = "sqlite+aiosqlite:///./"
    if url.startswith(prefix):
        target = (Path(__file__).resolve().parent.parent / url[len(prefix):]).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite+aiosqlite:///{target}"
    return url


engine = create_async_engine(_normalise_url(settings.database_url), future=True, pool_pre_ping=True)
SessionFactory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database ready: %s", engine.url.render_as_string(hide_password=True))


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    session = SessionFactory()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with session_scope() as session:
        yield session
