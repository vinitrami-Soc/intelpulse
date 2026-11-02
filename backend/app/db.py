"""Async engine/session plumbing. SQLite by default, Postgres in compose.

The schema is owned by Alembic (``app/migrations``): ``init_db`` brings any
database, new or from 1.x, to the newest migration.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Connection, inspect
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings

logger = logging.getLogger(__name__)

MIGRATIONS = Path(__file__).resolve().parent / "migrations"
BASELINE = "0001"


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


def alembic_config(connection: Connection | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    if connection is not None:
        config.attributes["connection"] = connection
    return config


def _upgrade(connection: Connection) -> None:
    """Bring the schema to the newest migration.

    A 1.x database already holds the baseline's tables, made by `create_all`,
    but no `alembic_version`: it is stamped at the baseline, so nothing is
    created twice and its rows stay where they are.
    """
    config = alembic_config(connection)
    tables = set(inspect(connection).get_table_names())
    if "alembic_version" not in tables and "cases" in tables:
        logger.info("a 1.x database: stamping migration %s before upgrading", BASELINE)
        command.stamp(config, BASELINE)
    command.upgrade(config, "head")


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(_upgrade)
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
