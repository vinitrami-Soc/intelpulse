"""Migrations build the models' schema, adopt a 1.x database, and run twice safely."""
from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.db import BASELINE, _upgrade, alembic_config
from app.models import Base
from app.platform import audit

# The 1.x tables as Core objects, so rows are written the way 1.x wrote them.
CASES_1X = sa.table(
    "cases", sa.column("id", sa.String()), sa.column("title", sa.String()), sa.column("source", sa.String()),
    sa.column("verdict", sa.String()), sa.column("max_score", sa.Integer()),
    sa.column("indicator_count", sa.Integer()), sa.column("duration_ms", sa.Integer()),
    sa.column("created_at", sa.DateTime(timezone=True)),
)
AUDIT_1X = sa.table(
    "audit_log", sa.column("action", sa.String()), sa.column("actor", sa.String()),
    sa.column("target", sa.String()), sa.column("detail", sa.JSON()),
    sa.column("created_at", sa.DateTime(timezone=True)),
)


def _a_1x_database(connection) -> None:
    """The baseline's tables, made by create_all, and no alembic_version."""
    command.upgrade(alembic_config(connection), BASELINE)
    connection.exec_driver_sql("DROP TABLE alembic_version")


def _engine(tmp_path):
    return sa.create_engine(f"sqlite:///{tmp_path / 'migrate.db'}")


def _head() -> str:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def _revision(connection) -> str:
    return connection.exec_driver_sql("SELECT version_num FROM alembic_version").scalar_one()


def test_a_new_database_is_built_by_the_migrations_to_the_models_schema(tmp_path):
    engine = _engine(tmp_path)
    with engine.begin() as conn:
        _upgrade(conn)
    with engine.connect() as conn:
        assert _revision(conn) == _head()
        drift = compare_metadata(MigrationContext.configure(conn), Base.metadata)
    assert drift == [], f"the migrations and app/models.py disagree: {drift}"


def test_a_1x_database_is_stamped_and_keeps_its_rows(tmp_path):
    engine = _engine(tmp_path)
    with engine.begin() as conn:
        _a_1x_database(conn)
        conn.execute(CASES_1X.insert().values(
            id="case-1", title="from 1.x", source="paste", verdict="high", max_score=80,
            indicator_count=2, duration_ms=10, created_at=datetime(2026, 9, 1, tzinfo=UTC),
        ))
    with engine.begin() as conn:
        _upgrade(conn)
    with engine.connect() as conn:
        assert _revision(conn) == _head()
        row = conn.exec_driver_sql("SELECT title, workspace_id FROM cases WHERE id = 'case-1'").one()
        assert tuple(row) == ("from 1.x", 1)  # moved to the default organization


async def test_audit_records_from_before_the_chain_are_chained(tmp_path):
    engine = _engine(tmp_path)
    with engine.begin() as conn:
        _a_1x_database(conn)
        for n in range(3):
            conn.execute(AUDIT_1X.insert().values(
                action=f"old.{n}", actor="api-token", target=f"case-{n}", detail={"n": n},
                created_at=datetime(2026, 9, n + 1, 12, 0, 0, 123456, tzinfo=UTC),
            ))
    with engine.begin() as conn:
        _upgrade(conn)
    reader = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'migrate.db'}")
    try:
        async with AsyncSession(reader) as db:
            assert await audit.verify(db) == []
            # The chain goes on from them: a new record follows the last old one.
            await audit.record(db, action="new", actor="tester", workspace_id=1)
            await db.commit()
            assert await audit.verify(db) == []
    finally:
        await reader.dispose()


def test_running_the_migrations_twice_changes_nothing(tmp_path):
    engine = _engine(tmp_path)
    with engine.begin() as conn:
        _upgrade(conn)
    with engine.begin() as conn:
        _upgrade(conn)
        assert _revision(conn) == _head()
