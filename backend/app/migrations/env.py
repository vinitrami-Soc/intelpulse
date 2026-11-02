"""Alembic environment for IntelPulse.

The app runs migrations itself at startup (``app.db.init_db``) and hands this
file its open connection through ``config.attributes["connection"]``; the CLI
(``python -m app.cli migrate``) does the same. ``render_as_batch`` lets SQLite,
which cannot alter a column in place, take the same migrations as Postgres.
"""
from __future__ import annotations

from alembic import context

from app.models import Base

target_metadata = Base.metadata


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        render_as_batch=True,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("run migrations through app.db.init_db or `python -m app.cli migrate`")
_run(connection)
