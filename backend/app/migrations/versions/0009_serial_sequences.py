"""Postgres: every id sequence continues after the highest id already taken.

0002 inserts the default organization as workspace 1 and 0003 the audit head as row 1, both with
the id given. Postgres does not move a SERIAL column's sequence for an id that was given, so the
first workspace made afterwards (the first sign-up) asked the sequence, got 1 again, and failed
on the primary key: every sign-up on a new Postgres server answered 500. SQLite has no
sequences and never had the problem.

This sets each table's sequence past its highest id, whichever tables have one. Running it again
changes nothing; the downgrade has nothing to undo.

Revision ID: 0009
Revises: 0008
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def resync(bind) -> list[str]:
    """Move every id sequence past its table's highest id; returns the tables it moved."""
    if bind.dialect.name != "postgresql":
        return []
    moved = []
    for table in sa.inspect(bind).get_table_names():
        columns = {column["name"] for column in sa.inspect(bind).get_columns(table)}
        if "id" not in columns:
            continue
        sequence = bind.execute(sa.text("SELECT pg_get_serial_sequence(:t, 'id')"), {"t": table}).scalar()
        if not sequence:
            continue   # a text id (cases) or no sequence
        quoted = bind.dialect.identifier_preparer.quote(table)
        top = bind.execute(sa.text(f"SELECT COALESCE(MAX(id), 0) FROM {quoted}")).scalar()
        # is_called false: the next id handed out is top + 1
        bind.execute(sa.text("SELECT setval(:s, :v, false)"), {"s": sequence, "v": int(top) + 1})
        moved.append(table)
    return moved


def upgrade() -> None:
    resync(op.get_bind())


def downgrade() -> None:
    pass
