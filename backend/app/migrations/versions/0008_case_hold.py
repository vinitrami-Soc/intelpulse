"""A hold on a case keeps its input past the retention days (spec 6.5).

Revision ID: 0008
Revises: 0007
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("cases") as batch:
        batch.add_column(sa.Column("held", sa.Boolean(), nullable=False, server_default=sa.false()))
    with op.batch_alter_table("cases") as batch:
        batch.alter_column("held", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("cases") as batch:
        batch.drop_column("held")
