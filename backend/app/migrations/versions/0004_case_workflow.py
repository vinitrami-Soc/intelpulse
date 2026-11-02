"""The case workflow: a status, an assignee, a closing reason and time on every
case, and the tickets raised for it.

Cases from before this revision are `new` and unassigned. Tickets raised before
it were only in the audit log; they are not copied, since a record there names
a case but not always a workspace member who could see it.

Revision ID: 0004
Revises: 0003
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("cases") as batch:
        batch.add_column(sa.Column("status", sa.String(20), nullable=False, server_default="new"))
        batch.add_column(sa.Column("assignee_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("closed_reason", sa.String(20), nullable=True))
        batch.add_column(sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True))
        batch.create_index("ix_cases_status", ["status"])
        batch.create_index("ix_cases_assignee_id", ["assignee_id"])
        batch.create_foreign_key("fk_cases_assignee_id", "users", ["assignee_id"], ["id"], ondelete="SET NULL")
    with op.batch_alter_table("cases") as batch:
        batch.alter_column("status", server_default=None)

    op.create_table(
        "case_tickets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("sink", sa.String(20), nullable=False),
        sa.Column("key", sa.String(120), nullable=False),
        sa.Column("url", sa.String(500), nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_case_tickets_workspace_id", "case_tickets", ["workspace_id"])
    op.create_index("ix_case_tickets_case_id", "case_tickets", ["case_id"])


def downgrade() -> None:
    op.drop_index("ix_case_tickets_case_id", table_name="case_tickets")
    op.drop_index("ix_case_tickets_workspace_id", table_name="case_tickets")
    op.drop_table("case_tickets")
    with op.batch_alter_table("cases") as batch:
        batch.drop_constraint("fk_cases_assignee_id", type_="foreignkey")
        batch.drop_index("ix_cases_assignee_id")
        batch.drop_index("ix_cases_status")
        batch.drop_column("closed_at")
        batch.drop_column("closed_reason")
        batch.drop_column("assignee_id")
        batch.drop_column("status")
