"""Invitations: a one-use link into a workspace, for a role, for seven days (spec 5.4).

Revision ID: 0005
Revises: 0004
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "invites",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_by", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_invites_created_by"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("used_by", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL", name="fk_invites_used_by"), nullable=True),
    )
    op.create_index("ix_invites_workspace_id", "invites", ["workspace_id"])
    op.create_index("ix_invites_token_hash", "invites", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_invites_token_hash", table_name="invites")
    op.drop_index("ix_invites_workspace_id", table_name="invites")
    op.drop_table("invites")
