"""Workspaces, users, sessions, API tokens and settings; every row a workspace owns
gets `workspace_id`, and a 1.x database's rows move to "Default organization".

Uniqueness of pushed alerts (source, alert id) and list entries (value, list)
becomes per workspace. Frozen: add a migration instead of editing this one.

Revision ID: 0002
Revises: 0001
"""
from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

DEFAULT_WORKSPACE_ID = 1
SCOPED = ("cases", "pushed_alerts", "indicator_results", "list_entries")


def upgrade() -> None:
    op.create_table(
        "workspaces",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("kind", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.bulk_insert(
        sa.table(
            "workspaces",
            sa.column("id", sa.Integer()),
            sa.column("name", sa.String()),
            sa.column("kind", sa.String()),
            sa.column("created_at", sa.DateTime(timezone=True)),
        ),
        [{"id": DEFAULT_WORKSPACE_ID, "name": "Default organization", "kind": "organization",
          "created_at": datetime.now(UTC)}],
    )
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("email", sa.String(254), nullable=True),
        sa.Column("email_confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("owner", sa.Boolean(), nullable=False),
        sa.Column("disabled", sa.Boolean(), nullable=False),
        sa.Column("must_change_password", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_users_workspace_id", "users", ["workspace_id"])
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_table(
        "sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("csrf_token", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])
    op.create_table(
        "api_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("created_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_api_tokens_workspace_id", "api_tokens", ["workspace_id"])
    op.create_index("ix_api_tokens_token_hash", "api_tokens", ["token_hash"], unique=True)
    op.create_table(
        "settings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("value", sa.JSON(), nullable=True),
        sa.Column("sealed", sa.LargeBinary(), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("workspace_id", "key", name="uq_setting_workspace_key"),
    )
    op.create_index("ix_settings_workspace_id", "settings", ["workspace_id"])

    # Every existing row is the default organization's: the column arrives
    # with that as its value, and the default is dropped again afterwards so
    # that code must always say which workspace a new row belongs to.
    for table in SCOPED:
        with op.batch_alter_table(table) as batch:
            batch.add_column(sa.Column("workspace_id", sa.Integer(), nullable=False,
                                       server_default=str(DEFAULT_WORKSPACE_ID)))
            batch.create_index(f"ix_{table}_workspace_id", ["workspace_id"])
            batch.create_foreign_key(f"fk_{table}_workspace_id", "workspaces", ["workspace_id"], ["id"],
                                     ondelete="CASCADE")
        with op.batch_alter_table(table) as batch:
            batch.alter_column("workspace_id", server_default=None)

    with op.batch_alter_table("cases") as batch:
        batch.add_column(sa.Column("created_by", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_cases_created_by", "users", ["created_by"], ["id"], ondelete="SET NULL")
    with op.batch_alter_table("pushed_alerts") as batch:
        batch.drop_constraint("uq_pushed_alert_source_id", type_="unique")
        batch.create_unique_constraint("uq_pushed_alert_source_id", ["workspace_id", "source", "alert_id"])
    with op.batch_alter_table("list_entries") as batch:
        batch.drop_constraint("uq_list_value_type", type_="unique")
        batch.create_unique_constraint("uq_list_value_type", ["workspace_id", "value", "list_type"])


def downgrade() -> None:
    with op.batch_alter_table("list_entries") as batch:
        batch.drop_constraint("uq_list_value_type", type_="unique")
        batch.create_unique_constraint("uq_list_value_type", ["value", "list_type"])
    with op.batch_alter_table("pushed_alerts") as batch:
        batch.drop_constraint("uq_pushed_alert_source_id", type_="unique")
        batch.create_unique_constraint("uq_pushed_alert_source_id", ["source", "alert_id"])
    with op.batch_alter_table("cases") as batch:
        batch.drop_constraint("fk_cases_created_by", type_="foreignkey")
        batch.drop_column("created_by")
    for table in SCOPED:
        with op.batch_alter_table(table) as batch:
            batch.drop_constraint(f"fk_{table}_workspace_id", type_="foreignkey")
            batch.drop_index(f"ix_{table}_workspace_id")
            batch.drop_column("workspace_id")
    for table in ("settings", "api_tokens", "sessions", "users", "workspaces"):
        op.drop_table(table)
