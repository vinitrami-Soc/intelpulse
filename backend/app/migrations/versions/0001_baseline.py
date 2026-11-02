"""IntelPulse 1.0.1's schema, as `create_all` made it.

A database from 1.x already has these tables and is stamped at this revision
instead of running it (see ``app.db._upgrade``); a new database runs it.
Frozen: never edit this file, add a migration instead.

Revision ID: 0001
Revises:
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("analyst", sa.String(120), nullable=True),
        sa.Column("raw_input", sa.Text(), nullable=True),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("max_score", sa.Integer(), nullable=False),
        sa.Column("indicator_count", sa.Integer(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "pushed_alerts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source", sa.String(40), nullable=False),
        sa.Column("alert_id", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("source", "alert_id", name="uq_pushed_alert_source_id"),
    )
    op.create_index("ix_pushed_alerts_case_id", "pushed_alerts", ["case_id"], unique=True)
    op.create_table(
        "indicator_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("case_id", sa.String(36), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("value", sa.String(2048), nullable=False),
        sa.Column("ioc_type", sa.String(16), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("verdict", sa.String(20), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("malware_families", sa.JSON(), nullable=False),
        sa.Column("attack_ids", sa.JSON(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_indicator_results_case_id", "indicator_results", ["case_id"])
    op.create_index("ix_indicator_results_value", "indicator_results", ["value"])
    op.create_table(
        "list_entries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("ioc_type", sa.String(16), nullable=False),
        sa.Column("list_type", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("created_by", sa.String(120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("value", "list_type", name="uq_list_value_type"),
    )
    op.create_index("ix_list_entries_value", "list_entries", ["value"])
    op.create_table(
        "feed_entries",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("value", sa.String(512), nullable=False),
        sa.Column("ioc_type", sa.String(16), nullable=False),
        sa.Column("feed", sa.String(64), nullable=False),
        sa.Column("malware_family", sa.String(120), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.String(40), nullable=True),
        sa.Column("last_seen", sa.String(40), nullable=True),
        sa.Column("extra", sa.JSON(), nullable=False),
        sa.Column("imported_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("value", "feed", name="uq_feed_value"),
    )
    op.create_index("ix_feed_entries_value", "feed_entries", ["value"])
    op.create_index("ix_feed_entries_value_feed", "feed_entries", ["value", "feed"])
    op.create_table(
        "feed_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("feed", sa.String(64), nullable=False),
        sa.Column("rows", sa.Integer(), nullable=False),
        sa.Column("ok", sa.Boolean(), nullable=False),
        sa.Column("detail", sa.String(500), nullable=False),
        sa.Column("ran_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_feed_runs_feed", "feed_runs", ["feed"])
    op.create_table(
        "cve_records",
        sa.Column("cve_id", sa.String(24), primary_key=True),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(120), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("published", sa.String(40), nullable=True),
        sa.Column("known_exploited", sa.Boolean(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
    )
    op.create_table(
        "audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(120), nullable=False),
        sa.Column("target", sa.String(512), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])


def downgrade() -> None:
    for table in ("audit_log", "cve_records", "feed_runs", "feed_entries", "list_entries",
                  "indicator_results", "pushed_alerts", "cases"):
        op.drop_table(table)
