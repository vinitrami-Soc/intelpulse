"""The audit log becomes a hash chain: `workspace_id`, `prev_hash` and `hash` on
each record, and an `audit_head` row with the newest hash and the count.

Records from before the chain belong to the default organization and are
chained here, oldest first, with a frozen copy of `app.platform.audit.digest`.

Revision ID: 0003
Revises: 0002
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

GENESIS = "0" * 64
DEFAULT_WORKSPACE_ID = 1


def _stamp(at: datetime | str) -> str:
    if isinstance(at, str):  # SQLite may hand the raw text back through a lightweight table
        at = datetime.fromisoformat(at)
    if at.tzinfo is not None:
        at = at.astimezone(UTC).replace(tzinfo=None)
    return at.isoformat()


def _digest(prev_hash: str, row) -> str:
    """Frozen copy of app.platform.audit.digest at this revision."""
    detail = row.detail if isinstance(row.detail, dict) else json.loads(row.detail or "{}")
    body = {"at": _stamp(row.created_at), "actor": row.actor, "action": row.action,
            "target": row.target, "detail": detail}
    if row.workspace_id is not None:
        body["workspace"] = row.workspace_id
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def upgrade() -> None:
    with op.batch_alter_table("audit_log") as batch:
        batch.add_column(sa.Column("workspace_id", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("prev_hash", sa.String(64), nullable=True))
        batch.add_column(sa.Column("hash", sa.String(64), nullable=True))
        batch.create_index("ix_audit_log_workspace_id", ["workspace_id"])
    op.create_table(
        "audit_head",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
    )

    bind = op.get_bind()
    audit = sa.table(
        "audit_log",
        sa.column("id", sa.Integer()), sa.column("workspace_id", sa.Integer()),
        sa.column("action", sa.String()), sa.column("actor", sa.String()),
        sa.column("target", sa.String()), sa.column("detail", sa.JSON()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("prev_hash", sa.String()), sa.column("hash", sa.String()),
    )
    bind.execute(audit.update().values(workspace_id=DEFAULT_WORKSPACE_ID))
    prev, count = GENESIS, 0
    for row in bind.execute(sa.select(audit).order_by(audit.c.id)).all():
        current = _digest(prev, row)
        bind.execute(audit.update().where(audit.c.id == row.id).values(prev_hash=prev, hash=current))
        prev, count = current, count + 1
    op.bulk_insert(
        sa.table("audit_head", sa.column("id", sa.Integer()), sa.column("hash", sa.String()),
                 sa.column("count", sa.Integer())),
        [{"id": 1, "hash": prev, "count": count}],
    )
    with op.batch_alter_table("audit_log") as batch:
        batch.alter_column("prev_hash", existing_type=sa.String(64), nullable=False)
        batch.alter_column("hash", existing_type=sa.String(64), nullable=False)


def downgrade() -> None:
    op.drop_table("audit_head")
    with op.batch_alter_table("audit_log") as batch:
        batch.drop_index("ix_audit_log_workspace_id")
        batch.drop_column("hash")
        batch.drop_column("prev_hash")
        batch.drop_column("workspace_id")
