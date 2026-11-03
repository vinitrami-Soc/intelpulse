"""Tier 1 moves into `case_inputs`, sealed (spec 6.3).

Every case's raw input, and every pushed alert's description and evidence text,
is sealed with the server's key (bound to its case) into `case_inputs`, with the
SHA-256 of what was sealed; `cases.raw_input` is dropped and the alert payloads
keep everything else. `cases.input_deleted_at` is where the retention sweep will
say when a case's input went. Downgrading opens them again and puts them back.

The logic is written out here rather than imported, so later changes to the
application cannot change what this revision did.

Revision ID: 0007
Revises: 0006
"""
from __future__ import annotations

import hashlib
import json

import sqlalchemy as sa
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

BATCH = 500

cases = sa.table("cases", sa.column("id", sa.String()), sa.column("workspace_id", sa.Integer()),
                 sa.column("raw_input", sa.Text()), sa.column("created_at", sa.DateTime(timezone=True)))
alerts = sa.table("pushed_alerts", sa.column("id", sa.Integer()), sa.column("case_id", sa.String()),
                  sa.column("payload", sa.JSON()))
inputs = sa.table("case_inputs", sa.column("case_id", sa.String()), sa.column("workspace_id", sa.Integer()),
                  sa.column("sealed", sa.LargeBinary()), sa.column("sha256", sa.String()),
                  sa.column("created_at", sa.DateTime(timezone=True)))


def _box():
    from app.platform.box import server_box  # the running server's key: without it, nothing is moved
    return server_box()


def _bound(case_id: str) -> str:
    return f"case_inputs:sealed:{case_id}"


def _pages(bind, query, key):
    last = ""
    while True:
        rows = bind.execute(query.where(key > last).order_by(key).limit(BATCH)).all()
        if not rows:
            return
        yield rows
        last = rows[-1][0]


def upgrade() -> None:
    op.create_table(
        "case_inputs",
        sa.Column("case_id", sa.String(36), sa.ForeignKey("cases.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("workspace_id", sa.Integer(), sa.ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False),
        sa.Column("sealed", sa.LargeBinary(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_case_inputs_workspace_id", "case_inputs", ["workspace_id"])
    with op.batch_alter_table("cases") as batch:
        batch.add_column(sa.Column("input_deleted_at", sa.DateTime(timezone=True), nullable=True))

    bind = op.get_bind()
    box = None
    query = sa.select(cases.c.id, cases.c.workspace_id, cases.c.raw_input, cases.c.created_at)
    for page in _pages(bind, query, cases.c.id):
        pushed = {row.case_id: (row.id, row.payload) for row in bind.execute(
            sa.select(alerts.c.id, alerts.c.case_id, alerts.c.payload).where(alerts.c.case_id.in_([r.id for r in page]))
        )}
        for case_id, workspace_id, raw_input, created_at in page:
            content = {}
            if raw_input:
                content["raw_input"] = raw_input
            if case_id in pushed:
                alert_id, payload = pushed[case_id]
                payload = dict(payload or {})
                description = payload.pop("description", "") or ""
                evidence = [dict(item) for item in payload.get("evidence") or [] if isinstance(item, dict)]
                texts = [str(item.pop("text", "") or "") for item in evidence]
                payload["evidence"] = evidence
                if description or any(texts):
                    content["alert"] = {"description": description, "evidence": texts}
                bind.execute(alerts.update().where(alerts.c.id == alert_id).values(payload=payload))
            if not content:
                continue
            box = box or _box()
            data = json.dumps(content, ensure_ascii=False, sort_keys=True).encode("utf-8")
            bind.execute(inputs.insert().values(case_id=case_id, workspace_id=workspace_id,
                                                sealed=box.seal(data, _bound(case_id)),
                                                sha256=hashlib.sha256(data).hexdigest(), created_at=created_at))

    with op.batch_alter_table("cases") as batch:
        batch.drop_column("raw_input")


def downgrade() -> None:
    with op.batch_alter_table("cases") as batch:
        batch.add_column(sa.Column("raw_input", sa.Text(), nullable=True))
    bind = op.get_bind()
    box = None
    query = sa.select(inputs.c.case_id, inputs.c.sealed)
    for page in _pages(bind, query, inputs.c.case_id):
        for case_id, sealed in page:
            box = box or _box()
            content = json.loads(box.open(sealed, _bound(case_id)).decode("utf-8"))
            if content.get("raw_input"):
                bind.execute(cases.update().where(cases.c.id == case_id).values(raw_input=content["raw_input"]))
            alert = content.get("alert")
            if alert:
                row = bind.execute(sa.select(alerts.c.id, alerts.c.payload).where(alerts.c.case_id == case_id)).first()
                if row is not None:
                    payload = dict(row.payload or {})
                    payload["description"] = alert.get("description", "")
                    texts = alert.get("evidence") or []
                    payload["evidence"] = [{**item, "text": texts[i] if i < len(texts) else ""}
                                           for i, item in enumerate(payload.get("evidence") or [])]
                    bind.execute(alerts.update().where(alerts.c.id == row.id).values(payload=payload))
    with op.batch_alter_table("cases") as batch:
        batch.drop_column("input_deleted_at")
    op.drop_index("ix_case_inputs_workspace_id", table_name="case_inputs")
    op.drop_table("case_inputs")
