"""Tier 1 (spec 6.3): what a case was made from, sealed, in `case_inputs`.

That is the paste or the uploaded file's text, and a pushed alert's description and
the text of each evidence item. It is sealed with the server's key, bound to its
case (a value copied to another row fails to open), with the SHA-256 of what was
sealed kept beside it, so a deleted input can still be named in the audit log.

Everything else about a case is tier 2 and stays until someone deletes it: the
verdict, the indicators and their provider answers, and the alert's source, ID,
severity, title, entities, techniques and the time and label of each evidence item.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Case, CaseInput
from ..platform.box import server_box
from ..platform.crypto import Box


def bound_to(case_id: str) -> str:
    return f"case_inputs:sealed:{case_id}"


def split_alert(payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """(the alert's tier 1, the alert without it): its description and each evidence item's text."""
    kept = dict(payload)
    description = kept.pop("description", "") or ""
    evidence = [dict(item) for item in kept.get("evidence") or [] if isinstance(item, dict)]
    texts = [str(item.pop("text", "") or "") for item in evidence]
    kept["evidence"] = evidence
    return {"description": description, "evidence": texts}, kept


def join_alert(payload: dict[str, Any], tier1: dict[str, Any] | None) -> dict[str, Any]:
    """The alert as it was pushed, its tier 1 put back; or, once that is gone, without it."""
    alert = dict(payload)
    if tier1 is None:
        return alert
    alert["description"] = tier1.get("description", "")
    texts = list(tier1.get("evidence") or [])
    alert["evidence"] = [{**item, "text": texts[i] if i < len(texts) else ""}
                         for i, item in enumerate(alert.get("evidence") or []) if isinstance(item, dict)]
    return alert


def seal(box: Box, case_id: str, content: dict[str, Any]) -> tuple[bytes, str]:
    data = json.dumps(content, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return box.seal(data, bound_to(case_id)), hashlib.sha256(data).hexdigest()


async def store(db: AsyncSession, case: Case, *, raw_input: str | None = None,
                alert: dict[str, Any] | None = None) -> CaseInput | None:
    """Seal a new case's input; nothing is stored when there is none."""
    content: dict[str, Any] = {}
    if raw_input:
        content["raw_input"] = raw_input
    if alert and (alert.get("description") or any(alert.get("evidence") or [])):
        content["alert"] = alert
    if not content:
        return None
    sealed, digest = seal(server_box(), case.id, content)
    row = CaseInput(case_id=case.id, workspace_id=case.workspace_id, sealed=sealed, sha256=digest)
    db.add(row)
    return row


async def read(db: AsyncSession, case_id: str) -> dict[str, Any] | None:
    """The case's input as it was given, or None when there is none (never given, or deleted)."""
    row = await db.get(CaseInput, case_id)
    if row is None:
        return None
    return json.loads(server_box().open(row.sealed, bound_to(case_id)).decode("utf-8"))


def may_read_raw(actor, case: Case) -> bool:
    """The paste itself (spec 5.6): an analyst reads their own cases', an admin any; a script with a
    token, and the 1.x token, read what they could before."""
    if actor.via != "session":
        return True
    return actor.is_admin or (case.created_by is not None and case.created_by == actor.user_id)
