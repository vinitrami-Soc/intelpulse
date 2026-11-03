"""Rotating ENCRYPTION_KEY (spec 6.4): every sealed value opened with the old key and sealed
again with the new one, in one transaction.

Sealed values are the settings' secrets (provider keys, tracker credentials, the
setup code) and every case's tier 1. If any value does not open with the old key,
nothing is changed: a half-rotated database would hold values neither key opens.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import SERVER, CaseInput, Setting
from . import audit
from .crypto import Box, DecryptError


class RotationError(Exception):
    pass


def _same_key(old: Box, new: Box) -> bool:
    try:
        old.open(new.seal(b"probe", "rotate:probe"), "rotate:probe")
    except DecryptError:
        return False
    return True


async def rotate(db: AsyncSession, old: Box, new: Box, *, actor: str = "rotate-key") -> dict[str, int]:
    """Re-seal everything under `new`; returns how many values of each kind. Raises RotationError,
    with nothing changed, when a value does not open with `old`."""
    if _same_key(old, new):
        raise RotationError("the new key is the current key: nothing was changed")
    counts = {"settings": 0, "case_inputs": 0}
    for row in (await db.execute(select(Setting).where(Setting.sealed.is_not(None)))).scalars():
        bound = f"settings:{row.workspace_id}:{row.key}"
        try:
            row.sealed = new.seal(old.open(row.sealed, bound), bound)
        except DecryptError as exc:
            raise RotationError(f"setting {row.key!r} of workspace {row.workspace_id} does not open with the "
                                "current key: nothing was changed") from exc
        counts["settings"] += 1
    for row in (await db.execute(select(CaseInput))).scalars():
        bound = f"case_inputs:sealed:{row.case_id}"
        try:
            row.sealed = new.seal(old.open(row.sealed, bound), bound)
        except DecryptError as exc:
            raise RotationError(f"the input of case {row.case_id} does not open with the current key: "
                                "nothing was changed") from exc
        counts["case_inputs"] += 1
    await audit.record(db, action="server.key_rotated", actor=actor, workspace_id=SERVER, detail=counts)
    return counts
