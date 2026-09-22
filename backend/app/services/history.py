"""What changed since an indicator was last triaged.

Re-scanning an address a week later and being shown the same verdict screen
tells an analyst nothing. The question is the delta: is it worse, did a source
that was quiet start answering, is there a malware family on it that was not
there before. Every field needed to answer that is already written to
`indicator_results` on every persisted case, so this module only has to read it
back and subtract.

The comparison itself is a pure function over two snapshots. That keeps it
testable without a database, and it is the same arithmetic the browser engine
runs against local case history in demo mode — see `web/assets/engine.js`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import IndicatorResult

# Least to most severe. Storage outlives any one release, so a band that is not
# in this list compares as "changed" without claiming a direction.
BANDS = ["informational", "low", "medium", "high", "critical"]

ANSWERED = {"ok", "clean"}


@dataclass
class IndicatorDiff:
    """The difference between this triage of an indicator and the last one."""

    value: str = ""
    current_score: int = 0
    current_verdict: str = "informational"
    first_seen: bool = False
    previous_case_id: str | None = None
    previous_at: datetime | None = None
    previous_score: int | None = None
    previous_verdict: str | None = None
    score_delta: int = 0
    verdict_changed: bool = False
    escalated: bool = False
    de_escalated: bool = False
    sources_added: list[str] = field(default_factory=list)
    sources_removed: list[str] = field(default_factory=list)
    new_malware_families: list[str] = field(default_factory=list)
    new_attack_ids: list[str] = field(default_factory=list)
    summary: str = ""

    @property
    def changed(self) -> bool:
        return bool(
            self.score_delta
            or self.verdict_changed
            or self.sources_added
            or self.sources_removed
            or self.new_malware_families
            or self.new_attack_ids
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "score": self.current_score,
            "verdict": self.current_verdict,
            "first_seen": self.first_seen,
            "changed": self.changed,
            "previous_case_id": self.previous_case_id,
            "previous_at": self.previous_at.isoformat() if self.previous_at else None,
            "previous_score": self.previous_score,
            "previous_verdict": self.previous_verdict,
            "score_delta": self.score_delta,
            "verdict_changed": self.verdict_changed,
            "escalated": self.escalated,
            "de_escalated": self.de_escalated,
            "sources_added": self.sources_added,
            "sources_removed": self.sources_removed,
            "new_malware_families": self.new_malware_families,
            "new_attack_ids": self.new_attack_ids,
            "summary": self.summary,
        }


def snapshot_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """The comparable shape of one indicator, out of a stored case payload.

    A provider that was skipped or errored did not answer, and counting it as a
    source would report a vendor outage as an intelligence change.
    """
    sources = payload.get("sources") or []
    answering = sorted(
        {
            str(s.get("provider"))
            for s in sources
            if isinstance(s, dict) and s.get("status") in ANSWERED and s.get("provider")
        }
    )
    techniques = payload.get("attack_techniques") or []
    attack_ids = sorted(
        {
            str(t.get("id"))
            for t in techniques
            if isinstance(t, dict) and t.get("id")
        }
        or {str(t) for t in techniques if isinstance(t, str)}
    )
    return {
        "score": int(payload.get("score") or 0),
        "verdict": str(payload.get("verdict") or "informational"),
        "answering": answering,
        "malware_families": sorted({str(m) for m in (payload.get("malware_families") or [])}),
        "attack_ids": attack_ids,
    }


def _rank(band: str) -> int | None:
    try:
        return BANDS.index(band)
    except ValueError:
        return None


def _summarise(d: IndicatorDiff) -> str:
    if d.first_seen:
        return "First time this indicator has been triaged."
    if not d.changed:
        return "No change since the last triage."

    parts: list[str] = []
    # The escalation is what an analyst reads first, so it leads.
    if d.verdict_changed and d.escalated:
        parts.append(f"Escalated from {d.previous_verdict} to {d.current_verdict}")
    elif d.verdict_changed and d.de_escalated:
        parts.append(f"Dropped from {d.previous_verdict} to {d.current_verdict}")
    elif d.verdict_changed:
        parts.append(f"Band changed from {d.previous_verdict} to {d.current_verdict}")
    elif d.score_delta:
        direction = "up" if d.score_delta > 0 else "down"
        parts.append(f"Score {direction} {abs(d.score_delta)} to {d.current_score}")

    if d.new_malware_families:
        parts.append("new malware: " + ", ".join(d.new_malware_families))
    if d.sources_added:
        parts.append("now answering: " + ", ".join(d.sources_added))
    if d.sources_removed:
        parts.append("stopped answering: " + ", ".join(d.sources_removed))
    if d.new_attack_ids:
        parts.append("new techniques: " + ", ".join(d.new_attack_ids))
    return "; ".join(parts) + "."


def diff_snapshots(
    current: dict[str, Any],
    previous: dict[str, Any] | None,
    *,
    value: str = "",
    previous_case_id: str | None = None,
    previous_at: datetime | None = None,
) -> IndicatorDiff:
    """Compare two snapshots. `previous` is None the first time an IOC is seen."""
    d = IndicatorDiff(value=value)
    d.current_score = int(current.get("score") or 0)
    d.current_verdict = str(current.get("verdict") or "informational")

    if previous is None:
        d.first_seen = True
        d.summary = _summarise(d)
        return d

    d.previous_case_id = previous_case_id
    d.previous_at = previous_at
    d.previous_score = int(previous.get("score") or 0)
    d.previous_verdict = str(previous.get("verdict") or "informational")
    d.score_delta = d.current_score - d.previous_score

    d.verdict_changed = d.current_verdict != d.previous_verdict
    if d.verdict_changed:
        now, before = _rank(d.current_verdict), _rank(d.previous_verdict)
        if now is not None and before is not None:
            d.escalated = now > before
            d.de_escalated = now < before

    was = set(previous.get("answering") or [])
    now_answering = set(current.get("answering") or [])
    d.sources_added = sorted(now_answering - was)
    d.sources_removed = sorted(was - now_answering)

    d.new_malware_families = sorted(
        set(current.get("malware_families") or []) - set(previous.get("malware_families") or [])
    )
    d.new_attack_ids = sorted(
        set(current.get("attack_ids") or []) - set(previous.get("attack_ids") or [])
    )

    d.summary = _summarise(d)
    return d


async def previous_result(
    session: AsyncSession, value: str, *, exclude_case_id: str | None = None
) -> IndicatorResult | None:
    """The most recent stored result for this indicator, before the current case."""
    stmt = (
        select(IndicatorResult)
        .where(IndicatorResult.value == value)
        .order_by(IndicatorResult.created_at.desc(), IndicatorResult.id.desc())
        .limit(1)
    )
    if exclude_case_id:
        stmt = stmt.where(IndicatorResult.case_id != exclude_case_id)
    return (await session.execute(stmt)).scalars().first()


async def diff_for_indicator(
    session: AsyncSession,
    value: str,
    current_payload: dict[str, Any],
    *,
    exclude_case_id: str | None = None,
) -> IndicatorDiff:
    previous = await previous_result(session, value, exclude_case_id=exclude_case_id)
    if previous is None:
        return diff_snapshots(snapshot_from_payload(current_payload), None, value=value)
    before = snapshot_from_payload(previous.payload or {})
    # The columns are authoritative over the payload blob for these two.
    before["score"] = previous.score
    before["verdict"] = previous.verdict
    if previous.malware_families:
        before["malware_families"] = sorted({str(m) for m in previous.malware_families})
    if previous.attack_ids:
        before["attack_ids"] = sorted({str(a) for a in previous.attack_ids})
    return diff_snapshots(
        snapshot_from_payload(current_payload),
        before,
        value=value,
        previous_case_id=previous.case_id,
        previous_at=previous.created_at,
    )
