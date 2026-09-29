"""Rebuilding a stored case's ticket, the same way for every route that needs one.

The download route, the tracker route and the webhook all render a stored case.
They share this module so the three can never describe one case differently.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..ioc import Indicator
from ..models import Case, IndicatorResult, PushedAlert
from ..reporting import ticket_level, to_markdown, to_ticket_json
from ..scoring import Contribution, IndicatorVerdict


def rehydrate(results: list[IndicatorResult]) -> list[IndicatorVerdict]:
    """Rebuild verdict objects from stored JSON so reports stay reproducible."""
    verdicts: list[IndicatorVerdict] = []
    for row in results:
        payload = row.payload or {}
        verdicts.append(
            IndicatorVerdict(
                indicator=Indicator(value=row.value, type=row.ioc_type),
                score=row.score,
                verdict=row.verdict,
                confidence=row.confidence,
                contributions=[
                    Contribution(
                        provider=e.get("provider", "?"),
                        signal=float(e.get("signal", 0)),
                        weight=float(e.get("weight", 0)),
                        weighted=float(e.get("weighted", 0)),
                        authority=0.0,
                        rationale=e.get("rationale", ""),
                    )
                    for e in payload.get("evidence", [])
                ],
                modifiers=payload.get("modifiers", []),
                tags=payload.get("tags", []),
                malware_families=row.malware_families or [],
                attack_techniques=payload.get("attack_techniques", []),
                providers_queried=payload.get("providers_queried", 0),
                providers_answered=payload.get("providers_answered", 0),
            )
        )
    return verdicts


async def alert_for(session: AsyncSession, case_id: str) -> dict[str, Any] | None:
    """The alert a SIEM pushed for this case, or None for a case an analyst started."""
    row = (
        await session.execute(select(PushedAlert).where(PushedAlert.case_id == case_id))
    ).scalar_one_or_none()
    return row.payload if row else None


async def _stored(session: AsyncSession, case: Case) -> tuple[list[IndicatorResult], dict[str, Any] | None]:
    rows = (
        await session.execute(select(IndicatorResult).where(IndicatorResult.case_id == case.id))
    ).scalars().all()
    return list(rows), await alert_for(session, case.id)


async def case_markdown(session: AsyncSession, case: Case) -> tuple[str, dict[str, Any]]:
    """The case's Markdown ticket, and the metadata a tracker needs to file it."""
    rows, alert = await _stored(session, case)
    body = to_markdown(
        case.id,
        case.title,
        rehydrate(rows),
        case.verdict,
        case.max_score,
        analyst=case.analyst,
        duration_ms=case.duration_ms,
        alert=alert,
    )
    meta = {
        "case_id": case.id,
        "title": case.title,
        # A pushed critical alert whose indicators no source knows is still filed as critical.
        "verdict": ticket_level(case.verdict, alert),
        "score": case.max_score,
        "indicators": [{"value": r.value} for r in rows],
    }
    return body, meta


async def case_json(session: AsyncSession, case: Case) -> dict[str, Any]:
    rows, alert = await _stored(session, case)
    return to_ticket_json(
        case.id, case.title, rehydrate(rows), case.verdict, case.max_score, analyst=case.analyst, alert=alert
    )
