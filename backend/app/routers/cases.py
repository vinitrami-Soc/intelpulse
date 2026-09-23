"""Case history, audit trail and report regeneration from stored results."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..ioc import Indicator
from ..models import AuditLog, Case, IndicatorResult
from ..reporting import to_markdown, to_ticket_json
from ..schemas import CaseSummary
from ..scoring import Contribution, IndicatorVerdict
from ..security import principal
from ..services.tickets import TicketError, create_ticket

router = APIRouter(tags=["cases"])


def _rehydrate(results: list[IndicatorResult]) -> list[IndicatorVerdict]:
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


@router.get("/cases", response_model=list[CaseSummary])
async def list_cases(
    limit: int = Query(25, ge=1, le=200),
    # bounded: an offset past SQLite's 64-bit integer was a 500 (found by schema fuzzing)
    offset: int = Query(0, ge=0, le=2**63 - 1),
    verdict: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> list[CaseSummary]:
    query = select(Case).order_by(Case.created_at.desc()).limit(limit).offset(offset)
    if verdict:
        query = query.where(Case.verdict == verdict)
    rows = (await session.execute(query)).scalars().all()
    return [
        CaseSummary(
            id=row.id,
            title=row.title,
            verdict=row.verdict,
            max_score=row.max_score,
            indicator_count=row.indicator_count,
            source=row.source,
            analyst=row.analyst,
            duration_ms=row.duration_ms,
            created_at=row.created_at.isoformat() if row.created_at else "",
        )
        for row in rows
    ]


@router.get("/cases/{case_id}")
async def get_case(case_id: str, session: AsyncSession = Depends(get_session)) -> dict:
    case = await session.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    rows = (
        await session.execute(
            select(IndicatorResult)
            .where(IndicatorResult.case_id == case_id)
            .order_by(IndicatorResult.score.desc())
        )
    ).scalars().all()
    return {
        "case_id": case.id,
        "title": case.title,
        "verdict": case.verdict,
        "score": case.max_score,
        "source": case.source,
        "analyst": case.analyst,
        "duration_ms": case.duration_ms,
        "created_at": case.created_at.isoformat() if case.created_at else None,
        "raw_input": case.raw_input,
        "indicator_count": case.indicator_count,
        "indicators": [row.payload for row in rows],
    }


@router.get("/cases/{case_id}/report")
async def case_report(
    case_id: str,
    fmt: str = Query("markdown", pattern="^(markdown|json)$"),
    session: AsyncSession = Depends(get_session),
):
    case = await session.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    rows = (
        await session.execute(select(IndicatorResult).where(IndicatorResult.case_id == case_id))
    ).scalars().all()
    verdicts = _rehydrate(list(rows))

    if fmt == "json":
        return to_ticket_json(case.id, case.title, verdicts, case.verdict, case.max_score, analyst=case.analyst)
    markdown = to_markdown(
        case.id,
        case.title,
        verdicts,
        case.verdict,
        case.max_score,
        analyst=case.analyst,
        duration_ms=case.duration_ms,
    )
    return PlainTextResponse(markdown, media_type="text/markdown")


@router.post("/cases/{case_id}/ticket")
async def raise_ticket(
    case_id: str,
    request: Request,
    sink: str = Query(..., pattern="^(jira|servicenow)$"),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Create this case as an issue in the tracker the SOC works in.

    Downloading Markdown and pasting it by hand is the step that gets skipped,
    so the report the download route renders is the report that goes over the
    wire — same function, same arguments, no second rendering to drift.
    """
    case = await session.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    rows = (
        await session.execute(select(IndicatorResult).where(IndicatorResult.case_id == case_id))
    ).scalars().all()
    verdicts = _rehydrate(list(rows))
    body = to_markdown(
        case.id,
        case.title,
        verdicts,
        case.verdict,
        case.max_score,
        analyst=case.analyst,
        duration_ms=case.duration_ms,
    )
    meta = {
        "case_id": case.id,
        "title": case.title,
        "verdict": case.verdict,
        "score": case.max_score,
        "indicators": [{"value": r.value} for r in rows],
    }
    try:
        ticket = await create_ticket(meta, body, sink)
    except TicketError as exc:
        # 409 when the sink is simply not configured, 502 when it refused us.
        raise HTTPException(status_code=exc.status or 502, detail=str(exc)) from exc

    session.add(
        AuditLog(
            action="ticket.created",
            actor=principal(request),
            target=case.id,
            detail={"sink": ticket.sink, "key": ticket.key, "url": ticket.url},
        )
    )
    await session.commit()
    return ticket.as_dict()


@router.delete("/cases/{case_id}", status_code=204)
async def delete_case(case_id: str, request: Request, session: AsyncSession = Depends(get_session)) -> None:
    case = await session.get(Case, case_id)
    if case is None:
        raise HTTPException(status_code=404, detail="case not found")
    await session.execute(delete(Case).where(Case.id == case_id))
    session.add(AuditLog(action="case.deleted", actor=principal(request), target=case_id, detail={}))


@router.get("/stats")
async def stats(session: AsyncSession = Depends(get_session)) -> dict:
    """Numbers for the dashboard header."""
    total = (await session.execute(select(func.count(Case.id)))).scalar_one()
    indicators = (await session.execute(select(func.count(IndicatorResult.id)))).scalar_one()
    by_verdict = dict(
        (await session.execute(select(Case.verdict, func.count(Case.id)).group_by(Case.verdict))).all()
    )
    top_families_rows = (
        await session.execute(
            select(IndicatorResult.malware_families).where(IndicatorResult.score >= 40).limit(500)
        )
    ).scalars().all()
    families: dict[str, int] = {}
    for entry in top_families_rows:
        for family in entry or []:
            families[family] = families.get(family, 0) + 1
    return {
        "cases": total,
        "indicators": indicators,
        "cases_by_verdict": by_verdict,
        "top_malware_families": sorted(families.items(), key=lambda kv: kv[1], reverse=True)[:8],
    }


@router.get("/audit")
async def audit(
    limit: int = Query(50, ge=1, le=500), session: AsyncSession = Depends(get_session)
) -> list[dict]:
    rows = (
        await session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit))
    ).scalars().all()
    return [
        {
            "id": row.id,
            "action": row.action,
            "actor": row.actor,
            "target": row.target,
            "detail": row.detail,
            "created_at": row.created_at.isoformat() if row.created_at else None,
        }
        for row in rows
    ]
