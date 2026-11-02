"""Case history, audit trail and report regeneration from stored results."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import SERVER, AuditLog, Case, IndicatorResult, PushedAlert
from ..platform import audit, scope
from ..platform.auth import Actor
from ..platform.deps import require_actor, require_admin
from ..schemas import CaseSummary
from ..services.reports import alert_for, case_json, case_markdown
from ..services.tickets import TicketError, create_ticket

router = APIRouter(tags=["cases"])


@router.get("/cases", response_model=list[CaseSummary])
async def list_cases(
    limit: int = Query(25, ge=1, le=200),
    # bounded: an offset past SQLite's 64-bit integer was a 500 (found by schema fuzzing)
    offset: int = Query(0, ge=0, le=2**63 - 1),
    verdict: str | None = None,
    actor: Actor = Depends(require_actor),
    session: AsyncSession = Depends(get_session),
) -> list[CaseSummary]:
    query = (
        select(Case).where(Case.workspace_id == actor.workspace_id)
        .order_by(Case.created_at.desc()).limit(limit).offset(offset)
    )
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
async def get_case(
    case_id: str, actor: Actor = Depends(require_actor), session: AsyncSession = Depends(get_session)
) -> dict:
    case = await scope.case_in(session, actor, case_id)
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
        # What a SIEM pushed, when the case came in through /api/alerts; otherwise null.
        "alert": await alert_for(session, case.id),
    }


@router.get("/cases/{case_id}/report")
async def case_report(
    case_id: str,
    fmt: str = Query("markdown", pattern="^(markdown|json)$"),
    actor: Actor = Depends(require_actor),
    session: AsyncSession = Depends(get_session),
):
    case = await scope.case_in(session, actor, case_id)
    if fmt == "json":
        return await case_json(session, case)
    markdown, _ = await case_markdown(session, case)
    return PlainTextResponse(markdown, media_type="text/markdown")


@router.post("/cases/{case_id}/ticket")
async def raise_ticket(
    case_id: str,
    sink: str = Query(..., pattern="^(jira|servicenow)$"),
    actor: Actor = Depends(require_actor),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Create this case as an issue in the tracker the SOC works in.

    Downloading Markdown and pasting it by hand is the step that gets skipped,
    so the report the download route renders is the report that goes over the
    wire — same function, same arguments, no second rendering to drift.
    """
    case = await scope.case_in(session, actor, case_id)
    body, meta = await case_markdown(session, case)
    try:
        ticket = await create_ticket(meta, body, sink)
    except TicketError as exc:
        # 409 when the sink is simply not configured, 502 when it refused us.
        raise HTTPException(status_code=exc.status or 502, detail=str(exc)) from exc

    await audit.record(
        session,
        action="ticket.created",
        actor=actor.label,
        workspace_id=actor.workspace_id,
        target=case.id,
        detail={"sink": ticket.sink, "key": ticket.key, "url": ticket.url},
    )
    await session.commit()
    return ticket.as_dict()


@router.delete("/cases/{case_id}", status_code=204)
async def delete_case(
    case_id: str, actor: Actor = Depends(require_admin), session: AsyncSession = Depends(get_session)
) -> None:
    await scope.case_in(session, actor, case_id)
    # SQLite does not enforce the foreign keys here, so the pushed alert goes by hand: left
    # behind, it would make a re-push of the same alert point at a case that is gone.
    await session.execute(delete(PushedAlert).where(PushedAlert.case_id == case_id))
    await session.execute(delete(Case).where(Case.id == case_id))
    await audit.record(session, action="case.deleted", actor=actor.label,
                       workspace_id=actor.workspace_id, target=case_id)


@router.get("/stats")
async def stats(actor: Actor = Depends(require_actor), session: AsyncSession = Depends(get_session)) -> dict:
    """Numbers for the dashboard header, for the caller's workspace."""
    ws = actor.workspace_id
    total = (await session.execute(select(func.count(Case.id)).where(Case.workspace_id == ws))).scalar_one()
    indicators = (
        await session.execute(select(func.count(IndicatorResult.id)).where(IndicatorResult.workspace_id == ws))
    ).scalar_one()
    by_verdict = dict(
        (
            await session.execute(
                select(Case.verdict, func.count(Case.id)).where(Case.workspace_id == ws).group_by(Case.verdict)
            )
        ).all()
    )
    top_families_rows = (
        await session.execute(
            select(IndicatorResult.malware_families)
            .where(IndicatorResult.workspace_id == ws, IndicatorResult.score >= 40)
            .limit(500)
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
async def audit_log(
    limit: int = Query(50, ge=1, le=500),
    actor: Actor = Depends(require_actor),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    """An analyst sees their own actions, an admin (or a token) the whole workspace, the
    owner the server's records too (setup, feed refreshes, failed sign-ins)."""
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if actor.via == "session" and actor.owner:
        query = query.where(or_(AuditLog.workspace_id == actor.workspace_id, AuditLog.workspace_id == SERVER))
    else:
        query = query.where(AuditLog.workspace_id == actor.workspace_id)
    if actor.via == "session" and not actor.is_admin:
        query = query.where(AuditLog.actor == actor.label)
    rows = (await session.execute(query)).scalars().all()
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
