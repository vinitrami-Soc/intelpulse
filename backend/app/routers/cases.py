"""Case history, audit trail and report regeneration from stored results."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import delete, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import SERVER, AuditLog, Case, CaseInput, IndicatorResult, PushedAlert, User
from ..platform import audit, scope
from ..platform.auth import Actor
from ..platform.box import server_box
from ..platform.deps import require_actor, require_admin, require_member, require_session_admin
from ..platform.errors import ApiError
from ..schemas import CaseSummary, CaseUpdate
from ..services import case_inputs, retention, views, workflow
from ..services import workspace_settings as ws_settings
from ..services.reports import alert_for, case_json, case_markdown
from ..services.tickets import TicketError, create_ticket

router = APIRouter(tags=["cases"])


@router.get("/cases", response_model=list[CaseSummary])
async def list_cases(
    limit: int = Query(25, ge=1, le=200),
    # bounded: an offset past SQLite's 64-bit integer was a 500 (found by schema fuzzing)
    offset: int = Query(0, ge=0, le=2**63 - 1),
    verdict: str | None = Query(None, max_length=20),
    q: str | None = Query(None, max_length=200, description="words in the title, or part of an indicator"),
    status: Literal["new", "in_progress", "closed", "open"] | None = Query(
        None, description="`open` is new or in progress"),
    source: str | None = Query(None, max_length=40),
    assignee: str | None = Query(None, pattern=r"^(me|none|[1-9][0-9]{0,18})$",
                                 description="`me`, `none`, or a member's id"),
    since: datetime | None = None,
    until: datetime | None = None,
    actor: Actor = Depends(require_actor),
    session: AsyncSession = Depends(get_session),
) -> list[CaseSummary]:
    """The workspace's cases, newest first, searched and filtered."""
    query = select(Case).where(Case.workspace_id == actor.workspace_id)
    if verdict:
        query = query.where(Case.verdict == verdict)
    if status == "open":
        query = query.where(Case.status != "closed")
    elif status:
        query = query.where(Case.status == status)
    if source:
        query = query.where(Case.source == source)
    if assignee == "me":
        query = query.where(Case.assignee_id == actor.user_id) if actor.user_id else query.where(False)
    elif assignee == "none":
        query = query.where(Case.assignee_id.is_(None))
    elif assignee:
        query = query.where(Case.assignee_id == int(assignee))
    if since:
        query = query.where(Case.created_at >= since)
    if until:
        query = query.where(Case.created_at < until)
    text = (q or "").strip().lower()
    if text:
        query = query.where(or_(
            func.lower(Case.title).contains(text, autoescape=True),
            exists().where(IndicatorResult.case_id == Case.id,
                           func.lower(IndicatorResult.value).contains(text, autoescape=True)),
        ))
    rows = (
        await session.execute(query.order_by(Case.created_at.desc()).limit(limit).offset(offset))
    ).scalars().all()
    assignees = {row.assignee_id for row in rows if row.assignee_id}
    people = {
        user.id: user for user in (
            await session.execute(select(User).where(User.id.in_(assignees)))
        ).scalars()
    } if assignees else {}
    tickets = await workflow.ticket_counts(session, [row.id for row in rows])
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
            status=row.status,
            assignee=workflow.person(people.get(row.assignee_id)),
            closed_reason=row.closed_reason,
            closed_at=workflow.iso(row.closed_at),
            ticket_count=tickets.get(row.id, 0),
            held=row.held,
            input_deleted_at=workflow.iso(row.input_deleted_at),
            created_by=row.created_by,
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
        # tier 1: the paste for its own analyst or an admin; null once deleted
        "raw_input": ((await case_inputs.read(session, case.id)) or {}).get("raw_input")
        if case_inputs.may_read_raw(actor, case) else None,
        "input_deleted_at": workflow.iso(case.input_deleted_at),
        "held": case.held,
        "created_by": case.created_by,
        "indicator_count": case.indicator_count,
        "indicators": [row.payload for row in rows],
        # What a SIEM pushed, when the case came in through /api/alerts; otherwise null.
        "alert": await alert_for(session, case.id),
        **await _workflow_of(session, case),
    }


async def _workflow_of(session: AsyncSession, case: Case) -> dict:
    assignee = await session.get(User, case.assignee_id) if case.assignee_id else None
    return {
        "status": case.status,
        "assignee": workflow.person(assignee),
        "closed_reason": case.closed_reason,
        "closed_at": workflow.iso(case.closed_at),
        "tickets": await workflow.tickets_for(session, case.id),
    }


@router.patch("/cases/{case_id}")
async def update_case(
    case_id: str,
    body: CaseUpdate,
    actor: Actor = Depends(require_member),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Move a case along: its status, its assignee, and the reason it was closed."""
    case = await scope.case_in(session, actor, case_id)
    changes = body.model_dump(include=body.model_fields_set)
    if not changes:
        raise ApiError(422, "invalid", "nothing to change: send status, assignee_id or closed_reason")
    changed = await workflow.update_case(session, actor, case, changes)
    return {"case_id": case.id, "changed": sorted(changed), **await _workflow_of(session, case)}


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
    config = await ws_settings.sink_config(session, server_box(), actor.workspace_id)
    try:
        ticket = await create_ticket(meta, body, sink, config)
    except TicketError as exc:
        # 409 when the sink is simply not configured, 502 when it refused us.
        raise HTTPException(status_code=exc.status or 502, detail=str(exc)) from exc

    await workflow.record_ticket(session, actor, case, ticket)
    await session.commit()
    return ticket.as_dict()


@router.delete("/cases/{case_id}", status_code=204)
async def delete_case(
    case_id: str, actor: Actor = Depends(require_admin), session: AsyncSession = Depends(get_session)
) -> None:
    await scope.case_in(session, actor, case_id)
    kept = await session.get(CaseInput, case_id)
    # SQLite does not enforce the foreign keys here, so the pushed alert goes by hand: left
    # behind, it would make a re-push of the same alert point at a case that is gone.
    await session.execute(delete(PushedAlert).where(PushedAlert.case_id == case_id))
    await session.execute(delete(CaseInput).where(CaseInput.case_id == case_id))
    await session.execute(delete(Case).where(Case.id == case_id))
    # the case can still be named: its ID, and the SHA-256 of the input it had
    await audit.record(session, action="case.deleted", actor=actor.label, workspace_id=actor.workspace_id,
                       target=case_id, detail={"input_sha256": kept.sha256 if kept else None})


@router.delete("/cases/{case_id}/input", status_code=204)
async def delete_case_input(
    case_id: str, actor: Actor = Depends(require_member), session: AsyncSession = Depends(get_session)
) -> None:
    """Delete a case's tier 1 now: an analyst their own cases', an admin any. The verdict, the
    indicators and the workflow stay. A held case keeps its input until it is released."""
    case = await scope.case_in(session, actor, case_id)
    if not (actor.is_admin or (case.created_by is not None and case.created_by == actor.user_id)):
        raise ApiError(403, "forbidden", "only the analyst who made this case, or an admin, deletes its input")
    if case.held:
        raise ApiError(409, "held", "this case is held: an admin releases it first")
    if await retention.delete_input(session, case, actor=actor.label) is None:
        raise ApiError(404, "not_found", "this case has no input to delete")


@router.post("/cases/{case_id}/hold")
async def hold_case(case_id: str, actor: Actor = Depends(require_session_admin),
                    session: AsyncSession = Depends(get_session)) -> dict:
    """Keep this case's input past the retention days, until it is released."""
    return await _set_hold(session, actor, case_id, True)


@router.delete("/cases/{case_id}/hold")
async def release_case(case_id: str, actor: Actor = Depends(require_session_admin),
                       session: AsyncSession = Depends(get_session)) -> dict:
    return await _set_hold(session, actor, case_id, False)


async def _set_hold(session: AsyncSession, actor: Actor, case_id: str, held: bool) -> dict:
    case = await scope.case_in(session, actor, case_id)
    if case.held != held:
        case.held = held
        await audit.record(session, action="case.held" if held else "case.released", actor=actor.label,
                           workspace_id=actor.workspace_id, target=case.id)
    return {"case_id": case.id, "held": case.held, "input_deleted_at": workflow.iso(case.input_deleted_at)}


@router.get("/stats")
async def stats(
    days: int = Query(90, ge=1, le=365, description="how many days the trend covers"),
    actor: Actor = Depends(require_actor),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Numbers for the overview, for the caller's workspace: each verdict band by status,
    cases opened and closed per day, and how long closing a case takes."""
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
        **await views.overview(session, ws, user_id=actor.user_id, days=days),
    }


@router.get("/audit")
async def audit_log(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0, le=2**63 - 1),
    action: str | None = Query(None, max_length=80, description="an action, or its start: `case.` for every case action"),
    by: str | None = Query(None, max_length=120, description="who acted: a username, `token:<name>` or `api-token`"),
    since: datetime | None = None,
    until: datetime | None = None,
    actor: Actor = Depends(require_actor),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    """An analyst sees their own actions, an admin (or a token) the whole workspace, the
    owner the server's records too (setup, feed refreshes, failed sign-ins)."""
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit).offset(offset)
    if actor.via == "session" and actor.owner:
        query = query.where(or_(AuditLog.workspace_id == actor.workspace_id, AuditLog.workspace_id == SERVER))
    else:
        query = query.where(AuditLog.workspace_id == actor.workspace_id)
    if actor.via == "session" and not actor.is_admin:
        query = query.where(AuditLog.actor == actor.label)
    if action:
        query = query.where(AuditLog.action.startswith(action, autoescape=True))
    if by:
        query = query.where(AuditLog.actor == by)
    if since:
        query = query.where(AuditLog.created_at >= since)
    if until:
        query = query.where(AuditLog.created_at < until)
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


@router.get("/audit/verify")
async def verify_audit(actor: Actor = Depends(require_admin), session: AsyncSession = Depends(get_session)) -> dict:
    """Recompute the hash chain. The chain is the whole server's, so only its owner (or the
    1.x token) is told which records are wrong; another admin learns whether it holds."""
    problems = await audit.verify(session)
    count = (await session.execute(select(func.count(AuditLog.id)))).scalar_one()
    answer = {"intact": not problems, "records": count, "problems": len(problems)}
    if actor.owner or actor.via == "legacy":
        answer["details"] = problems[:100]
    await audit.record(session, action="audit.verified", actor=actor.label, workspace_id=actor.workspace_id,
                       detail={"intact": not problems})
    return answer

