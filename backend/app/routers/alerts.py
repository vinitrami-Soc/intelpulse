"""Webhook ingestion: a SIEM pushes an alert, and it is triaged into a case.

The alert brings two things. Its own account of what happened (which host,
which account, which techniques, the events behind it) is kept beside the case
and opens its ticket. Its indicators go through the same extraction and triage
as a paste: explicit ones first, then whatever the extractor finds in the
evidence, refanged, with private addresses and file names dropped as always.

A sender retries when it does not hear back, so `source` and `alert_id` name
the alert: a second push of the same one returns the first case without
spending any vendor quota. An alert with no enrichable indicator is still a
case, because the detection itself is what the SOC needs to see.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..ioc import Indicator, classify, extract, refang
from ..models import AuditLog, Case, PushedAlert
from ..reporting import ticket_level
from ..schemas import AlertIn, AlertOut
from ..security import principal
from ..services.reports import case_markdown
from ..services.tickets import TicketError, create_ticket
from ..services.triage import persist_case, triage

logger = logging.getLogger(__name__)
router = APIRouter(tags=["alerts"])


def _indicators(alert: AlertIn) -> list[Indicator]:
    """Explicit indicators, then those in the evidence; one of each, capped like a triage."""
    found: list[Indicator] = []
    for raw in alert.indicators:
        raw = refang(raw.strip())
        if not raw:
            continue
        ioc_type = classify(raw)
        if ioc_type is None:
            found.extend(extract(raw))  # not one indicator: perhaps a line with some in it
        else:
            found.append(Indicator(value=raw if ioc_type in ("url", "cve") else raw.lower(), type=ioc_type, original=raw))
    found.extend(extract(_evidence_text(alert)))
    unique: dict[str, Indicator] = {}
    for indicator in found:
        unique.setdefault(indicator.value, indicator)
    return list(unique.values())[: settings.max_iocs_per_request]


def _evidence_text(alert: AlertIn) -> str:
    return "\n".join([alert.description, *(item.text for item in alert.evidence)]).strip()


def _answer(case: Case, alert: dict, *, duplicate: bool, ticket=None, ticket_error=None) -> AlertOut:
    return AlertOut(
        case_id=case.id,
        duplicate=duplicate,
        alert_severity=alert["severity"],
        verdict=case.verdict,
        score=case.max_score,
        indicator_count=case.indicator_count,
        ticket_level=ticket_level(case.verdict, alert),
        report=f"/api/cases/{case.id}/report",
        ticket=ticket,
        ticket_error=ticket_error,
    )


@router.post(
    "/alerts",
    response_model=AlertOut,
    status_code=201,
    responses={
        200: {"description": "This alert was received before; its case is returned and nothing is triaged again"},
        409: {"description": "The same alert is being received by another request at this moment"},
    },
)
async def receive_alert(
    alert: AlertIn, request: Request, response: Response, session: AsyncSession = Depends(get_session)
) -> AlertOut:
    """Triage a pushed alert into a case (201), or return the case an earlier push made (200)."""
    earlier = (
        await session.execute(
            select(PushedAlert).where(PushedAlert.source == alert.source, PushedAlert.alert_id == alert.alert_id)
        )
    ).scalar_one_or_none()
    if earlier is not None:
        case = await session.get(Case, earlier.case_id)
        if case is not None:
            response.status_code = 200
            return _answer(case, earlier.payload, duplicate=True)
        await session.delete(earlier)  # its case is gone: this push starts a new one
        await session.flush()

    stored = alert.model_dump(mode="json", exclude={"ticket"})
    outcome = await triage(_indicators(alert), title=alert.title)
    case = await persist_case(
        session,
        outcome,
        raw_input=_evidence_text(alert),
        source="webhook",
        actor=principal(request),
    )
    session.add(PushedAlert(case_id=case.id, source=alert.source, alert_id=alert.alert_id,
                            severity=alert.severity, payload=stored))
    session.add(
        AuditLog(
            action="alert.received",
            actor=principal(request),
            target=case.id,
            detail={"source": alert.source, "alert_id": alert.alert_id, "severity": alert.severity,
                    "indicator_count": len(outcome.verdicts)},
        )
    )
    try:
        await session.flush()
    except IntegrityError as exc:
        # The same alert arrived twice at once, and the other push stored it first.
        raise HTTPException(status_code=409, detail="this alert is already being received; retry to get its case") from exc

    ticket = ticket_error = None
    if alert.ticket:
        body, meta = await case_markdown(session, case)
        try:
            filed = await create_ticket(meta, body, alert.ticket)
        except TicketError as exc:
            # The case is stored either way; the sender is told why the tracker said no.
            ticket_error = str(exc)
        else:
            ticket = filed.as_dict()
            session.add(AuditLog(action="ticket.created", actor=principal(request), target=case.id, detail=ticket))
    logger.info("alert received", extra={"source": alert.source, "case": case.id, "severity": alert.severity})
    return _answer(case, stored, duplicate=False, ticket=ticket, ticket_error=ticket_error)
