"""Triage endpoints — the core of the workbench."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..ioc import Indicator, classify, extract, summarise
from ..reporting import to_markdown, to_ticket_json
from ..schemas import ExtractRequest, ExtractResponse, TriageRequest, TriageResponse
from ..services.history import diff_for_indicator
from ..services.triage import persist_case, triage

logger = logging.getLogger(__name__)
router = APIRouter(tags=["triage"])


async def _diffs_for(
    session: AsyncSession, body: dict, *, exclude_case_id: str | None = None
) -> list[dict]:
    """One diff per indicator, in the same order the response lists them."""
    return [
        (
            await diff_for_indicator(
                session, item["value"], item, exclude_case_id=exclude_case_id
            )
        ).as_dict()
        for item in body.get("indicators", [])
    ]


def _indicators_from_request(payload: TriageRequest) -> list[Indicator]:
    limit = min(payload.limit or settings.max_iocs_per_request, settings.max_iocs_per_request)
    if payload.indicators:
        indicators: list[Indicator] = []
        for raw in payload.indicators:
            raw = raw.strip()
            if not raw:
                continue
            ioc_type = classify(raw)
            if ioc_type is None:
                # Fall back to the extractor: the analyst may have pasted a line.
                indicators.extend(extract(raw))
            else:
                value = raw if ioc_type in ("url", "cve") else raw.lower()
                indicators.append(Indicator(value=value, type=ioc_type, original=raw))
        deduped: dict[str, Indicator] = {}
        for indicator in indicators:
            deduped.setdefault(indicator.value, indicator)
        return list(deduped.values())[:limit]
    if payload.text:
        return extract(payload.text, limit=limit)
    raise HTTPException(status_code=422, detail="provide either `text` or `indicators`")


@router.post("/extract", response_model=ExtractResponse)
async def extract_endpoint(payload: ExtractRequest) -> ExtractResponse:
    """Parse-only: what would be triaged, without spending a single API call."""
    indicators = extract(payload.text, limit=payload.limit or settings.max_iocs_per_request)
    return ExtractResponse(
        count=len(indicators),
        counts_by_type=summarise(indicators),
        indicators=[i.as_dict() for i in indicators],  # type: ignore[arg-type]
    )


@router.post("/triage", response_model=TriageResponse)
async def triage_endpoint(
    payload: TriageRequest, session: AsyncSession = Depends(get_session)
) -> TriageResponse:
    indicators = _indicators_from_request(payload)
    if not indicators:
        raise HTTPException(status_code=422, detail="no usable indicators found in the input")

    outcome = await triage(
        indicators,
        title=payload.title,
        use_cache=payload.use_cache,
        analyst=payload.analyst,
    )
    persisted = False
    body = outcome.as_dict()
    # Read the history BEFORE this case joins it, or every indicator diffs
    # against itself and reports no change.
    diffs = await _diffs_for(session, body, exclude_case_id=outcome.case_id)
    if payload.persist:
        await persist_case(
            session,
            outcome,
            raw_input=payload.text,
            source="paste" if payload.text else "api",
            analyst=payload.analyst,
        )
        persisted = True

    return TriageResponse(**body, persisted=persisted, diffs=diffs)


@router.post("/triage/upload", response_model=TriageResponse)
async def triage_upload(
    file: UploadFile = File(...),
    title: str = Form("Uploaded log triage"),
    analyst: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
) -> TriageResponse:
    """Accepts .txt/.log/.csv/.json (including evtx-converted JSON) up to 5 MB."""
    raw = await file.read(settings.max_upload_bytes + 1)
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"file exceeds {settings.max_upload_bytes // (1024 * 1024)} MB limit",
        )
    text = raw.decode("utf-8", errors="ignore")
    indicators = extract(text, limit=settings.max_iocs_per_request)
    if not indicators:
        raise HTTPException(status_code=422, detail="no indicators found in the uploaded file")

    outcome = await triage(indicators, title=f"{title} — {file.filename}", analyst=analyst)
    await persist_case(session, outcome, raw_input=text[:20_000], source="upload", analyst=analyst)
    return TriageResponse(**outcome.as_dict(), persisted=True)


@router.post("/triage/report")
async def triage_report(
    payload: TriageRequest,
    fmt: str = Query("markdown", pattern="^(markdown|json)$"),
    session: AsyncSession = Depends(get_session),
):
    """Triage and return a ready-to-paste SOC ticket in one call."""
    indicators = _indicators_from_request(payload)
    if not indicators:
        raise HTTPException(status_code=422, detail="no usable indicators found in the input")
    outcome = await triage(
        indicators, title=payload.title, use_cache=payload.use_cache, analyst=payload.analyst
    )
    if payload.persist:
        await persist_case(
            session, outcome, raw_input=payload.text, source="report", analyst=payload.analyst
        )

    if fmt == "json":
        return to_ticket_json(
            outcome.case_id,
            outcome.title,
            outcome.verdicts,
            outcome.verdict,
            outcome.score,
            analyst=payload.analyst,
        )
    markdown = to_markdown(
        outcome.case_id,
        outcome.title,
        outcome.verdicts,
        outcome.verdict,
        outcome.score,
        analyst=payload.analyst,
        duration_ms=outcome.duration_ms,
    )
    return PlainTextResponse(markdown, media_type="text/markdown")
