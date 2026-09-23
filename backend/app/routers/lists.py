"""Analyst allow/block lists — local knowledge beats vendor opinion."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..ioc import classify, refang
from ..models import AuditLog, ListEntry
from ..schemas import ListEntryIn, ListEntryOut
from ..security import principal
from ..text import clean_label

router = APIRouter(tags=["lists"])


@router.get("/lists", response_model=list[ListEntryOut])
async def get_lists(
    list_type: str | None = Query(None, pattern="^(allow|block)$"),
    session: AsyncSession = Depends(get_session),
) -> list[ListEntryOut]:
    query = select(ListEntry).order_by(ListEntry.created_at.desc())
    if list_type:
        query = query.where(ListEntry.list_type == list_type)
    rows = (await session.execute(query)).scalars().all()
    return [
        ListEntryOut(
            id=row.id,
            value=row.value,
            ioc_type=row.ioc_type,
            list_type=row.list_type,  # type: ignore[arg-type]
            reason=row.reason,
            created_by=row.created_by,
            created_at=row.created_at.isoformat() if row.created_at else "",
        )
        for row in rows
    ]


@router.post("/lists", response_model=ListEntryOut, status_code=201)
async def add_list_entry(
    payload: ListEntryIn, request: Request, session: AsyncSession = Depends(get_session)
) -> ListEntryOut:
    """An override that changes verdicts, so what goes in is checked.

    This used to store whatever it was given: a value with a CRLF and ten
    thousand characters went in, and so did an ioc_type of "<script>". Now the
    value must be one indicator the extractor itself would recognise, its type
    is the one the server works out, and the reason is one clean line.
    """
    raw = payload.value.strip()
    if not raw:
        raise HTTPException(status_code=422, detail="value is required")
    candidate = refang(raw).strip()
    ioc_type = classify(candidate)
    if ioc_type is None:
        raise HTTPException(
            status_code=422,
            detail="value must be a single routable IP, domain, URL, hash, email or CVE",
        )
    value = candidate if ioc_type == "url" else candidate.lower()
    reason = clean_label(payload.reason, 300)
    claimed = clean_label(payload.created_by, 120) if payload.created_by else None
    existing = (
        await session.execute(
            select(ListEntry).where(
                ListEntry.value == value, ListEntry.list_type == payload.list_type
            )
        )
    ).scalars().first()
    if existing:
        raise HTTPException(status_code=409, detail="entry already exists")

    entry = ListEntry(
        value=value,
        ioc_type=ioc_type,
        list_type=payload.list_type,
        reason=reason,
        created_by=claimed,
    )
    session.add(entry)
    session.add(
        AuditLog(
            action=f"list.{payload.list_type}.added",
            actor=principal(request),
            target=value,
            detail={"reason": reason, "claimed_by": claimed},
        )
    )
    await session.flush()
    return ListEntryOut(
        id=entry.id,
        value=entry.value,
        ioc_type=entry.ioc_type,
        list_type=entry.list_type,  # type: ignore[arg-type]
        reason=entry.reason,
        created_by=entry.created_by,
        created_at=entry.created_at.isoformat() if entry.created_at else "",
    )


@router.delete("/lists/{entry_id}", status_code=204)
async def delete_list_entry(
    request: Request,
    # bounded: a 26-digit id overflowed SQLite's integer and came back as a 500
    entry_id: int = Path(..., ge=1, le=2**63 - 1),
    session: AsyncSession = Depends(get_session),
) -> None:
    entry = await session.get(ListEntry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="entry not found")
    await session.execute(delete(ListEntry).where(ListEntry.id == entry_id))
    session.add(
        AuditLog(action="list.removed", actor=principal(request), target=entry.value, detail={})
    )
