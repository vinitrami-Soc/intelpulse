"""Analyst allow/block lists — local knowledge beats vendor opinion."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import AuditLog, ListEntry
from ..schemas import ListEntryIn, ListEntryOut

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
    payload: ListEntryIn, session: AsyncSession = Depends(get_session)
) -> ListEntryOut:
    value = payload.value.strip().lower()
    if not value:
        raise HTTPException(status_code=422, detail="value is required")
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
        ioc_type=payload.ioc_type,
        list_type=payload.list_type,
        reason=payload.reason,
        created_by=payload.created_by,
    )
    session.add(entry)
    session.add(
        AuditLog(
            action=f"list.{payload.list_type}.added",
            actor=payload.created_by or "anonymous",
            target=value,
            detail={"reason": payload.reason},
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
async def delete_list_entry(entry_id: int, session: AsyncSession = Depends(get_session)) -> None:
    entry = await session.get(ListEntry, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="entry not found")
    await session.execute(delete(ListEntry).where(ListEntry.id == entry_id))
    session.add(
        AuditLog(action="list.removed", actor="anonymous", target=entry.value, detail={})
    )
