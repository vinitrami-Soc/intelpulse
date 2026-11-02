"""Scoped getters: every read of one workspace row by its id goes through here.

A row of another workspace is answered exactly like a row that does not exist
(404, same message), so a guessed id reveals nothing.
"""
from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import ApiToken, Case, ListEntry
from .auth import Actor


async def _one(db: AsyncSession, model, key, actor: Actor, what: str):
    row = await db.get(model, key)
    if row is None or row.workspace_id != actor.workspace_id:
        raise HTTPException(status_code=404, detail=f"{what} not found")
    return row


async def case_in(db: AsyncSession, actor: Actor, case_id: str) -> Case:
    return await _one(db, Case, case_id, actor, "case")


async def list_entry_in(db: AsyncSession, actor: Actor, entry_id: int) -> ListEntry:
    return await _one(db, ListEntry, entry_id, actor, "entry")


async def token_in(db: AsyncSession, actor: Actor, token_id: int) -> ApiToken:
    return await _one(db, ApiToken, token_id, actor, "token")
