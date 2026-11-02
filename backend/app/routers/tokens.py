"""API tokens: an admin creates, lists and revokes the workspace's tokens.

A token's value is shown once, in the answer that creates it; only its SHA-256
is stored. Scopes: `read` (every GET), `triage` (read, plus extract and triage),
`ingest` (POST /api/alerts only, for DwellWatch or a SIEM).
"""
from __future__ import annotations

from datetime import timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Path
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import ApiToken, User, utcnow
from ..platform import audit, auth, scope
from ..platform.deps import require_session_admin
from ..platform.errors import ApiError

router = APIRouter(tags=["tokens"])


class TokenIn(BaseModel):
    name: str = Field(..., max_length=64)
    scope: Literal["read", "triage", "ingest"]
    expires_in_days: int | None = Field(None, ge=1, le=730)


def _iso(at) -> str | None:
    return at.isoformat() if at else None


def _out(row: ApiToken, created_by: str | None) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "scope": row.scope,
        "created_by": created_by,
        "created_at": _iso(row.created_at),
        "expires_at": _iso(row.expires_at),
        "last_used_at": _iso(row.last_used_at),
        "revoked_at": _iso(row.revoked_at),
    }


@router.get("/tokens")
async def list_tokens(
    actor: auth.Actor = Depends(require_session_admin), db: AsyncSession = Depends(get_session)
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(ApiToken, User.username)
            .outerjoin(User, User.id == ApiToken.created_by)
            .where(ApiToken.workspace_id == actor.workspace_id)
            .order_by(ApiToken.id.desc())
        )
    ).all()
    return [_out(row, username) for row, username in rows]


@router.post("/tokens", status_code=201)
async def create_token(
    body: TokenIn, actor: auth.Actor = Depends(require_session_admin), db: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    expires = utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None
    try:
        value, row = await auth.create_token(
            db, workspace_id=actor.workspace_id, name=body.name, scope=body.scope,
            created_by=actor.user_id, expires_at=expires,
        )
    except auth.AuthError as exc:
        raise ApiError(422, "invalid", str(exc)) from exc
    await audit.record(db, action="token.created", actor=actor.label, workspace_id=actor.workspace_id,
                       target=row.name, detail={"id": row.id, "scope": row.scope})
    return {**_out(row, actor.username), "token": value}


@router.delete("/tokens/{token_id}", status_code=204)
async def revoke_token(
    token_id: int = Path(..., ge=1, le=2**63 - 1),
    actor: auth.Actor = Depends(require_session_admin),
    db: AsyncSession = Depends(get_session),
) -> None:
    row = await scope.token_in(db, actor, token_id)
    if row.revoked_at is None:
        row.revoked_at = utcnow()
        await audit.record(db, action="token.revoked", actor=actor.label, workspace_id=actor.workspace_id,
                           target=row.name, detail={"id": row.id})
