"""Getting into IntelPulse: the owner's setup with a one-time code.

Ported from PhishHawk's ``server/accounts.py``. Sign-up, invitations and the
email flows arrive with milestone M3.

The setup code is sealed like a provider key, never logged, and printed only by
``python -m app.cli setup-code`` on the operator's own terminal: whoever enters
it first owns the server, so it must not travel in a log.
"""
from __future__ import annotations

import base64
import hmac
import re
import secrets

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import DEFAULT_WORKSPACE_ID, DEFAULT_WORKSPACE_NAME, SERVER, User, Workspace
from ..text import clean_label
from . import audit, auth
from . import settings_store as store
from .crypto import Box
from .errors import ApiError

SETUP_KEY = "setup_code"
EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]+\.[^@\s]+$")


def _new_code() -> str:
    """80 random bits as four groups of four letters and digits, easy to read out and type."""
    letters = base64.b32encode(secrets.token_bytes(10)).decode("ascii")
    return "-".join(letters[i:i + 4] for i in range(0, 16, 4))


async def needs_setup(db: AsyncSession) -> bool:
    """True while no one has an account."""
    return (await db.execute(select(User.id).limit(1))).first() is None


async def setup_code(db: AsyncSession, box: Box) -> str | None:
    """The one-time setup code while no one has an account (made the first time it is asked for), else None."""
    if not await needs_setup(db):
        return None
    code = await store.get_secret(db, box, SERVER, SETUP_KEY)
    if not code:
        code = _new_code()
        await store.set_secret(db, box, SERVER, SETUP_KEY, code)
        await db.flush()
    return code


async def set_up(
    db: AsyncSession,
    box: Box,
    *,
    code: str,
    username: str,
    password: str,
    organization: str,
    display_name: str = "",
    email: str | None = None,
) -> User:
    """The owner's account, in the default organization renamed after theirs; the code then stops working."""
    # Locked first, so two people entering the code at once cannot both become owner (Postgres).
    workspace = (
        await db.execute(select(Workspace).where(Workspace.id == DEFAULT_WORKSPACE_ID).with_for_update())
    ).scalars().first()
    current = await setup_code(db, box)
    if current is None:
        raise ApiError(409, "set_up", "this server is set up already: sign in")
    if not hmac.compare_digest(code.strip().upper().encode(), current.encode()):
        raise ApiError(403, "wrong_code", "that setup code is not right")
    name = clean_label(organization, 120)
    if not name:
        raise ApiError(422, "invalid", "the organization needs a name")
    email = (email or "").strip() or None
    if email is not None and (len(email) > 254 or not EMAIL_RE.match(email)):
        raise ApiError(422, "invalid", "that is not an email address")
    if workspace is None:  # a database built without the 0002 migration's default row
        workspace = Workspace(id=DEFAULT_WORKSPACE_ID, name=DEFAULT_WORKSPACE_NAME, kind="organization")
        db.add(workspace)
        await db.flush()
    try:
        user = await auth.create_user(
            db, username, password, role="admin", owner=True, workspace_id=workspace.id,
            display_name=clean_label(display_name, 120), email=email,
        )
    except auth.AuthError as exc:
        raise ApiError(422, "invalid", str(exc)) from exc
    workspace.name = name
    await store.set_secret(db, box, SERVER, SETUP_KEY, "")
    await audit.record(db, action="server.setup", actor=user.username, workspace_id=SERVER, target=name)
    return user
