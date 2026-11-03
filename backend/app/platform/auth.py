"""Users, sessions, API tokens and the login throttle. Ported from PhishHawk's
``server/auth.py`` and rewritten for async SQLAlchemy.

Passwords are argon2id. Session cookies and API tokens are random, and only
their SHA-256 is stored, so a copy of the database signs nobody in.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import (
    DEFAULT_WORKSPACE_ID,
    ApiToken,
    LoginSession,
    User,
    utcnow,
)

ROLES = ("admin", "analyst")
# read: every GET; triage: read plus extract and triage; ingest: POST /api/alerts only.
TOKEN_SCOPES = ("read", "triage", "ingest")
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
MIN_PASSWORD = 12
SESSION_IDLE = timedelta(hours=8)
SESSION_ABSOLUTE = timedelta(days=7)
TOKEN_PREFIX = "ipt_"
_hasher = PasswordHasher()


class AuthError(ValueError):
    """A username, password, role or scope that is not acceptable."""


@dataclass(frozen=True)
class Actor:
    """Who a request is, as far as the server can verify."""

    workspace_id: int
    via: str             # "session", "token" or "legacy"
    scope: str           # "full" for a session or the legacy token, else the token's scope
    label: str           # how the audit log names this actor
    user_id: int | None = None
    username: str = ""
    role: str = "analyst"
    owner: bool = False
    csrf: str = ""       # the session's CSRF token, when via is "session"
    session_id: str = ""
    token_id: int | None = None          # when via is "token"
    must_change_password: bool = False   # an admin set it: only the profile is open until it changes

    @property
    def is_admin(self) -> bool:
        return self.via == "session" and self.role == "admin"


def digest(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _aware(at: datetime) -> datetime:
    """SQLite hands datetimes back without an offset; they were written in UTC."""
    return at if at.tzinfo is not None else at.replace(tzinfo=utcnow().tzinfo)


# -- users ---------------------------------------------------------------------
def check_password_rules(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"passwords need at least {MIN_PASSWORD} characters")


async def create_user(
    db: AsyncSession,
    username: str,
    password: str,
    *,
    role: str,
    workspace_id: int = DEFAULT_WORKSPACE_ID,
    owner: bool = False,
    display_name: str = "",
    email: str | None = None,
) -> User:
    if not USERNAME_RE.match(username):
        raise AuthError("usernames are 3 to 64 lowercase letters, digits, dots, dashes or underscores")
    check_password_rules(password)
    if role not in ROLES:
        raise AuthError("role must be admin or analyst")
    if (await db.execute(select(User.id).where(User.username == username))).first() is not None:
        raise AuthError("that username is taken")
    user = User(
        username=username,
        password_hash=_hasher.hash(password),
        role=role,
        owner=owner,
        workspace_id=workspace_id,
        display_name=display_name or username,
        email=email,
    )
    db.add(user)
    await db.flush()
    return user


def set_password(user: User, password: str) -> None:
    check_password_rules(password)
    user.password_hash = _hasher.hash(password)
    user.must_change_password = False


async def check_login(db: AsyncSession, username: str, password: str) -> User | None:
    user = (await db.execute(select(User).where(User.username == username))).scalars().first()
    if user is None or user.disabled:
        _hasher.hash(password)  # the same work either way, so timing does not reveal usernames
        return None
    try:
        _hasher.verify(user.password_hash, password)
    except (VerificationError, InvalidHashError):
        return None
    return user


# -- sessions --------------------------------------------------------------------
async def open_session(db: AsyncSession, user: User) -> tuple[str, LoginSession]:
    """A new session for a user; returns the cookie value (never stored) and the row."""
    cookie = secrets.token_urlsafe(32)
    row = LoginSession(id=digest(cookie), user_id=user.id, csrf_token=secrets.token_urlsafe(32))
    db.add(row)
    user.last_login_at = utcnow()
    await db.flush()
    return cookie, row


async def find_session(db: AsyncSession, cookie: str) -> Actor | None:
    row = await db.get(LoginSession, digest(cookie))
    if row is None:
        return None
    user = await db.get(User, row.user_id)
    now = utcnow()
    expired = (
        now - _aware(row.last_seen_at) > SESSION_IDLE
        or now - _aware(row.created_at) > SESSION_ABSOLUTE
    )
    if user is None or user.disabled or expired:
        await db.delete(row)
        await db.flush()
        return None
    row.last_seen_at = now
    return Actor(
        workspace_id=user.workspace_id, via="session", scope="full", label=user.username,
        user_id=user.id, username=user.username, role=user.role, owner=user.owner,
        csrf=row.csrf_token, session_id=row.id, must_change_password=user.must_change_password,
    )


async def close_session(db: AsyncSession, cookie: str) -> None:
    await db.execute(delete(LoginSession).where(LoginSession.id == digest(cookie)))


async def end_sessions(db: AsyncSession, user_id: int, keep: str = "") -> None:
    """Every session of a user but the one whose stored id is `keep`."""
    await db.execute(delete(LoginSession).where(LoginSession.user_id == user_id, LoginSession.id != keep))


# -- API tokens ------------------------------------------------------------------
async def create_token(
    db: AsyncSession,
    *,
    workspace_id: int,
    name: str,
    scope: str,
    created_by: int | None = None,
    expires_at: datetime | None = None,
) -> tuple[str, ApiToken]:
    """A new token; returns its value (shown once, never stored) and the row."""
    if scope not in TOKEN_SCOPES:
        raise AuthError("scope must be read, triage or ingest")
    name = name.strip()
    if not 1 <= len(name) <= 64:
        raise AuthError("a token needs a name of 1 to 64 characters")
    value = TOKEN_PREFIX + secrets.token_urlsafe(32)
    row = ApiToken(workspace_id=workspace_id, name=name, scope=scope, token_hash=digest(value),
                   created_by=created_by, expires_at=expires_at)
    db.add(row)
    await db.flush()
    return value, row


async def find_token(db: AsyncSession, value: str) -> Actor | None:
    row = (await db.execute(select(ApiToken).where(ApiToken.token_hash == digest(value)))).scalars().first()
    if row is None or row.revoked_at is not None:
        return None
    if row.expires_at is not None and utcnow() >= _aware(row.expires_at):
        return None
    row.last_used_at = utcnow()
    return Actor(workspace_id=row.workspace_id, via="token", scope=row.scope, label=f"token:{row.name}",
                 token_id=row.id)


# -- login throttle ----------------------------------------------------------------
class LoginThrottle:
    """After three failures for a username or an address, each new attempt waits
    twice as long as the last (1 s, 2 s, 4 s ... up to 5 minutes). It remembers at
    most `limit` names and addresses, forgetting the oldest failure first, so a
    flood of made-up usernames cannot use up the memory."""

    def __init__(self, clock=time.monotonic, limit: int = 10_000) -> None:
        self._clock = clock
        self._limit = limit
        self._failures: dict[str, tuple[int, float]] = {}

    def __len__(self) -> int:
        return len(self._failures)

    def wait(self, *keys: str) -> float:
        now = self._clock()
        return max([0.0] + [until - now for _count, until in (self._failures.get(k, (0, 0.0)) for k in keys)])

    def failed(self, *keys: str) -> None:
        now = self._clock()
        for key in keys:
            count = self._failures.pop(key, (0, 0.0))[0] + 1  # popped, so it moves to the newest end
            delay = 0.0 if count < 3 else min(2.0 ** (count - 3), 300.0)
            self._failures[key] = (count, now + delay)
        while len(self._failures) > self._limit:
            del self._failures[next(iter(self._failures))]

    def clear(self) -> None:
        self._failures.clear()

    def succeeded(self, *keys: str) -> None:
        for key in keys:
            self._failures.pop(key, None)
