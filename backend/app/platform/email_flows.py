"""Confirming an address, and resetting a forgotten password (spec 5.5).

Both send a link with a random token; the server keeps its SHA-256, the purpose,
and for a confirmation the address it confirms, so a link made for an old
address confirms nothing once the address has changed. A confirmation link opens
a page whose button confirms: a mail scanner that follows links confirms nothing.

A reset link works once, for one hour, and only for an account with a confirmed
address: nothing is sent to an unconfirmed one. Asking for it gets the same answer
whether or not an account matches, and the new password ends every session.
"""
from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import EmailToken, User, utcnow
from . import audit, auth, mail
from .errors import ApiError

CONFIRM_FOR = timedelta(hours=24)
RESET_FOR = timedelta(hours=1)
RESETS_PER_HOUR = 3   # mails one account is sent, so a stranger cannot flood someone's inbox
GONE = "this link is not valid: it may have been used already or expired. Ask for a new one"


def _aware(at: datetime) -> datetime:
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


async def _issue(db: AsyncSession, user: User, purpose: str, lifetime: timedelta) -> str:
    token = secrets.token_urlsafe(32)
    db.add(EmailToken(user_id=user.id, purpose=purpose, token_hash=auth.digest(token), email=user.email or "",
                      expires_at=utcnow() + lifetime))
    await db.flush()
    return token


async def _take(db: AsyncSession, token: str, purpose: str) -> EmailToken:
    """The open token of this purpose, locked, or 404 in every other case."""
    if not token or len(token) > 200:
        raise ApiError(404, "not_found", GONE)
    row = (await db.execute(
        select(EmailToken).where(EmailToken.token_hash == auth.digest(token), EmailToken.purpose == purpose)
        .with_for_update()
    )).scalars().first()
    if row is None or row.used_at is not None or _aware(row.expires_at) <= utcnow():
        raise ApiError(404, "not_found", GONE)
    return row


async def send_confirmation(db: AsyncSession, user: User) -> bool:
    """Mail a confirmation link for the account's address, if email is on and there is one to confirm."""
    if not mail.enabled() or not user.email or user.email_confirmed_at is not None:
        return False
    token = await _issue(db, user, "confirm", CONFIRM_FOR)
    return await mail.send(user.email, "Confirm your address for IntelPulse", (
        f"Hello {user.display_name or user.username},\n\n"
        "Open this link and press the button on the page to confirm that this address is yours:\n\n"
        f"{mail.link('#/confirm/' + token)}\n\n"
        "The link works for 24 hours. If you did not give IntelPulse this address, ignore this message.\n"
    ))


async def confirm(db: AsyncSession, token: str) -> User:
    row = await _take(db, token, "confirm")
    user = await db.get(User, row.user_id)
    if user is None or user.email != row.email:   # the address changed since the link was sent
        raise ApiError(404, "not_found", GONE)
    row.used_at = utcnow()
    user.email_confirmed_at = utcnow()
    await audit.record(db, action="email.confirmed", actor=user.username, workspace_id=user.workspace_id)
    return user


async def forgot(db: AsyncSession, login: str) -> None:
    """Mail a reset link to the account this username or address names, if it has a confirmed
    address; otherwise do nothing. The caller answers the same either way."""
    login = (login or "").strip().lower()
    if not login or not mail.enabled():
        return
    user = (await db.execute(
        select(User).where(or_(User.username == login, func.lower(User.email) == login)).limit(1)
    )).scalars().first()
    if user is None or user.disabled or not user.email or user.email_confirmed_at is None:
        return
    recent = (await db.execute(select(func.count(EmailToken.id)).where(
        EmailToken.user_id == user.id, EmailToken.purpose == "reset", EmailToken.created_at >= utcnow() - RESET_FOR
    ))).scalar_one()
    if recent >= RESETS_PER_HOUR:
        return
    token = await _issue(db, user, "reset", RESET_FOR)
    await audit.record(db, action="password.reset_requested", actor=user.username, workspace_id=user.workspace_id)
    await mail.send(user.email, "Reset your IntelPulse password", (
        f"Hello {user.display_name or user.username},\n\n"
        "Someone asked to reset the password of your IntelPulse account. If it was you, open this link "
        "within the hour and choose a new password:\n\n"
        f"{mail.link('#/reset/' + token)}\n\n"
        "It works once. Every session of your account ends when the password changes. "
        "If you did not ask, ignore this message: your password stays as it is.\n"
    ))


async def reset(db: AsyncSession, token: str, password: str) -> User:
    row = await _take(db, token, "reset")
    user = await db.get(User, row.user_id)
    if user is None or user.disabled:
        raise ApiError(404, "not_found", GONE)
    try:
        auth.set_password(user, password)
    except auth.AuthError as exc:
        raise ApiError(422, "invalid", str(exc)) from exc   # the link still works: try another password
    now = utcnow()
    # this link, and every other reset link of the account, stop working
    await db.execute(update(EmailToken).where(EmailToken.user_id == user.id, EmailToken.purpose == "reset",
                                              EmailToken.used_at.is_(None)).values(used_at=now))
    await auth.end_sessions(db, user.id)
    await audit.record(db, action="password.reset", actor=user.username, workspace_id=user.workspace_id)
    return user
