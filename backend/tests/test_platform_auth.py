"""Accounts, sessions, API tokens and the login throttle."""
from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.db import session_scope
from app.models import DEFAULT_WORKSPACE_ID, ApiToken, LoginSession, User, utcnow
from app.platform import auth

PASSWORD = "correct horse battery"


async def _user(username: str = "alice", role: str = "analyst", **kwargs) -> int:
    async with session_scope() as db:
        user = await auth.create_user(db, username, PASSWORD, role=role, **kwargs)
        return user.id


# -- users ---------------------------------------------------------------------
@pytest.mark.parametrize(
    ("username", "password", "role", "message"),
    [
        ("Al", PASSWORD, "analyst", "usernames are"),
        ("alice smith", PASSWORD, "analyst", "usernames are"),
        ("alice", "short", "analyst", "at least 12"),
        ("alice", PASSWORD, "owner", "role must be"),
    ],
)
async def test_unacceptable_accounts_are_refused(clean_db, username, password, role, message):
    async with session_scope() as db:
        with pytest.raises(auth.AuthError, match=message):
            await auth.create_user(db, username, password, role=role)


async def test_a_username_is_taken_once(clean_db):
    await _user("alice")
    async with session_scope() as db:
        with pytest.raises(auth.AuthError, match="taken"):
            await auth.create_user(db, "alice", PASSWORD, role="analyst")


async def test_the_password_is_stored_only_as_an_argon2id_hash(clean_db):
    await _user("alice")
    async with session_scope() as db:
        user = (await db.execute(select(User))).scalars().one()
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash
    assert user.workspace_id == DEFAULT_WORKSPACE_ID


async def test_login_needs_the_right_password_and_an_enabled_account(clean_db):
    await _user("alice")
    async with session_scope() as db:
        assert (await auth.check_login(db, "alice", PASSWORD)) is not None
        assert await auth.check_login(db, "alice", PASSWORD + "x") is None
        assert await auth.check_login(db, "nobody", PASSWORD) is None
        user = (await db.execute(select(User))).scalars().one()
        user.disabled = True
    async with session_scope() as db:
        assert await auth.check_login(db, "alice", PASSWORD) is None


# -- sessions --------------------------------------------------------------------
async def _session(user_id: int) -> str:
    async with session_scope() as db:
        cookie, _row = await auth.open_session(db, await db.get(User, user_id))
        return cookie


async def test_a_session_is_found_by_its_cookie_and_stored_only_as_a_hash(clean_db):
    user_id = await _user("alice", role="admin")
    cookie = await _session(user_id)
    async with session_scope() as db:
        actor = await auth.find_session(db, cookie)
        stored = (await db.execute(select(LoginSession.id))).scalars().all()
    assert actor is not None and actor.username == "alice" and actor.is_admin
    assert actor.workspace_id == DEFAULT_WORKSPACE_ID and actor.csrf
    assert cookie not in stored and auth.digest(cookie) in stored


@pytest.mark.parametrize(("field", "age"), [("last_seen_at", timedelta(hours=9)),
                                            ("created_at", timedelta(days=8))])
async def test_an_idle_or_old_session_ends(clean_db, field, age):
    cookie = await _session(await _user("alice"))
    async with session_scope() as db:
        row = (await db.execute(select(LoginSession))).scalars().one()
        setattr(row, field, utcnow() - age)
    async with session_scope() as db:
        assert await auth.find_session(db, cookie) is None
        assert (await db.execute(select(LoginSession))).first() is None


async def test_a_disabled_users_sessions_stop_working(clean_db):
    user_id = await _user("alice")
    cookie = await _session(user_id)
    async with session_scope() as db:
        (await db.get(User, user_id)).disabled = True
    async with session_scope() as db:
        assert await auth.find_session(db, cookie) is None


async def test_closing_and_ending_sessions(clean_db):
    user_id = await _user("alice")
    first, second, third = await _session(user_id), await _session(user_id), await _session(user_id)
    async with session_scope() as db:
        await auth.close_session(db, first)
        await auth.end_sessions(db, user_id, keep=auth.digest(third))
    async with session_scope() as db:
        assert await auth.find_session(db, first) is None
        assert await auth.find_session(db, second) is None
        assert await auth.find_session(db, third) is not None


# -- API tokens ------------------------------------------------------------------
async def test_a_token_is_shown_once_and_stored_as_a_hash(clean_db):
    async with session_scope() as db:
        value, row = await auth.create_token(db, workspace_id=DEFAULT_WORKSPACE_ID, name="dwellwatch",
                                             scope="ingest")
    assert value.startswith("ipt_") and row.token_hash == auth.digest(value)
    async with session_scope() as db:
        actor = await auth.find_token(db, value)
        assert (await db.execute(select(ApiToken.token_hash))).scalars().all() == [auth.digest(value)]
    assert (actor.via, actor.scope, actor.label) == ("token", "ingest", "token:dwellwatch")
    assert not actor.is_admin


@pytest.mark.parametrize(("name", "scope", "message"), [("x", "admin", "scope must be"),
                                                        ("   ", "read", "a name of 1 to 64")])
async def test_unacceptable_tokens_are_refused(clean_db, name, scope, message):
    async with session_scope() as db:
        with pytest.raises(auth.AuthError, match=message):
            await auth.create_token(db, workspace_id=DEFAULT_WORKSPACE_ID, name=name, scope=scope)


async def test_a_revoked_or_expired_token_stops_working(clean_db):
    async with session_scope() as db:
        revoked, row = await auth.create_token(db, workspace_id=DEFAULT_WORKSPACE_ID, name="a", scope="read")
        row.revoked_at = utcnow()
        expired, _row = await auth.create_token(db, workspace_id=DEFAULT_WORKSPACE_ID, name="b", scope="read",
                                                expires_at=utcnow() - timedelta(seconds=1))
    async with session_scope() as db:
        assert await auth.find_token(db, revoked) is None
        assert await auth.find_token(db, expired) is None
        assert await auth.find_token(db, "ipt_made-up") is None


# -- login throttle ----------------------------------------------------------------
def test_the_throttle_waits_longer_after_each_failure_from_the_third():
    now = [100.0]
    throttle = auth.LoginThrottle(clock=lambda: now[0])
    throttle.failed("alice", "198.51.100.7")
    throttle.failed("alice", "198.51.100.7")
    assert throttle.wait("alice") == 0.0
    throttle.failed("alice", "198.51.100.7")
    assert throttle.wait("alice") == 1.0
    throttle.failed("alice")
    assert throttle.wait("alice", "198.51.100.7") == 2.0
    throttle.succeeded("alice", "198.51.100.7")
    assert throttle.wait("alice", "198.51.100.7") == 0.0


def test_the_throttle_forgets_the_oldest_names_first():
    throttle = auth.LoginThrottle(clock=lambda: 0.0, limit=3)
    for name in ("a", "b", "c", "d"):
        throttle.failed(name)
    assert len(throttle) == 3 and throttle.wait("a") == 0.0
