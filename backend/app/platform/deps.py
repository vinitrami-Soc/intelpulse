"""Who is asking, and may they: the FastAPI dependencies every /api route goes through.

A request is one of three things, checked in this order:

- a bearer token: an API token (``ipt_...``, scoped and revocable), or the
  ``API_TOKEN`` of 1.x, which keeps the access it had, in the default
  organization, and is logged as deprecated;
- a session cookie, set at sign-in; a state-changing request made with it must
  carry the session's CSRF token in ``X-CSRF-Token``;
- nobody, which is 401 everywhere but the few public routes.

A wrong bearer token is refused even when a session cookie comes with it, so a
script cannot fall back on whoever happens to be signed in.
"""
from __future__ import annotations

import hmac
import logging

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..db import get_session
from ..models import DEFAULT_WORKSPACE_ID
from . import auth
from .auth import Actor
from .errors import ApiError

logger = logging.getLogger(__name__)

SESSION_COOKIE = "ip_session"
CSRF_HEADER = "x-csrf-token"
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
READ_METHODS = frozenset({"GET", "HEAD"})

# What each API token scope may do beyond reading (spec 5.7), named by the endpoint
# function a route runs: an included router's route template carries no "/api" prefix,
# and a function name cannot drift from its route the way a copied path can.
TRIAGE_WRITES = frozenset({
    "app.routers.triage.extract_endpoint",   # POST /api/extract
    "app.routers.triage.triage_endpoint",    # POST /api/triage
    "app.routers.triage.triage_upload",      # POST /api/triage/upload
    "app.routers.triage.triage_report",      # POST /api/triage/report
})
INGEST_WRITES = frozenset({"app.routers.alerts.receive_alert"})  # POST /api/alerts
# All a session may reach while its password must change (an admin set it).
WHILE_CHANGING_PASSWORD = frozenset({
    "app.routers.profile.read_profile",
    "app.routers.profile.update_profile",
    "app.routers.account.sign_out",
})

login_throttle = auth.LoginThrottle()


def unauthenticated() -> ApiError:
    return ApiError(
        401, "unauthorized",
        "sign in, or send an API token as 'Authorization: Bearer <token>'",
        {"WWW-Authenticate": 'Bearer realm="intelpulse"'},
    )


def forbidden(detail: str) -> ApiError:
    return ApiError(403, "forbidden", detail)


def legacy_actor() -> Actor:
    return Actor(workspace_id=DEFAULT_WORKSPACE_ID, via="legacy", scope="full", label="api-token")


async def resolve_actor(request: Request, db: AsyncSession) -> Actor | None:
    """The verified caller, or None. Never a name the client typed."""
    sent = request.headers.get("authorization", "")
    scheme, _, credential = sent.partition(" ")
    credential = credential.strip()
    if sent:
        if scheme.lower() != "bearer" or not credential:
            return None
        legacy = settings.api_token
        if legacy and hmac.compare_digest(credential.encode(), legacy.encode()):
            logger.warning("the API_TOKEN of IntelPulse 1.x is deprecated: create an API token instead",
                           extra={"path": request.url.path})
            return legacy_actor()
        if credential.startswith(auth.TOKEN_PREFIX):
            return await auth.find_token(db, credential)
        return None
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        return await auth.find_session(db, cookie)
    return None


def token_allows(scope: str, method: str, endpoint: str) -> bool:
    if scope == "full":
        return True
    if scope == "ingest":
        return endpoint in INGEST_WRITES
    if method in READ_METHODS:
        return scope in ("read", "triage")
    return scope == "triage" and endpoint in TRIAGE_WRITES


def endpoint_name(request: Request) -> str:
    endpoint = request.scope.get("endpoint")
    return f"{endpoint.__module__}.{endpoint.__name__}" if endpoint else ""


async def require_actor(request: Request, db: AsyncSession = Depends(get_session)) -> Actor:
    """Any verified caller whose credential reaches this route; CSRF checked for a session."""
    actor: Actor | None = getattr(request.state, "actor", None)
    if actor is None:
        actor = await resolve_actor(request, db)
        if actor is None:
            logger.warning("unauthenticated request refused", extra={"path": request.url.path})
            raise unauthenticated()
        request.state.actor = actor
        request.state.principal = actor.label
    if not token_allows(actor.scope, request.method, endpoint_name(request)):
        raise forbidden(f"this API token's scope ({actor.scope}) does not cover {request.method} {request.url.path}")
    if actor.must_change_password and endpoint_name(request) not in WHILE_CHANGING_PASSWORD:
        raise ApiError(403, "password_change_required",
                       "choose a new password first: an admin set this one (PATCH /api/profile)")
    if actor.via == "session" and request.method in WRITE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not hmac.compare_digest(sent.encode(), actor.csrf.encode()):
            raise ApiError(403, "csrf", "missing or wrong X-CSRF-Token: reload the page and try again")
    return actor


async def require_admin(actor: Actor = Depends(require_actor)) -> Actor:
    """An admin's session, or the 1.x API_TOKEN (which keeps the access it had)."""
    if actor.via == "legacy" or actor.is_admin:
        return actor
    raise forbidden("only an admin can do this")


async def require_owner(actor: Actor = Depends(require_actor)) -> Actor:
    """The owner's session, or the 1.x API_TOKEN: server-wide actions such as feed refreshes."""
    if actor.via == "legacy" or (actor.via == "session" and actor.owner):
        return actor
    raise forbidden("only the owner of this server can do this")


async def require_member(actor: Actor = Depends(require_actor)) -> Actor:
    """A person, signed in, any role. New v2 endpoints: neither API tokens nor the 1.x API_TOKEN reach them."""
    if actor.via == "session":
        return actor
    raise forbidden("sign in to do this: API tokens cannot")


async def require_session_admin(actor: Actor = Depends(require_actor)) -> Actor:
    """An admin, signed in. New v2 endpoints: neither API tokens nor the 1.x API_TOKEN reach them."""
    if actor.is_admin:
        return actor
    if actor.via != "session":
        raise forbidden("sign in as an admin to do this: API tokens cannot")
    raise forbidden("only an admin can do this")
