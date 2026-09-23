"""Request-path defences: body limits, rate limiting, security headers.

The threat model for a triage workbench is not "someone steals the data" — the
data is threat intel. It is "someone burns the SOC's API quota, exhausts the
box, or turns the tool into a scanner". Hence: bounded bodies, bounded
indicators, per-IP budgets that treat an enrichment request as expensive and a
health check as cheap, and headers that stop the API being framed or sniffed.
"""
from __future__ import annotations

import hmac
import json
import logging
import time
import uuid
from collections import deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .config import settings

logger = logging.getLogger(__name__)

# Endpoints that spend quota or CPU get their own, much smaller budget.
EXPENSIVE_PREFIXES = ("/api/triage", "/api/intel/feeds")
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def client_ip(request: Request) -> str:
    """Client address, honouring X-Forwarded-For only when explicitly trusted.

    Behind a reverse proxy the socket address is the proxy, so the limiter must
    read the forwarded header — but trusting that header when there is no proxy
    hands every attacker an unlimited supply of identities. So it is opt-in.
    """
    if settings.trust_forwarded_for:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


class SlidingWindowLimiter:
    """Per-key sliding window. In-process by design.

    A single API container is the deployment this project targets; for a
    multi-replica deployment the same interface is backed by Redis INCR, which
    is why the check is one method.
    """

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._last_sweep = 0.0

    def _sweep(self, now: float, window: float) -> None:
        if now - self._last_sweep < 30:
            return
        self._last_sweep = now
        for key in [k for k, v in self._hits.items() if not v or v[-1] < now - window]:
            self._hits.pop(key, None)

    def check(self, key: str, limit: int, window: float) -> tuple[bool, int, int]:
        """Returns (allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        self._sweep(now, window)
        hits = self._hits.setdefault(key, deque())
        cutoff = now - window
        while hits and hits[0] < cutoff:
            hits.popleft()
        if len(hits) >= limit:
            retry_after = max(1, int(hits[0] + window - now) + 1)
            return False, 0, retry_after
        hits.append(now)
        return True, limit - len(hits), 0


limiter = SlidingWindowLimiter()


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.window = float(settings.rate_limit_window_seconds)

    def _limit_for(self, request: Request) -> tuple[str, int]:
        path = request.url.path
        if any(path.startswith(prefix) for prefix in EXPENSIVE_PREFIXES):
            return "triage", settings.rate_limit_triage
        if request.method in WRITE_METHODS:
            return "write", settings.rate_limit_write
        return "read", settings.rate_limit_read

    async def dispatch(self, request: Request, call_next):
        if not settings.rate_limit_enabled or request.method == "OPTIONS":
            return await call_next(request)

        bucket, limit = self._limit_for(request)
        key = f"{bucket}:{client_ip(request)}"
        allowed, remaining, retry_after = limiter.check(key, limit, self.window)
        if not allowed:
            logger.warning(
                "rate limit hit", extra={"client_ip": client_ip(request), "path": request.url.path}
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": (
                        f"rate limit exceeded for {bucket} requests "
                        f"({limit} per {int(self.window)}s); retry in {retry_after}s"
                    )
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(limit),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


async def _send_json(send: Send, status: int, payload: dict, headers: dict[str, str] | None = None) -> None:
    body = json.dumps(payload).encode()
    raw = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    raw += [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    await send({"type": "http.response.start", "status": status, "headers": raw})
    await send({"type": "http.response.body", "body": body})


class BodySizeLimitMiddleware:
    """Rejects oversized bodies, declared or not.

    This used to read only Content-Length. A chunked request carries none, and
    a 20 MB chunked body sailed through a 1 MiB limit into memory. So the limit
    is also counted on the stream itself, and the request stops the moment it is
    crossed. Pure ASGI rather than BaseHTTPMiddleware, because only this layer
    sees the body arrive.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = settings.max_upload_bytes if scope["path"].endswith("/upload") else settings.max_request_bytes
        detail = {"detail": f"request body exceeds the {limit // 1024} KiB limit"}
        declared = dict(scope.get("headers") or []).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            await _send_json(send, 413, detail)
            return

        seen = 0
        started = refused = False

        async def counted() -> Message:
            nonlocal seen, refused
            if refused:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > limit:
                    # Answer now and tell the app the client has gone, so it
                    # stops reading. Raising here does not work: FastAPI turns
                    # any error while reading a body into its own 400.
                    refused = True
                    if not started:
                        await _send_json(send, 413, detail)
                    return {"type": "http.disconnect"}
            return message

        async def watched(message: Message) -> None:
            nonlocal started
            if refused:
                return  # the answer has been given; whatever the app says now is dropped
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, counted, watched)
        except Exception:
            if not refused:
                raise


class OriginGuardMiddleware(BaseHTTPMiddleware):
    """Refuses state-changing requests a browser sent from someone else's page.

    CORS decides whether a page may READ a response; it does not stop a write
    from happening. A form post or a no-cors fetch is sent without asking, and
    before this guard any page an analyst had open could allowlist an
    attacker's address through their local API (proven, then fixed). Browsers
    always name the origin of a write, so a write naming a foreign one, or
    marked cross-site by Fetch Metadata, is refused. Clients that are not
    browsers send neither header and are unaffected; the API token is what
    governs them.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method in WRITE_METHODS and not settings.cors_allows_any:
            origin = request.headers.get("origin")
            # the API's own pages (/docs) write from the API's own origin
            own = f"{request.url.scheme}://{request.headers.get('host', '')}"
            allowed = set(settings.cors_origin_list) | {own}
            if origin is not None:
                refused = origin == "null" or origin not in allowed   # "null": sandboxed frames, file://
            else:
                refused = request.headers.get("sec-fetch-site", "") == "cross-site"
            if refused:
                logger.warning(
                    "cross-origin write refused",
                    extra={"client_ip": client_ip(request), "path": request.url.path, "origin": origin or ""},
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": "cross-origin write refused: this origin is not in CORS_ORIGINS"},
                )
        return await call_next(request)


# Open without a token: whether the service is up, and the published weights.
TOKEN_EXEMPT = frozenset({"/api/health", "/api/scoring/model"})


def principal(request: Request) -> str:
    """Who the request is, as far as the server can verify: never a name the client typed."""
    return getattr(request.state, "principal", "anonymous")


class TokenAuthMiddleware(BaseHTTPMiddleware):
    """Bearer-token authentication, on when API_TOKEN is set.

    Compared with hmac.compare_digest so the check takes the same time however
    much of the token a guess gets right. Preflights and the two read-only
    status endpoints stay open; so do /docs and the schema, which describe the
    API without touching any data.
    """

    async def dispatch(self, request: Request, call_next):
        token = settings.api_token
        request.state.principal = "anonymous"
        if not token or request.method == "OPTIONS":
            return await call_next(request)
        path = request.url.path
        if not path.startswith("/api/") or path in TOKEN_EXEMPT:
            return await call_next(request)
        sent = request.headers.get("authorization", "")
        scheme, _, credential = sent.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(credential.strip().encode(), token.encode()):
            logger.warning("unauthenticated request refused", extra={"client_ip": client_ip(request), "path": path})
            return JSONResponse(
                status_code=401,
                content={"detail": "a valid API token is required: send it as 'Authorization: Bearer <token>'"},
                headers={"WWW-Authenticate": 'Bearer realm="intelpulse"'},
            )
        request.state.principal = "api-token"
        return await call_next(request)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Conservative headers on API responses.

    `/docs` and `/redoc` load Swagger's bundle from a CDN, so the strict CSP is
    applied to everything else and those two paths get a relaxed one rather
    than a broken page or a lie about what is enforced.
    """

    API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    DOCS_CSP = (
        "default-src 'self'; img-src 'self' data: https://fastapi.tiangolo.com; "
        "script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' "
        "https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    )

    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        # A client-chosen request ID ends up in logs and in a header: keep it plain.
        request_id = "".join(ch for ch in request_id if ch.isascii() and (ch.isalnum() or ch in "-_"))[:64]
        request_id = request_id or uuid.uuid4().hex[:16]
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # Fail closed and say nothing about the internals: the trace goes
            # to the log under the request ID, the client gets the ID to quote.
            logger.exception("unhandled error", extra={"request_id": request_id, "path": request.url.path})
            response = JSONResponse(
                status_code=500, content={"detail": "internal error", "request_id": request_id}
            )
        duration_ms = int((time.perf_counter() - started) * 1000)

        is_docs = request.url.path in ("/docs", "/redoc", "/docs/oauth2-redirect")
        response.headers.setdefault(
            "Content-Security-Policy", self.DOCS_CSP if is_docs else self.API_CSP
        )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=(), interest-cohort=()"
        )
        if settings.environment.lower() in ("production", "prod"):
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        response.headers["X-Request-ID"] = request_id

        logger.info(
            "%s %s -> %s",
            request.method,
            request.url.path,
            response.status_code,
            extra={
                "request_id": request_id,
                "client_ip": client_ip(request),
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_ms": duration_ms,
            },
        )
        return response
