"""Request-path defences: body limits, rate limiting, security headers.

The threat model for a triage workbench is not "someone steals the data" — the
data is threat intel. It is "someone burns the SOC's API quota, exhausts the
box, or turns the tool into a scanner". Hence: bounded bodies, bounded
indicators, per-IP budgets that treat an enrichment request as expensive and a
health check as cheap, and headers that stop the API being framed or sniffed.
"""
from __future__ import annotations

import logging
import time
import uuid
from collections import deque

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

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
                        f"({limit} per {int(self.window)}s) — retry in {retry_after}s"
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


class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Rejects oversized bodies before FastAPI buffers them into memory."""

    async def dispatch(self, request: Request, call_next):
        declared = request.headers.get("content-length")
        limit = (
            settings.max_upload_bytes
            if request.url.path.endswith("/upload")
            else settings.max_request_bytes
        )
        if declared and declared.isdigit() and int(declared) > limit:
            return JSONResponse(
                status_code=413,
                content={"detail": f"request body exceeds the {limit // 1024} KiB limit"},
            )
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
        started = time.perf_counter()
        response = await call_next(request)
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
