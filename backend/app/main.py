"""FastAPI application factory and lifespan wiring."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .cache import cache
from .config import settings
from .db import init_db
from .enrichment import PROVIDERS
from .logging_config import configure_logging
from .routers import cases, health, intel, lists, triage
from .security import (
    BodySizeLimitMiddleware,
    OriginGuardMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
    TokenAuthMiddleware,
)

configure_logging(settings.log_level, json_logs=settings.json_logs)
logger = logging.getLogger("intelpulse")

DESCRIPTION = """
**IntelPulse** correlates a SOC alert against multiple threat-intelligence
sources in one request, so an analyst stops opening six browser tabs per IOC.

* `POST /api/extract` — pull indicators out of raw syslog / JSON / a paste
* `POST /api/triage` — enrich every indicator in parallel and score it
* `POST /api/triage/report` — the same, returned as a ready-to-paste SOC ticket
* `GET  /api/scoring/model` — the exact weights behind every verdict

Sources: AbuseIPDB, AlienVault OTX, GreyNoise, ThreatFox, URLhaus, plus offline
MaxMind GeoLite2, Feodo Tracker / FireHOL and an NVD CVE slice.
"""


def create_app() -> FastAPI:
    app = FastAPI(
        title=f"{settings.app_name} API",
        description=DESCRIPTION,
        version="1.0.1",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    # Added innermost first; a request meets them in the reverse order:
    #   headers -> CORS -> rate limit -> origin guard -> token -> body limit -> route.
    # CORS sits outside the guards so a dashboard that is allowed to call the
    # API can read why a request was refused (401, 403, 429) instead of seeing
    # an opaque network error. The rate limiter sits outside the token check,
    # so guessing tokens is rate limited like everything else.
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(TokenAuthMiddleware)
    app.add_middleware(OriginGuardMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "X-Request-ID", "Authorization"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After"],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
        """Say what was wrong, never repeat what was sent.

        FastAPI's default echoes each offending value back, so a 250 KB body
        came back as a 250 KB error, markup and all. Location, type and message
        are enough to fix a request.
        """
        errors = [
            {"type": error.get("type"), "loc": list(error.get("loc", ())), "msg": error.get("msg")}
            for error in exc.errors()[:20]
        ]
        return JSONResponse(status_code=422, content={"detail": errors})

    # Every refusal the API can make, in the contract: schema fuzzing flagged
    # 401/403/404/413/415/429 as undocumented.
    refusals = {
        400: {"description": "The body could not be parsed (malformed JSON or encoding)"},
        401: {"description": "API_TOKEN is set and the request did not carry it"},
        403: {"description": "A browser write from an origin not in CORS_ORIGINS"},
        404: {"description": "No such case, entry, feed or CVE"},
        413: {"description": "Body over the size limit"},
        415: {"description": "Upload is not a text file"},
        429: {"description": "Rate limit exceeded; see Retry-After"},
    }
    app.include_router(health.router, prefix="/api", responses=refusals)
    app.include_router(triage.router, prefix="/api", responses=refusals)
    app.include_router(cases.router, prefix="/api", responses=refusals)
    app.include_router(lists.router, prefix="/api", responses=refusals)
    app.include_router(intel.router, prefix="/api", responses=refusals)

    @app.on_event("startup")
    async def _startup() -> None:
        await init_db()
        await cache.connect()
        configured = [p.name for p in PROVIDERS if p.configured()]
        logger.info(
            "%s ready — live providers: %s",
            settings.app_name,
            ", ".join(configured) or "none (offline sources only)",
        )
        production = settings.environment.lower() in ("production", "prod")
        if settings.cors_allows_any:
            logger.warning(
                "CORS_ORIGINS is '*': any page in any browser can call this API and "
                "the cross-origin write guard is off — list the dashboard's origin instead"
            )
        if production and not settings.api_token:
            logger.warning(
                "API_TOKEN is not set in a production environment: anyone who can "
                "reach this API can write to it"
            )

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        await cache.close()

    @app.get("/", include_in_schema=False)
    async def root() -> JSONResponse:
        return JSONResponse(
            {
                "name": settings.app_name,
                "docs": "/docs",
                "health": "/api/health",
                "triage": "POST /api/triage",
            }
        )

    return app


app = create_app()
