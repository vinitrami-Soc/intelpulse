"""FastAPI application factory and lifespan wiring."""
from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .cache import cache
from .config import settings
from .db import init_db, session_scope
from .enrichment import PROVIDERS
from .logging_config import configure_logging
from .platform import accounts
from .platform.box import server_box
from .platform.deps import require_actor
from .platform.errors import ApiError
from .routers import (
    account,
    alerts,
    cases,
    health,
    healthz,
    intel,
    invites,
    lists,
    profile,
    server,
    team,
    tokens,
    triage,
    views,
)
from .routers import settings as settings_router
from .security import (
    BodySizeLimitMiddleware,
    OriginGuardMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from .services import workspace_settings
from .web import ConsoleFiles

configure_logging(settings.log_level, json_logs=settings.json_logs)
logger = logging.getLogger("intelpulse")

DESCRIPTION = """
**IntelPulse** correlates a SOC alert against multiple threat-intelligence
sources in one request, so an analyst stops opening six browser tabs per IOC.

* `POST /api/extract` — pull indicators out of raw syslog / JSON / a paste
* `POST /api/triage` — enrich every indicator in parallel and score it
* `POST /api/triage/report` — the same, returned as a ready-to-paste SOC ticket
* `POST /api/alerts` — a SIEM pushes an alert; it is triaged into a case and its ticket
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

    @app.exception_handler(ApiError)
    async def _api_error(_request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"error": exc.error, "detail": exc.detail},
                            headers=exc.headers)

    # Every refusal the API can make, in the contract: schema fuzzing flagged
    # 401/403/404/413/415/429 as undocumented.
    refusals = {
        400: {"description": "The body could not be parsed (malformed JSON or encoding)"},
        401: {"description": "No session and no valid API token"},
        403: {"description": "Beyond the caller's role or token scope, a missing CSRF token, "
                             "or a browser write from an origin not in CORS_ORIGINS"},
        404: {"description": "No such case, entry, feed or CVE"},
        413: {"description": "Body over the size limit"},
        415: {"description": "Upload is not a text file"},
        429: {"description": "Rate limit exceeded; see Retry-After"},
    }
    # Open to anyone: health, the published scoring model, signing in and the one-time setup.
    app.include_router(health.router, prefix="/api", responses=refusals)
    app.include_router(healthz.router)   # /healthz, for monitors: 200 or 503
    app.include_router(account.router, prefix="/api", responses=refusals)
    app.include_router(invites.public, prefix="/api", responses=refusals)
    # Everything else needs a verified caller. Each route also names the actor it acts
    # for; this router-wide check is the backstop that makes a forgotten one a 401, not a leak.
    signed_in = [Depends(require_actor)]
    for module in (triage, alerts, cases, lists, intel, tokens, settings_router, team, profile, views, server, invites):
        app.include_router(module.router, prefix="/api", responses=refusals, dependencies=signed_in)

    @app.on_event("startup")
    async def _startup() -> None:
        # Before anything touches the database: a server that cannot seal
        # alert text and secrets must not start at all.
        server_box()
        await init_db()
        # once: 1.x's provider keys move from the environment into the default organization
        async with session_scope() as db:
            await workspace_settings.import_env_keys(db, server_box())
            await workspace_settings.import_env_sinks(db, server_box())
        await cache.connect()
        configured = [p.name for p in PROVIDERS if p.configured()]
        logger.info(
            "%s ready — live providers: %s",
            settings.app_name,
            ", ".join(configured) or "none (offline sources only)",
        )
        if settings.cors_allows_any:
            logger.warning(
                "CORS_ORIGINS is '*': any page in any browser can call this API and "
                "the cross-origin write guard is off — list the dashboard's origin instead"
            )
        if settings.api_token:
            logger.warning(
                "API_TOKEN (IntelPulse 1.x) is set: it still works for the endpoints 1.x had, "
                "but it is deprecated; create scoped API tokens instead"
            )
        # The code itself stays out of the log: logs travel, and whoever enters it first owns the server.
        async with session_scope() as db:
            if await accounts.needs_setup(db):
                logger.warning(
                    "no one has an account yet: run `python -m app.cli setup-code` for the one-time "
                    "setup code, then open the console and enter it"
                )

    @app.on_event("shutdown")
    async def _shutdown() -> None:
        await cache.close()

    if settings.web_dir is not None and (settings.web_dir / "index.html").is_file():
        @app.get("/assets/mode.json", include_in_schema=False)
        async def console_mode() -> JSONResponse:
            # web/assets/mode.json says "demo" wherever the folder is served as it is;
            # this server answers the same path, so the console knows to sign in (data.js).
            return JSONResponse({"mode": "server"}, headers={"Cache-Control": "no-store"})

        # Last, so every /api route and /docs are matched first.
        app.mount("/", ConsoleFiles(directory=settings.web_dir, html=True), name="console")
    else:
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
