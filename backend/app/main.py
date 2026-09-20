"""FastAPI application factory and lifespan wiring."""
from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .cache import cache
from .config import settings
from .db import init_db
from .enrichment import PROVIDERS
from .routers import cases, health, intel, lists, triage

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s %(name)s :: %(message)s",
)
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
        version="1.0.0",
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api")
    app.include_router(triage.router, prefix="/api")
    app.include_router(cases.router, prefix="/api")
    app.include_router(lists.router, prefix="/api")
    app.include_router(intel.router, prefix="/api")

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
