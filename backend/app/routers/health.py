"""Service health and capability discovery.

The frontend calls this on load so the dashboard can tell an analyst exactly
which sources are live — a triage run where three providers are unconfigured
must never look like a triage run where all six answered.
"""
from __future__ import annotations

from fastapi import APIRouter
from sqlalchemy import func, select

from ..cache import cache
from ..config import settings
from ..db import engine, session_scope
from ..enrichment import PROVIDERS
from ..models import Case, CveRecord, FeedEntry
from ..schemas import HealthResponse, ProviderStatus

router = APIRouter(tags=["system"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    database = "ok"
    feed_rows = cve_rows = case_rows = 0
    try:
        async with session_scope() as session:
            feed_rows = (await session.execute(select(func.count(FeedEntry.id)))).scalar_one()
            cve_rows = (await session.execute(select(func.count(CveRecord.cve_id)))).scalar_one()
            case_rows = (await session.execute(select(func.count(Case.id)))).scalar_one()
    except Exception as exc:  # pragma: no cover
        database = f"error: {exc}"

    providers = [
        ProviderStatus(
            name=p.name,
            label=p.label,
            supported_types=sorted(p.supported_types),
            requires_key=p.requires_key,
            configured=p.configured(),
        )
        for p in PROVIDERS
    ]
    return HealthResponse(
        status="ok" if database == "ok" else "degraded",
        app=settings.app_name,
        environment=settings.environment,
        database=f"{engine.url.get_backend_name()} ({database})",
        cache=cache.status(),
        providers=providers,
        offline_datasets={
            "feed_entries": feed_rows,
            "cve_records": cve_rows,
            "stored_cases": case_rows,
            "geoip_city": settings.geoip_city_db.exists(),
            "geoip_asn": settings.geoip_asn_db.exists(),
        },
    )


@router.get("/scoring/model")
async def scoring_model() -> dict:
    """Expose the weights so a reviewer can audit how a verdict was reached."""
    from ..scoring import AUTHORITY

    return {
        "weights": settings.provider_weights,
        "authority": AUTHORITY,
        "thresholds": {
            "low": settings.score_low_threshold,
            "medium": settings.score_medium_threshold,
            "high": settings.score_high_threshold,
            "critical": settings.score_high_threshold + 15,
        },
        "modifiers": {
            "greynoise_benign_multiplier": settings.greynoise_benign_multiplier,
            "allowlist": "forces score 0",
            "blocklist": "forces score >= 90",
        },
        "formula": "score = 100 x max(weighted_mean_of_answering_providers, max(signal x authority))",
    }
