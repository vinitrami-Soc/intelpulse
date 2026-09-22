"""Triage orchestration: fan out to every applicable provider, then score.

Concurrency model — one shared `httpx.AsyncClient` (connection reuse), one
task per (indicator, provider) pair, a global semaphore so a 50-IOC paste
cannot open 350 sockets at once, and `return_exceptions=True` so a single
vendor outage degrades the result instead of failing the request.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import settings
from ..enrichment import PROVIDERS, list_entry_for
from ..enrichment.base import ProviderResult
from ..graph import build_graph
from ..ioc import Indicator
from ..models import AuditLog, Case, IndicatorResult
from ..net import build_client
from ..reporting import containment_actions, executive_summary
from ..scoring import IndicatorVerdict, case_verdict, score_indicator

logger = logging.getLogger(__name__)

MAX_CONCURRENT_LOOKUPS = 12
USER_AGENT = "IntelPulse/1.0 (+https://github.com/vinitrami-Soc)"


@dataclass
class TriageOutcome:
    case_id: str
    title: str
    verdict: str
    score: int
    duration_ms: int
    verdicts: list[IndicatorVerdict]
    results_by_ioc: dict[str, list[ProviderResult]]
    cache_hits: int = 0

    def as_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "verdict": self.verdict,
            "score": self.score,
            "duration_ms": self.duration_ms,
            "cache_hits": self.cache_hits,
            "summary": executive_summary(self.title, self.verdicts, self.verdict, self.score),
            "indicator_count": len(self.verdicts),
            "indicators": [
                {
                    "value": v.indicator.value,
                    "type": v.indicator.type,
                    "context": v.indicator.context,
                    "score": v.score,
                    "verdict": v.verdict,
                    "confidence": v.confidence,
                    "tags": v.tags,
                    "malware_families": v.malware_families,
                    "attack_techniques": v.attack_techniques,
                    "modifiers": v.modifiers,
                    "providers_queried": v.providers_queried,
                    "providers_answered": v.providers_answered,
                    "containment": containment_actions(v),
                    "evidence": [
                        {
                            "provider": c.provider,
                            "signal": c.signal,
                            "weight": c.weight,
                            "weighted": c.weighted,
                            "rationale": c.rationale,
                        }
                        for c in v.contributions
                    ],
                    "sources": [
                        r.as_dict() for r in self.results_by_ioc.get(v.indicator.value, [])
                    ],
                }
                for v in sorted(self.verdicts, key=lambda x: x.score, reverse=True)
            ],
            "graph": build_graph(self.verdicts, self.results_by_ioc),
        }


async def _lookup(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    provider,
    indicator: Indicator,
    use_cache: bool,
) -> ProviderResult:
    async with semaphore:
        return await provider.lookup(client, indicator, use_cache=use_cache)


async def enrich_indicator(
    client: httpx.AsyncClient,
    indicator: Indicator,
    *,
    semaphore: asyncio.Semaphore,
    use_cache: bool = True,
) -> list[ProviderResult]:
    applicable = [p for p in PROVIDERS if p.supports(indicator)]
    tasks = [_lookup(semaphore, client, p, indicator, use_cache) for p in applicable]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    results: list[ProviderResult] = []
    for provider, outcome in zip(applicable, gathered, strict=True):
        if isinstance(outcome, BaseException):
            logger.warning("provider %s failed hard: %s", provider.name, outcome)
            results.append(
                ProviderResult(
                    provider=provider.name,
                    label=provider.label,
                    ioc=indicator.value,
                    status="error",
                    error=str(outcome),
                )
            )
        else:
            results.append(outcome)
    return results


async def triage(
    indicators: Sequence[Indicator],
    *,
    title: str = "Ad-hoc triage",
    use_cache: bool = True,
    analyst: str | None = None,
) -> TriageOutcome:
    started = time.perf_counter()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_LOOKUPS)
    results_by_ioc: dict[str, list[ProviderResult]] = {}
    verdicts: list[IndicatorVerdict] = []

    # One address, one fan-out. Both routers de-duplicate their input, but this
    # function is also the CLI's entry point, and duplicates arriving here used
    # to race: N concurrent lookups of the same address, none of which had
    # written the cache entry the others were about to read. On a free tier
    # that is N quota units spent on one indicator, not a rounding error.
    unique: dict[str, Indicator] = {}
    for indicator in indicators:
        unique.setdefault(indicator.value, indicator)
    targets = list(unique.values())

    limits = httpx.Limits(max_connections=MAX_CONCURRENT_LOOKUPS, max_keepalive_connections=8)
    # build_client applies the egress policy — HTTPS only, host allowlist, no
    # resolution into private or metadata space — to every hop, redirects
    # included.
    async with build_client(
        timeout=settings.provider_timeout_seconds,
        limits=limits,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        enrichments = await asyncio.gather(
            *[
                enrich_indicator(client, indicator, semaphore=semaphore, use_cache=use_cache)
                for indicator in targets
            ],
            return_exceptions=False,
        )

    for indicator, results in zip(targets, enrichments, strict=True):
        results_by_ioc[indicator.value] = results
        entry = await list_entry_for(indicator.value)
        verdicts.append(score_indicator(indicator, results, list_entry=entry))

    level, score = case_verdict(verdicts)
    duration_ms = int((time.perf_counter() - started) * 1000)
    cache_hits = sum(1 for results in results_by_ioc.values() for r in results if r.cached)

    return TriageOutcome(
        case_id=str(uuid.uuid4()),
        title=title,
        verdict=level,
        score=score,
        duration_ms=duration_ms,
        verdicts=verdicts,
        results_by_ioc=results_by_ioc,
        cache_hits=cache_hits,
    )


async def persist_case(
    session: AsyncSession,
    outcome: TriageOutcome,
    *,
    raw_input: str | None = None,
    source: str = "api",
    analyst: str | None = None,
) -> Case:
    case = Case(
        id=outcome.case_id,
        title=outcome.title,
        source=source,
        analyst=analyst,
        raw_input=(raw_input or "")[:20_000] or None,
        verdict=outcome.verdict,
        max_score=outcome.score,
        indicator_count=len(outcome.verdicts),
        duration_ms=outcome.duration_ms,
    )
    session.add(case)

    payload = outcome.as_dict()
    payload_by_value = {item["value"]: item for item in payload["indicators"]}
    for verdict in outcome.verdicts:
        session.add(
            IndicatorResult(
                case_id=case.id,
                value=verdict.indicator.value,
                ioc_type=verdict.indicator.type,
                score=verdict.score,
                verdict=verdict.verdict,
                confidence=verdict.confidence,
                malware_families=verdict.malware_families,
                attack_ids=[t["id"] for t in verdict.attack_techniques],
                payload=payload_by_value.get(verdict.indicator.value, {}),
            )
        )

    session.add(
        AuditLog(
            action="triage.completed",
            actor=analyst or "anonymous",
            target=case.id,
            detail={
                "indicator_count": len(outcome.verdicts),
                "verdict": outcome.verdict,
                "score": outcome.score,
                "duration_ms": outcome.duration_ms,
                "cache_hits": outcome.cache_hits,
                "source": source,
            },
        )
    )
    await session.flush()
    return case
