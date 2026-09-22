"""Provider contract shared by every enrichment source.

A provider converts one vendor's response into three things the rest of the
pipeline understands:

  * `signals`  - normalised 0..1 maliciousness values that feed the composite
                 score (weights live in config, not here),
  * `facts`    - flat key/value pairs rendered in the analyst timeline,
  * `relations`- typed edges (ioc -> malware family, ioc -> ASN, domain -> ip)
                 used to build the investigation graph.

Caching, timeouts and error handling are implemented once in `lookup()`, so a
new source is ~40 lines and cannot forget to burn quota or hang a request.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote

import httpx

from ..cache import cache
from ..config import settings
from ..ioc import Indicator

logger = logging.getLogger(__name__)

STATUS_OK = "ok"
STATUS_CLEAN = "clean"           # provider answered, nothing known about the IOC
STATUS_SKIPPED = "skipped"       # unsupported IOC type or missing credential
STATUS_ERROR = "error"
STATUS_RATE_LIMITED = "rate_limited"


@dataclass
class Signal:
    """One normalised contribution to the composite score."""

    key: str            # maps to a weight in Settings.provider_weights
    value: float        # 0.0 (benign) .. 1.0 (confirmed malicious)
    rationale: str
    weight_hint: float | None = None

    def clamped(self) -> float:
        return max(0.0, min(1.0, self.value))


@dataclass
class Relation:
    """An edge for the investigation graph."""

    target: str
    target_type: str            # ip | domain | url | hash | malware | asn | country | pulse | cve
    relation: str               # resolves_to | hosts | attributed_to | announced_by | ...
    confidence: float = 0.6


@dataclass
class ProviderResult:
    provider: str
    label: str
    ioc: str
    status: str = STATUS_SKIPPED
    signals: list[Signal] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    attack_ids: list[str] = field(default_factory=list)
    relations: list[Relation] = field(default_factory=list)
    reference: str | None = None
    error: str | None = None
    latency_ms: int = 0
    cached: bool = False

    @property
    def answered(self) -> bool:
        return self.status in (STATUS_OK, STATUS_CLEAN)

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "label": self.label,
            "status": self.status,
            "cached": self.cached,
            "latency_ms": self.latency_ms,
            "facts": self.facts,
            "tags": self.tags,
            "malware_families": self.malware_families,
            "attack_ids": self.attack_ids,
            "reference": self.reference,
            "error": self.error,
            "signals": [
                {"key": s.key, "value": round(s.clamped(), 3), "rationale": s.rationale}
                for s in self.signals
            ],
            "relations": [
                {
                    "target": r.target,
                    "target_type": r.target_type,
                    "relation": r.relation,
                    "confidence": r.confidence,
                }
                for r in self.relations
            ],
        }


# One in-flight fetch per (provider, indicator). Process-local on purpose: the
# deployment this targets is a single container, and a distributed lock would
# buy correctness across replicas at the cost of a Redis round trip on the hot
# path. Entries are removed as soon as the last waiter leaves.
_inflight: dict[tuple[str, str], asyncio.Lock] = {}


class Provider:
    """Base class: subclasses implement `fetch()` only."""

    name: str = "provider"
    label: str = "Provider"
    supported_types: set[str] = set()
    requires_key: bool = True
    reference_url: str = ""
    cacheable: bool = True

    def configured(self) -> bool:
        return True

    def supports(self, indicator: Indicator) -> bool:
        return indicator.type in self.supported_types

    def reference_for(self, indicator: Indicator) -> str | None:
        """Vendor deep-link for the analyst. The indicator is encoded because
        this string is rendered as an href in the dashboard."""
        if not self.reference_url:
            return None
        return self.reference_url.format(ioc=quote(indicator.value, safe=""))

    async def fetch(self, client: httpx.AsyncClient, indicator: Indicator) -> ProviderResult:
        raise NotImplementedError

    # -- orchestration ---------------------------------------------------
    def _result(self, indicator: Indicator, **kwargs: Any) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            label=self.label,
            ioc=indicator.value,
            reference=self.reference_for(indicator),
            **kwargs,
        )

    async def lookup(
        self, client: httpx.AsyncClient, indicator: Indicator, *, use_cache: bool = True
    ) -> ProviderResult:
        if not self.supports(indicator):
            return self._result(
                indicator, status=STATUS_SKIPPED, error=f"{indicator.type} not supported"
            )
        if not self.configured():
            return self._result(
                indicator, status=STATUS_SKIPPED, error="API key not configured"
            )

        if use_cache and self.cacheable:
            cached = await cache.get(self.name, indicator.value)
            if cached is not None:
                result = _from_cache(cached, self, indicator)
                if result is not None:
                    return result

        # Single-flight. A cache miss is not the same as "nobody is fetching
        # this": two analysts triaging the same address in the same second both
        # miss, both fetch, and the second answer overwrites the first having
        # spent a second quota unit for it. Callers that want the same pair
        # queue behind the first and read its result from the cache.
        if not self.cacheable:
            return await self._fetch_and_store(client, indicator)

        key = (self.name, indicator.value)
        lock = _inflight.get(key)
        if lock is None:
            lock = _inflight[key] = asyncio.Lock()
        async with lock:
            # The holder of the lock has written the cache by the time we get
            # here, so re-check before spending a call of our own.
            if use_cache:
                cached = await cache.get(self.name, indicator.value)
                if cached is not None:
                    result = _from_cache(cached, self, indicator)
                    if result is not None:
                        return result
            try:
                return await self._fetch_and_store(client, indicator)
            finally:
                # Only the last holder clears the entry, so the map cannot grow
                # without bound across a long-running process.
                if not lock.locked() or _inflight.get(key) is lock:
                    _inflight.pop(key, None)

    async def _fetch_and_store(
        self, client: httpx.AsyncClient, indicator: Indicator
    ) -> ProviderResult:
        started = time.perf_counter()
        try:
            result = await asyncio.wait_for(
                self.fetch(client, indicator), timeout=settings.provider_timeout_seconds
            )
        except TimeoutError:
            result = self._result(
                indicator,
                status=STATUS_ERROR,
                error=f"timeout after {settings.provider_timeout_seconds:g}s",
            )
        except httpx.HTTPError as exc:
            result = self._result(indicator, status=STATUS_ERROR, error=f"http error: {exc}")
        except Exception as exc:  # defensive: one bad vendor never fails a triage
            logger.exception("provider %s crashed on %s", self.name, indicator.value)
            result = self._result(indicator, status=STATUS_ERROR, error=str(exc))

        result.latency_ms = int((time.perf_counter() - started) * 1000)
        result.reference = result.reference or self.reference_for(indicator)

        if self.cacheable and result.status in (STATUS_OK, STATUS_CLEAN, STATUS_ERROR):
            ttl = (
                settings.cache_ttl_seconds
                if result.answered
                else settings.cache_negative_ttl_seconds
            )
            await cache.set(self.name, indicator.value, result.as_dict(), ttl=ttl)
        return result


def _from_cache(payload: dict, provider: Provider, indicator: Indicator) -> ProviderResult | None:
    try:
        return ProviderResult(
            provider=provider.name,
            label=provider.label,
            ioc=indicator.value,
            status=payload.get("status", STATUS_CLEAN),
            signals=[
                Signal(key=s["key"], value=float(s["value"]), rationale=s.get("rationale", ""))
                for s in payload.get("signals", [])
            ],
            facts=payload.get("facts", {}),
            tags=payload.get("tags", []),
            malware_families=payload.get("malware_families", []),
            attack_ids=payload.get("attack_ids", []),
            relations=[
                Relation(
                    target=r["target"],
                    target_type=r["target_type"],
                    relation=r["relation"],
                    confidence=float(r.get("confidence", 0.6)),
                )
                for r in payload.get("relations", [])
            ],
            reference=payload.get("reference"),
            error=payload.get("error"),
            latency_ms=int(payload.get("latency_ms", 0)),
            cached=True,
        )
    except (KeyError, TypeError, ValueError):
        return None
