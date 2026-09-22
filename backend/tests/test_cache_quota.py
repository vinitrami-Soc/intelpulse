"""Quota discipline: one (provider, indicator) pair costs one upstream call.

Free tiers are the binding constraint in this design — AbuseIPDB gives 1 000
checks a day, GreyNoise community 100 — so a duplicate fetch is not a
performance detail, it is a quota unit an analyst does not get back. The cache
docstring promises this; nothing enforced it until this file.

Every test here counts real `fetch` calls against a provider whose network is
replaced by a counter, so a regression shows up as an integer, not a timing.
"""
from __future__ import annotations

import asyncio

import pytest

from app.enrichment.base import STATUS_OK, Provider, Signal
from app.ioc import Indicator
from app.services import triage as triage_service


class CountingProvider(Provider):
    """A provider that answers instantly and records every upstream fetch."""

    name = "counting"
    label = "Counting"
    supported_types = {"ip"}
    requires_key = False
    cacheable = True

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.delay = 0.0

    def configured(self) -> bool:
        return True

    def reference_for(self, indicator: Indicator) -> str | None:
        return None

    async def fetch(self, client, indicator: Indicator):
        self.calls.append(indicator.value)
        if self.delay:
            await asyncio.sleep(self.delay)
        return self._result(
            indicator,
            status=STATUS_OK,
            signals=[Signal(key="counting", value=0.5, rationale="stub")],
            facts={"hits": 1},
        )


@pytest.fixture
async def counting(monkeypatch, clean_db):
    """Swap the provider registry for one counting provider, and empty the cache.

    `clean_db` is required: triage() consults the analyst allow/block list, so
    these tests need the schema even though they never write to it.
    """
    from app import cache as cache_module

    provider = CountingProvider()
    monkeypatch.setattr(triage_service, "PROVIDERS", [provider])
    await cache_module.cache.invalidate("")
    yield provider
    await cache_module.cache.invalidate("")


def ip(value: str) -> Indicator:
    return Indicator(value=value, type="ip", original=value)


@pytest.mark.anyio
async def test_one_indicator_costs_one_call(counting):
    await triage_service.triage([ip("203.0.113.10")])
    assert counting.calls == ["203.0.113.10"]


@pytest.mark.anyio
async def test_the_same_indicator_twice_in_one_paste_costs_one_call(counting):
    """The routers de-duplicate, but triage() is also the CLI's entry point.

    The two lookups run concurrently, so the first has not written its cache
    entry when the second checks — a classic stampede that spends two quota
    units on one address.
    """
    await triage_service.triage([ip("203.0.113.10"), ip("203.0.113.10")])
    assert counting.calls == ["203.0.113.10"], (
        f"{len(counting.calls)} upstream calls for one address: {counting.calls}"
    )


@pytest.mark.anyio
async def test_a_slow_provider_still_costs_one_call(counting):
    """Widen the stampede window: a slow vendor must not multiply the cost."""
    counting.delay = 0.05
    await triage_service.triage([ip("198.51.100.7")] * 4)
    assert counting.calls == ["198.51.100.7"], (
        f"{len(counting.calls)} upstream calls for one address under a slow provider"
    )


@pytest.mark.anyio
async def test_re_triaging_within_the_ttl_is_free(counting):
    """The second shift-hour lookup of the same address reads the cache."""
    await triage_service.triage([ip("203.0.113.55")])
    await triage_service.triage([ip("203.0.113.55")])
    assert counting.calls == ["203.0.113.55"], (
        f"a repeat triage cost another call: {counting.calls}"
    )


@pytest.mark.anyio
async def test_distinct_indicators_each_cost_one_call(counting):
    """De-duplication must not collapse different addresses into one."""
    await triage_service.triage([ip("203.0.113.1"), ip("203.0.113.2"), ip("203.0.113.1")])
    assert sorted(counting.calls) == ["203.0.113.1", "203.0.113.2"]


@pytest.mark.anyio
async def test_every_distinct_indicator_still_gets_a_verdict(counting):
    """Whatever de-duplication does upstream, the caller gets what it asked for."""
    outcome = await triage_service.triage([ip("203.0.113.1"), ip("203.0.113.2"), ip("203.0.113.1")])
    assert sorted(outcome.results_by_ioc) == ["203.0.113.1", "203.0.113.2"]
    assert sorted(v.indicator.value for v in outcome.verdicts) == ["203.0.113.1", "203.0.113.2"]


@pytest.mark.anyio
async def test_use_cache_false_still_costs_one_call_per_pair(counting):
    """A forced refresh re-reads the vendor once, not once per duplicate."""
    await triage_service.triage([ip("203.0.113.9")] * 3, use_cache=False)
    assert counting.calls == ["203.0.113.9"], (
        f"a forced refresh fanned out to {len(counting.calls)} calls"
    )


@pytest.mark.anyio
async def test_two_analysts_triaging_the_same_address_at_once_cost_one_call(counting):
    """The stampede that survives de-duplication: two requests, same second.

    De-duplicating inside one triage cannot help here — these are two separate
    calls, and neither has written a cache entry the other could read. Without
    a single-flight the vendor is asked twice for the same answer.
    """
    counting.delay = 0.05
    await asyncio.gather(
        triage_service.triage([ip("203.0.113.77")]),
        triage_service.triage([ip("203.0.113.77")]),
    )
    assert counting.calls == ["203.0.113.77"], (
        f"{len(counting.calls)} concurrent callers each spent a quota unit"
    )


@pytest.mark.anyio
async def test_a_single_flight_does_not_serialise_different_addresses(counting):
    """Collapsing duplicates must not turn the fan-out into a queue."""
    counting.delay = 0.05
    started = asyncio.get_event_loop().time()
    await triage_service.triage([ip(f"203.0.113.{n}") for n in range(20, 32)])
    elapsed = asyncio.get_event_loop().time() - started
    assert len(counting.calls) == 12
    assert elapsed < 0.4, f"12 distinct lookups took {elapsed:.2f}s — they are not concurrent"
