"""Offline historical datasets held in Postgres/SQLite.

Two sources, refreshed by the Celery beat worker (or `make feeds`):

  * `feed_entries` — Feodo Tracker C2 IPs, FireHOL level-1 ranges and the
    ThreatFox daily dump. A hit here is high-confidence and, crucially, works
    with no internet access and no API quota at all.
  * `cve_records`  — an NVD slice used to score CVE indicators offline.
"""
from __future__ import annotations

import httpx
from sqlalchemy import select

from ..db import session_scope
from ..ioc import Indicator
from ..models import CveRecord, FeedEntry, ListEntry
from .base import STATUS_CLEAN, STATUS_OK, Provider, ProviderResult, Relation, Signal


class LocalFeedProvider(Provider):
    name = "local_blocklist"
    label = "Local historical feeds"
    supported_types = {"ip", "domain", "url", "hash"}
    requires_key = False
    cacheable = False  # already a local index lookup

    def reference_for(self, indicator: Indicator) -> str | None:
        return None

    async def fetch(self, client: httpx.AsyncClient, indicator: Indicator) -> ProviderResult:
        async with session_scope() as session:
            rows = (
                await session.execute(
                    select(FeedEntry).where(FeedEntry.value == indicator.value.lower()).limit(10)
                )
            ).scalars().all()

        if not rows:
            return self._result(
                indicator,
                status=STATUS_CLEAN,
                facts={"feed_hits": 0},
                signals=[Signal("local_blocklist", 0.0, "no match in local historical feeds")],
            )

        feeds = sorted({row.feed for row in rows})
        families = sorted({row.malware_family for row in rows if row.malware_family})
        confidence = max(row.confidence for row in rows) / 100

        return self._result(
            indicator,
            status=STATUS_OK,
            facts={
                "feed_hits": len(rows),
                "feeds": feeds,
                "malware_families": families,
                "first_seen": min((r.first_seen for r in rows if r.first_seen), default=None),
                "last_seen": max((r.last_seen for r in rows if r.last_seen), default=None),
            },
            tags=[f"feed:{f}" for f in feeds],
            malware_families=families,
            attack_ids=["T1071"] if any("c2" in f.lower() or "feodo" in f.lower() for f in feeds) else [],
            relations=[Relation(f, "malware", "attributed_to", 0.9) for f in families],
            signals=[
                Signal(
                    "local_blocklist",
                    max(0.8, confidence),
                    f"present in offline feed(s): {', '.join(feeds)}"
                    + (f" — {', '.join(families[:3])}" if families else ""),
                )
            ],
        )


class CveProvider(Provider):
    """Scores CVE indicators from the offline NVD slice."""

    name = "nvd"
    label = "NVD (offline)"
    supported_types = {"cve"}
    requires_key = False
    cacheable = False
    reference_url = "https://nvd.nist.gov/vuln/detail/{ioc}"

    async def fetch(self, client: httpx.AsyncClient, indicator: Indicator) -> ProviderResult:
        async with session_scope() as session:
            record = await session.get(CveRecord, indicator.value.upper())

        if record is None:
            return self._result(
                indicator,
                status=STATUS_CLEAN,
                facts={"in_local_nvd": False},
                signals=[
                    Signal("otx", 0.25, "CVE not present in the local NVD slice — enrich manually")
                ],
            )

        score = record.cvss_score or 0.0
        value = min(1.0, score / 10)
        if record.known_exploited:
            value = max(value, 0.9)

        return self._result(
            indicator,
            status=STATUS_OK,
            facts={
                "in_local_nvd": True,
                "cvss_score": score,
                "cvss_vector": record.cvss_vector,
                "severity": record.severity,
                "published": record.published,
                "known_exploited": record.known_exploited,
                "description": (record.description or "")[:400],
            },
            tags=[f"cvss:{record.severity}"] if record.severity else [],
            relations=[Relation(indicator.value.upper(), "cve", "exploits", 0.8)],
            signals=[
                Signal(
                    "otx",
                    value,
                    f"CVSS {score} ({record.severity or 'unrated'})"
                    + (" — known exploited in the wild" if record.known_exploited else ""),
                )
            ],
        )


async def list_entry_for(value: str) -> ListEntry | None:
    """Analyst allow/block list lookup — checked before any vendor opinion."""
    async with session_scope() as session:
        return (
            await session.execute(
                select(ListEntry).where(ListEntry.value == value.lower()).limit(1)
            )
        ).scalars().first()
