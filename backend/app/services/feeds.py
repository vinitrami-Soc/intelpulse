"""Offline dataset ingestion.

These loaders are what make IntelPulse useful when the API keys run out: once
the feeds are imported, C2 lookups, GeoIP and CVE severity all resolve locally
with no quota and no internet. Run them from the Celery beat worker in compose,
or manually with `python -m app.cli feeds --all`.
"""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import logging
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from ..db import session_scope
from ..models import CveRecord, FeedEntry, FeedRun
from ..net import build_client

logger = logging.getLogger(__name__)

FEODO_CSV = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
THREATFOX_CSV = "https://threatfox.abuse.ch/export/csv/recent/"
FIREHOL_LEVEL1 = (
    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
)
CISA_KEV = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_TIMEOUT = 60.0


async def _download(url: str, *, headers: dict | None = None) -> str:
    async with build_client(timeout=DEFAULT_TIMEOUT) as client:
        response = await client.get(url, headers=headers or {})
        response.raise_for_status()
        return response.text


async def _replace_feed(feed: str, rows: Iterable[dict]) -> int:
    """Swap a feed's contents atomically and record the run."""
    rows = list(rows)
    async with session_scope() as session:
        await session.execute(delete(FeedEntry).where(FeedEntry.feed == feed))
        seen: set[str] = set()
        for row in rows:
            value = str(row["value"]).lower()
            if value in seen:
                continue
            seen.add(value)
            session.add(FeedEntry(feed=feed, **{**row, "value": value}))
        session.add(FeedRun(feed=feed, rows=len(seen), ok=True, detail=f"imported {len(seen)} rows"))
    logger.info("feeds: %s imported %d rows", feed, len(rows))
    return len(rows)


async def _record_failure(feed: str, exc: Exception) -> None:
    async with session_scope() as session:
        session.add(FeedRun(feed=feed, rows=0, ok=False, detail=str(exc)[:490]))
    logger.warning("feeds: %s failed: %s", feed, exc)


async def refresh_feodo() -> int:
    """Feodo Tracker: active botnet C2 servers (Emotet, Dridex, QakBot, ...)."""
    feed = "feodo-tracker"
    try:
        text = await _download(FEODO_CSV)
    except Exception as exc:
        await _record_failure(feed, exc)
        return 0

    rows: list[dict] = []
    reader = csv.reader(line for line in text.splitlines() if line and not line.startswith("#"))
    for parts in reader:
        if len(parts) < 6:
            continue
        first_seen, dst_ip, dst_port, c2_status, last_online, malware = parts[:6]
        rows.append(
            {
                "value": dst_ip.strip(),
                "ioc_type": "ip",
                "malware_family": malware.strip() or None,
                "confidence": 95 if c2_status.strip() == "online" else 80,
                "first_seen": first_seen.strip(),
                "last_seen": last_online.strip() or None,
                "extra": {"port": dst_port.strip(), "c2_status": c2_status.strip()},
            }
        )
    return await _replace_feed(feed, rows)


async def refresh_threatfox_dump(limit: int = 20_000) -> int:
    """ThreatFox recent IOC export — offline mirror of the live API."""
    feed = "threatfox-dump"
    try:
        text = await _download(THREATFOX_CSV)
    except Exception as exc:
        await _record_failure(feed, exc)
        return 0

    rows: list[dict] = []
    reader = csv.reader(
        (line for line in text.splitlines() if line and not line.startswith("#")),
        skipinitialspace=True,
    )
    for parts in reader:
        # first_seen, ioc_id, ioc_value, ioc_type, threat_type, fk_malware, ...
        if len(parts) < 7:
            continue
        value = parts[2].strip().strip('"')
        raw_type = parts[3].strip().strip('"')
        ioc_type = (
            "ip" if raw_type.startswith("ip") else
            "domain" if "domain" in raw_type else
            "url" if "url" in raw_type else
            "hash" if "hash" in raw_type else None
        )
        if not ioc_type:
            continue
        if ioc_type == "ip" and ":" in value and value.count(":") == 1:
            value = value.split(":", 1)[0]  # ThreatFox stores ip:port
        rows.append(
            {
                "value": value,
                "ioc_type": ioc_type,
                "malware_family": parts[5].strip().strip('"') or None,
                "confidence": int(parts[6]) if parts[6].strip().isdigit() else 75,
                "first_seen": parts[0].strip().strip('"'),
                "last_seen": None,
                "extra": {"threat_type": parts[4].strip().strip('"')},
            }
        )
        if len(rows) >= limit:
            break
    return await _replace_feed(feed, rows)


async def refresh_firehol(max_prefix: int = 24, limit: int = 100_000) -> int:
    """FireHOL level 1 — expands only /24 and smaller; larger ranges are skipped.

    Storing a /8 as 16 million rows would be absurd; those ranges are mostly
    bogons that the extractor already drops as non-routable.
    """
    feed = "firehol-level1"
    try:
        text = await _download(FIREHOL_LEVEL1)
    except Exception as exc:
        await _record_failure(feed, exc)
        return 0

    rows: list[dict] = []
    skipped = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        if network.prefixlen < max_prefix:
            skipped += 1
            continue
        for address in network:
            rows.append(
                {
                    "value": str(address),
                    "ioc_type": "ip",
                    "malware_family": None,
                    "confidence": 70,
                    "first_seen": None,
                    "last_seen": None,
                    "extra": {"source_range": line},
                }
            )
            if len(rows) >= limit:
                break
        if len(rows) >= limit:
            break
    imported = await _replace_feed(feed, rows)
    logger.info("feeds: firehol skipped %d ranges wider than /%d", skipped, max_prefix)
    return imported


async def refresh_kev() -> int:
    """CISA Known Exploited Vulnerabilities — flags CVEs under active attack."""
    feed = "cisa-kev"
    try:
        async with build_client(timeout=DEFAULT_TIMEOUT) as client:
            response = await client.get(CISA_KEV)
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        await _record_failure(feed, exc)
        return 0

    vulns = payload.get("vulnerabilities", [])
    async with session_scope() as session:
        for vuln in vulns:
            cve_id = str(vuln.get("cveID", "")).upper()
            if not cve_id:
                continue
            record = await session.get(CveRecord, cve_id)
            if record is None:
                record = CveRecord(
                    cve_id=cve_id,
                    description=vuln.get("shortDescription", "")[:2000],
                    severity="KNOWN-EXPLOITED",
                    published=vuln.get("dateAdded"),
                    references=[],
                )
                session.add(record)
            record.known_exploited = True
        session.add(FeedRun(feed=feed, rows=len(vulns), ok=True, detail=f"{len(vulns)} KEV entries"))
    logger.info("feeds: cisa-kev imported %d entries", len(vulns))
    return len(vulns)


async def refresh_nvd(days: int = 30, api_key: str | None = None, page_limit: int = 5) -> int:
    """NVD CVE API 2.0 — pulls a recent window into the local CVE table."""
    feed = "nvd"
    end = datetime.now(UTC)
    start = end - timedelta(days=days)
    headers = {"apiKey": api_key} if api_key else {}
    imported = 0

    try:
        async with build_client(timeout=DEFAULT_TIMEOUT) as client:
            start_index = 0
            for _ in range(page_limit):
                response = await client.get(
                    NVD_API,
                    params={
                        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                        "resultsPerPage": 2000,
                        "startIndex": start_index,
                    },
                    headers=headers,
                )
                response.raise_for_status()
                payload = response.json()
                vulns = payload.get("vulnerabilities", [])
                if not vulns:
                    break
                async with session_scope() as session:
                    for item in vulns:
                        cve = item.get("cve", {})
                        cve_id = str(cve.get("id", "")).upper()
                        if not cve_id:
                            continue
                        descriptions = cve.get("descriptions", [])
                        description = next(
                            (d.get("value", "") for d in descriptions if d.get("lang") == "en"), ""
                        )
                        score, vector, severity = _best_cvss(cve.get("metrics", {}))
                        record = await session.get(CveRecord, cve_id)
                        if record is None:
                            record = CveRecord(cve_id=cve_id)
                            session.add(record)
                        record.description = description[:4000]
                        record.cvss_score = score
                        record.cvss_vector = vector
                        record.severity = severity
                        record.published = cve.get("published")
                        record.references = [
                            r.get("url") for r in (cve.get("references") or [])[:5] if r.get("url")
                        ]
                        imported += 1
                start_index += len(vulns)
                if start_index >= int(payload.get("totalResults", 0)):
                    break
                await asyncio.sleep(6 if not api_key else 0.6)  # NVD rate limits hard
    except Exception as exc:
        await _record_failure(feed, exc)
        return imported

    async with session_scope() as session:
        session.add(
            FeedRun(feed=feed, rows=imported, ok=True, detail=f"{days}d window, {imported} CVEs")
        )
    logger.info("feeds: nvd imported %d CVEs", imported)
    return imported


def _best_cvss(metrics: dict) -> tuple[float | None, str | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        data = entries[0].get("cvssData", {})
        return (
            float(data.get("baseScore")) if data.get("baseScore") is not None else None,
            data.get("vectorString"),
            data.get("baseSeverity") or entries[0].get("baseSeverity"),
        )
    return None, None, None


async def import_local_csv(path: str, feed: str, ioc_type: str = "ip") -> int:
    """Import an air-gapped CSV/TXT export (one indicator per line or column 1)."""
    with open(path, encoding="utf-8", errors="ignore") as handle:
        content = handle.read()
    rows: list[dict] = []
    reader = csv.reader(io.StringIO(content))
    for parts in reader:
        if not parts or parts[0].startswith("#"):
            continue
        value = parts[0].strip()
        if not value:
            continue
        rows.append(
            {
                "value": value,
                "ioc_type": ioc_type,
                "malware_family": parts[1].strip() if len(parts) > 1 else None,
                "confidence": 75,
                "first_seen": None,
                "last_seen": None,
                "extra": {"imported_from": path},
            }
        )
    return await _replace_feed(feed, rows)


async def feed_status() -> list[dict]:
    async with session_scope() as session:
        runs = (
            await session.execute(select(FeedRun).order_by(FeedRun.ran_at.desc()).limit(50))
        ).scalars().all()
        counts = {}
        entries = (await session.execute(select(FeedEntry.feed))).scalars().all()
        for feed in entries:
            counts[feed] = counts.get(feed, 0) + 1
        cve_count = len((await session.execute(select(CveRecord.cve_id))).scalars().all())

    latest: dict[str, dict] = {}
    for run in runs:
        if run.feed in latest:
            continue
        latest[run.feed] = {
            "feed": run.feed,
            "rows": run.rows,
            "ok": run.ok,
            "detail": run.detail,
            "ran_at": run.ran_at.isoformat() if run.ran_at else None,
            "stored_rows": counts.get(run.feed, 0),
        }
    for feed, count in counts.items():
        latest.setdefault(feed, {"feed": feed, "rows": count, "ok": True, "detail": "", "ran_at": None, "stored_rows": count})
    latest.setdefault("cve_records", {"feed": "cve_records", "rows": cve_count, "ok": True, "detail": "local NVD slice", "ran_at": None, "stored_rows": cve_count})
    return sorted(latest.values(), key=lambda item: item["feed"])
