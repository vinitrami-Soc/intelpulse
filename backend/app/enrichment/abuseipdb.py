"""AbuseIPDB — crowd-sourced abuse reports for IPv4/IPv6.

Free tier: 1 000 checks/day. The confidence score is already 0-100, but a high
score on a single stale report is weaker evidence than the same score backed by
80 reporters, so the signal is damped when the reporter count is very low.
"""
from __future__ import annotations

import httpx

from ..config import settings
from ..ioc import Indicator
from .base import STATUS_CLEAN, STATUS_OK, STATUS_RATE_LIMITED, Provider, ProviderResult, Relation, Signal

API_URL = "https://api.abuseipdb.com/api/v2/check"

CATEGORY_NAMES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    14: "Port Scan", 15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


class AbuseIPDBProvider(Provider):
    name = "abuseipdb"
    label = "AbuseIPDB"
    supported_types = {"ip"}
    reference_url = "https://www.abuseipdb.com/check/{ioc}"

    def configured(self) -> bool:
        return bool(settings.abuseipdb_api_key)

    async def fetch(self, client: httpx.AsyncClient, indicator: Indicator) -> ProviderResult:
        response = await client.get(
            API_URL,
            params={
                "ipAddress": indicator.value,
                "maxAgeInDays": settings.abuseipdb_max_age_days,
                "verbose": "",
            },
            headers={"Key": settings.abuseipdb_api_key or "", "Accept": "application/json"},
        )
        if response.status_code == 429:
            return self._result(indicator, status=STATUS_RATE_LIMITED, error="daily quota exhausted")
        response.raise_for_status()
        data = response.json().get("data", {})

        confidence = int(data.get("abuseConfidenceScore", 0) or 0)
        total_reports = int(data.get("totalReports", 0) or 0)
        distinct = int(data.get("numDistinctUsers", 0) or 0)

        # Low corroboration damps the vendor score: 1 reporter != 80 reporters.
        corroboration = min(1.0, 0.45 + 0.55 * min(distinct, 10) / 10) if total_reports else 0.0
        value = (confidence / 100) * corroboration

        categories: list[str] = []
        for report in (data.get("reports") or [])[:25]:
            for cat in report.get("categories", []):
                name = CATEGORY_NAMES.get(int(cat))
                if name and name not in categories:
                    categories.append(name)

        facts = {
            "abuse_confidence": confidence,
            "total_reports_90d": total_reports,
            "distinct_reporters": distinct,
            "last_reported": data.get("lastReportedAt"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
            "domain": data.get("domain"),
            "country": data.get("countryCode"),
            "is_tor": bool(data.get("isTor")),
            "is_whitelisted": bool(data.get("isWhitelisted")),
            "top_categories": categories[:6],
        }

        relations: list[Relation] = []
        if data.get("domain"):
            relations.append(Relation(str(data["domain"]), "domain", "registered_to_isp", 0.4))

        tags = list(categories[:6])
        if facts["is_tor"]:
            tags.append("tor-exit-node")

        status = STATUS_OK if total_reports else STATUS_CLEAN
        return self._result(
            indicator,
            status=status,
            facts=facts,
            tags=tags,
            relations=relations,
            signals=[
                Signal(
                    key="abuseipdb",
                    value=value,
                    rationale=(
                        f"{confidence}% abuse confidence from {total_reports} reports "
                        f"by {distinct} reporters in the last {settings.abuseipdb_max_age_days} days"
                        if total_reports
                        else "no abuse reports on record"
                    ),
                )
            ],
        )
