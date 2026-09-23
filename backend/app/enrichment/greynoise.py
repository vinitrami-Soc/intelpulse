"""GreyNoise Community API — separates targeted attacks from internet noise.

This is the provider that stops an analyst wasting an afternoon: if GreyNoise
classifies an IP as `benign` (Shodan, Censys, Qualys, academic scanners) the
composite score is multiplied down rather than left to look like an incident.
"""
from __future__ import annotations

from urllib.parse import quote

import httpx

from ..config import settings
from ..ioc import Indicator
from .base import (
    STATUS_CLEAN,
    STATUS_OK,
    STATUS_RATE_LIMITED,
    Provider,
    ProviderResult,
    Signal,
)

API_URL = "https://api.greynoise.io/v3/community/{ip}"


class GreyNoiseProvider(Provider):
    name = "greynoise"
    label = "GreyNoise"
    supported_types = {"ip"}
    reference_url = "https://viz.greynoise.io/ip/{ioc}"

    def configured(self) -> bool:
        return bool(settings.greynoise_api_key)

    async def fetch(self, client: httpx.AsyncClient, indicator: Indicator) -> ProviderResult:
        response = await client.get(
            API_URL.format(ip=quote(indicator.value, safe='')),
            headers={"key": settings.greynoise_api_key or "", "Accept": "application/json"},
        )
        if response.status_code == 429:
            return self._result(indicator, status=STATUS_RATE_LIMITED, error="daily quota exhausted")
        if response.status_code == 404:
            return self._result(
                indicator,
                status=STATUS_CLEAN,
                facts={"noise": False, "classification": "unseen"},
                signals=[
                    Signal(
                        "greynoise",
                        0.35,
                        "not seen scanning the internet, consistent with targeted activity",
                    )
                ],
            )
        response.raise_for_status()
        data = response.json()

        classification = str(data.get("classification", "unknown")).lower()
        noise = bool(data.get("noise"))
        riot = bool(data.get("riot"))

        value = {"malicious": 0.85, "suspicious": 0.55, "unknown": 0.3, "benign": 0.05}.get(
            classification, 0.3
        )
        rationale = {
            "malicious": "GreyNoise observed this IP conducting malicious mass scanning",
            "suspicious": "GreyNoise observed suspicious mass scanning from this IP",
            "benign": f"internet background noise: known scanner ({data.get('name') or 'unnamed'})",
            "unknown": "seen scanning but not yet classified",
        }.get(classification, "no classification available")
        if riot:
            rationale += "; RIOT: common business service"

        tags = [f"greynoise:{classification}"]
        if noise:
            tags.append("mass-scanner")
        if riot:
            tags.append("common-business-service")

        return self._result(
            indicator,
            status=STATUS_OK if (noise or riot) else STATUS_CLEAN,
            facts={
                "classification": classification,
                "noise": noise,
                "riot": riot,
                "actor": data.get("name"),
                "last_seen": data.get("last_seen"),
            },
            tags=tags,
            signals=[Signal("greynoise", value, rationale)],
        )
