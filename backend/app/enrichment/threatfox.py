"""abuse.ch ThreatFox — C2 infrastructure and payload IOCs by malware family."""
from __future__ import annotations

import httpx

from ..config import settings
from ..ioc import Indicator
from .base import STATUS_CLEAN, STATUS_OK, Provider, ProviderResult, Relation, Signal

API_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFoxProvider(Provider):
    name = "threatfox"
    label = "ThreatFox (abuse.ch)"
    supported_types = {"ip", "domain", "url", "hash"}
    requires_key = False
    reference_url = "https://threatfox.abuse.ch/browse.php?search=ioc%3A{ioc}"

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if settings.abusech_auth_key:
            headers["Auth-Key"] = settings.abusech_auth_key
        return headers

    async def fetch(self, client: httpx.AsyncClient, indicator: Indicator) -> ProviderResult:
        response = await client.post(
            API_URL,
            json={"query": "search_ioc", "search_term": indicator.value, "exact_match": True},
            headers=self._headers(),
        )
        response.raise_for_status()
        payload = response.json()

        if payload.get("query_status") != "ok" or not payload.get("data"):
            return self._result(
                indicator,
                status=STATUS_CLEAN,
                facts={"matches": 0},
                signals=[Signal("threatfox", 0.0, "no ThreatFox IOC match")],
            )

        entries = payload["data"] if isinstance(payload["data"], list) else [payload["data"]]
        families: list[str] = []
        tags: list[str] = []
        threat_types: list[str] = []
        confidence = 0
        first_seen = None
        for entry in entries[:10]:
            family = entry.get("malware_printable") or entry.get("malware")
            if family and family not in families:
                families.append(str(family))
            threat_type = entry.get("threat_type")
            if threat_type and threat_type not in threat_types:
                threat_types.append(str(threat_type))
            for tag in entry.get("tags") or []:
                if tag and tag not in tags:
                    tags.append(str(tag))
            confidence = max(confidence, int(entry.get("confidence_level", 0) or 0))
            first_seen = first_seen or entry.get("first_seen")

        value = max(0.6, confidence / 100) if entries else 0.0
        attack_ids = []
        if any("c2" in t.lower() or "botnet" in t.lower() for t in threat_types):
            attack_ids.append("T1071")   # Application Layer Protocol (C2)

        return self._result(
            indicator,
            status=STATUS_OK,
            facts={
                "matches": len(entries),
                "malware_families": families,
                "threat_types": threat_types,
                "confidence_level": confidence,
                "first_seen": first_seen,
                "reporter": entries[0].get("reporter"),
            },
            tags=tags[:8],
            malware_families=families,
            attack_ids=attack_ids,
            relations=[Relation(f, "malware", "attributed_to", 0.9) for f in families],
            signals=[
                Signal(
                    "threatfox",
                    value,
                    f"listed as active {', '.join(threat_types) or 'threat'} infrastructure"
                    + (f" for {', '.join(families[:3])}" if families else "")
                    + f" (abuse.ch confidence {confidence}%)",
                )
            ],
        )
