"""AlienVault OTX — community pulses, malware families and ATT&CK mapping.

OTX is the only free source in this stack that hands back ATT&CK technique IDs
(`attack_ids` on a pulse), so it drives the MITRE tagging shown in the UI.
Pulse count is capped logarithmically: 40 pulses is not four times as damning
as 10, it usually means one popular feed got syndicated.
"""
from __future__ import annotations

import math

import httpx

from ..config import settings
from ..ioc import Indicator, hash_algorithm, url_host
from .base import STATUS_CLEAN, STATUS_OK, Provider, ProviderResult, Relation, Signal

BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

_SECTION = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}


class OTXProvider(Provider):
    name = "otx"
    label = "AlienVault OTX"
    supported_types = {"ip", "domain", "url", "hash"}

    def configured(self) -> bool:
        return bool(settings.otx_api_key)

    def reference_for(self, indicator: Indicator) -> str | None:
        section = _SECTION.get(indicator.type, "IPv4")
        return f"https://otx.alienvault.com/indicator/{section.lower()}/{indicator.value}"

    async def fetch(self, client: httpx.AsyncClient, indicator: Indicator) -> ProviderResult:
        section = _SECTION.get(indicator.type, "IPv4")
        if indicator.type == "ip" and ":" in indicator.value:
            section = "IPv6"
        headers = {"X-OTX-API-KEY": settings.otx_api_key or ""}

        response = await client.get(
            f"{BASE_URL}/{section}/{indicator.value}/general", headers=headers
        )
        if response.status_code == 404:
            return self._result(
                indicator,
                status=STATUS_CLEAN,
                facts={"pulse_count": 0},
                signals=[Signal("otx", 0.0, "indicator unknown to OTX")],
            )
        response.raise_for_status()
        data = response.json()

        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        pulse_count = int(pulse_info.get("count", len(pulses)) or 0)

        names: list[str] = []
        families: list[str] = []
        attack_ids: list[str] = []
        adversaries: list[str] = []
        tags: list[str] = []
        for pulse in pulses[:15]:
            if pulse.get("name"):
                names.append(str(pulse["name"])[:120])
            for family in pulse.get("malware_families", []) or []:
                display = family.get("display_name") if isinstance(family, dict) else family
                if display and display not in families:
                    families.append(str(display))
            for attack in pulse.get("attack_ids", []) or []:
                tid = attack.get("id") if isinstance(attack, dict) else attack
                if tid and tid not in attack_ids:
                    attack_ids.append(str(tid))
            if pulse.get("adversary"):
                adversaries.append(str(pulse["adversary"]))
            for tag in (pulse.get("tags") or [])[:6]:
                if tag not in tags:
                    tags.append(str(tag))

        # log1p keeps 1 pulse meaningful and 50 pulses from saturating instantly.
        value = min(1.0, math.log1p(pulse_count) / math.log1p(12)) if pulse_count else 0.0
        if families or adversaries:
            value = max(value, 0.75)

        relations = [Relation(f, "malware", "attributed_to", 0.7) for f in families[:6]]
        relations += [Relation(a, "actor", "attributed_to", 0.6) for a in dict.fromkeys(adversaries)]
        relations += [Relation(n, "pulse", "reported_in", 0.4) for n in names[:5]]

        facts = {
            "pulse_count": pulse_count,
            "pulse_names": names[:5],
            "malware_families": families[:6],
            "adversaries": list(dict.fromkeys(adversaries))[:4],
            "attack_ids": attack_ids[:10],
        }
        if indicator.type == "hash":
            facts["hash_algorithm"] = hash_algorithm(indicator.value)
        if indicator.type == "url":
            facts["host"] = url_host(indicator.value)
        for key in ("asn", "country_name", "city", "whois"):
            if data.get(key):
                facts[key] = data[key]

        return self._result(
            indicator,
            status=STATUS_OK if pulse_count else STATUS_CLEAN,
            facts=facts,
            tags=tags[:8],
            malware_families=families[:6],
            attack_ids=attack_ids[:10],
            relations=relations,
            signals=[
                Signal(
                    "otx",
                    value,
                    (
                        f"referenced in {pulse_count} OTX pulse(s)"
                        + (f"; families: {', '.join(families[:3])}" if families else "")
                        if pulse_count
                        else "no OTX pulses reference this indicator"
                    ),
                )
            ],
        )
