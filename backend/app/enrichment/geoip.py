"""MaxMind GeoLite2 — offline geolocation and ASN, zero API cost.

Geo alone never convicts an IP; it contributes a small signal only when the
hosting context is one SOCs treat as elevated risk (bulletproof/anonymising
ASNs, sanctioned or high-abuse geographies), and it supplies the ASN/country
nodes that make the relationship graph readable.
"""
from __future__ import annotations

import logging

import httpx

from ..config import settings
from ..ioc import Indicator
from .base import STATUS_CLEAN, STATUS_OK, STATUS_SKIPPED, Provider, ProviderResult, Relation, Signal

logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    import geoip2.database
    import geoip2.errors
except ImportError:  # pragma: no cover
    geoip2 = None  # type: ignore[assignment]

# ASNs repeatedly associated with anonymisation or abuse-tolerant hosting.
ELEVATED_ASNS = {
    9009: "M247 (VPN/anonymising)",
    16276: "OVH (frequent abuse origin)",
    14061: "DigitalOcean (frequent abuse origin)",
    49505: "Selectel",
    200019: "Alexhost (bulletproof reputation)",
    58061: "Scalaxy",
    48666: "MAROSNET",
    204957: "ITHOST",
    60117: "Host Sailor",
    51852: "Private Layer",
}
ELEVATED_COUNTRIES = {"RU", "KP", "IR", "BY", "SY"}


class GeoIPProvider(Provider):
    name = "geoip"
    label = "MaxMind GeoLite2 (offline)"
    supported_types = {"ip"}
    requires_key = False
    cacheable = False  # local mmdb lookup is microseconds; caching adds nothing

    def __init__(self) -> None:
        self._city = None
        self._asn = None
        self._loaded = False

    def _load(self) -> None:
        if self._loaded or geoip2 is None:
            self._loaded = True
            return
        self._loaded = True
        try:
            if settings.geoip_city_db.exists():
                self._city = geoip2.database.Reader(str(settings.geoip_city_db))
            if settings.geoip_asn_db.exists():
                self._asn = geoip2.database.Reader(str(settings.geoip_asn_db))
        except Exception as exc:  # pragma: no cover
            logger.warning("geoip: failed to open database (%s)", exc)

    def configured(self) -> bool:
        self._load()
        return bool(self._city or self._asn)

    def reference_for(self, indicator: Indicator) -> str | None:
        return None

    async def fetch(self, client: httpx.AsyncClient, indicator: Indicator) -> ProviderResult:
        self._load()
        if not (self._city or self._asn):
            return self._result(
                indicator, status=STATUS_SKIPPED, error="GeoLite2 database not installed"
            )

        facts: dict = {}
        relations: list[Relation] = []
        tags: list[str] = []
        value = 0.0
        reasons: list[str] = []

        if self._city is not None:
            try:
                city = self._city.city(indicator.value)
                facts.update(
                    {
                        "country": city.country.iso_code,
                        "country_name": city.country.name,
                        "city": city.city.name,
                        "latitude": city.location.latitude,
                        "longitude": city.location.longitude,
                        "time_zone": city.location.time_zone,
                    }
                )
                if city.country.iso_code:
                    relations.append(
                        Relation(str(city.country.iso_code), "country", "located_in", 0.5)
                    )
                if city.country.iso_code in ELEVATED_COUNTRIES:
                    value = max(value, 0.35)
                    reasons.append(f"hosted in {city.country.iso_code}")
                    tags.append(f"geo:{city.country.iso_code}")
            except geoip2.errors.AddressNotFoundError:
                pass   # the expected miss: an address the database does not cover
            except Exception:
                # Anything else is a broken or unreadable database. Keep going,
                # because a lookup is best-effort, but say so: this used to be
                # swallowed, and a corrupt file would have looked like "no data".
                logger.warning("GeoIP city lookup failed", exc_info=True)

        if self._asn is not None:
            try:
                asn = self._asn.asn(indicator.value)
                facts.update(
                    {
                        "asn": asn.autonomous_system_number,
                        "as_org": asn.autonomous_system_organization,
                        "network": str(asn.network) if asn.network else None,
                    }
                )
                if asn.autonomous_system_number:
                    relations.append(
                        Relation(f"AS{asn.autonomous_system_number}", "asn", "announced_by", 0.6)
                    )
                note = ELEVATED_ASNS.get(int(asn.autonomous_system_number or 0))
                if note:
                    value = max(value, 0.4)
                    reasons.append(f"AS{asn.autonomous_system_number} — {note}")
                    tags.append("elevated-asn")
            except geoip2.errors.AddressNotFoundError:
                pass
            except Exception:
                logger.warning("GeoIP ASN lookup failed", exc_info=True)

        if not facts:
            return self._result(
                indicator, status=STATUS_CLEAN, facts={}, signals=[],
                error="address not present in local GeoLite2 database",
            )

        rationale = "; ".join(reasons) if reasons else (
            f"hosted in {facts.get('country_name') or 'unknown'}"
            f"{' on ' + str(facts.get('as_org')) if facts.get('as_org') else ''}"
        )
        return self._result(
            indicator,
            status=STATUS_OK,
            facts=facts,
            tags=tags,
            relations=relations,
            signals=[Signal("geoip", value, rationale)],
        )
