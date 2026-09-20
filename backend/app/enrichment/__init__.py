"""Provider registry.

Order here is display order in the UI timeline, not execution order: every
provider that supports an indicator is queried concurrently.
"""
from __future__ import annotations

from .abuseipdb import AbuseIPDBProvider
from .base import Provider, ProviderResult, Relation, Signal
from .geoip import GeoIPProvider
from .greynoise import GreyNoiseProvider
from .local_feeds import CveProvider, LocalFeedProvider, list_entry_for
from .otx import OTXProvider
from .threatfox import ThreatFoxProvider
from .urlhaus import URLhausProvider

PROVIDERS: list[Provider] = [
    AbuseIPDBProvider(),
    OTXProvider(),
    ThreatFoxProvider(),
    URLhausProvider(),
    GreyNoiseProvider(),
    LocalFeedProvider(),
    GeoIPProvider(),
    CveProvider(),
]

__all__ = [
    "PROVIDERS",
    "Provider",
    "ProviderResult",
    "Relation",
    "Signal",
    "list_entry_for",
]
