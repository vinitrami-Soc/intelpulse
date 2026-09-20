"""Composite scoring engine.

Why not just take AbuseIPDB's number? Because each free source is wrong in a
different direction: AbuseIPDB over-reports shared cloud egress, OTX inflates
on feed syndication, GreyNoise labels half the internet's scanners benign, and
abuse.ch only knows what it has confirmed. Triaging on any one of them alone is
how false positives reach a firewall change ticket.

The engine therefore computes two numbers and takes the higher:

  weighted mean   = Σ(weight_p × signal_p) / Σ(weight_p)      over providers
                    that actually answered — a dead API cannot deflate a verdict
  authority floor = max(signal_p × authority_p)               a confirmed C2
                    listing stays "critical" even if five other sources are quiet

then applies modifiers that encode analyst judgement:

  * GreyNoise `benign` (Shodan/Censys/academic scanners) multiplies the score
    down — noise, not an incident,
  * an analyst allowlist entry forces 0 (your own CDN is not an adversary),
  * an analyst blocklist entry forces >= 90,

and reports `confidence` separately from `score`, because "85/100 from one
source" and "85/100 from five" are different instructions to an analyst.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from .config import settings
from .enrichment.base import ProviderResult, Signal
from .ioc import Indicator
from .models import ListEntry

# How much a single source is trusted to convict on its own.
AUTHORITY = {
    "threatfox": 0.95,        # abuse.ch confirmed C2 / payload IOC
    "urlhaus": 0.95,          # confirmed malware distribution URL
    "local_blocklist": 0.90,  # curated historical C2 feeds
    "abuseipdb": 0.80,        # crowd-sourced, corroboration-weighted upstream
    "otx": 0.70,              # community pulses, prone to syndication
    "greynoise": 0.50,        # context provider more than a verdict provider
    "geoip": 0.30,            # hosting context only
}

VERDICTS = ("informational", "low", "medium", "high", "critical")

# Minimal local ATT&CK map: technique -> (name, tactic). Kept small and honest —
# these are the techniques this data can actually evidence.
ATTACK_TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1071": ("Application Layer Protocol", "Command and Control"),
    "T1071.001": ("Web Protocols", "Command and Control"),
    "T1090": ("Proxy", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1566": ("Phishing", "Initial Access"),
    "T1566.002": ("Spearphishing Link", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1583.003": ("Acquire Infrastructure: Virtual Private Server", "Resource Development"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1498": ("Network Denial of Service", "Impact"),
    "T1499": ("Endpoint Denial of Service", "Impact"),
    "T1078": ("Valid Accounts", "Defense Evasion"),
}

# Tag / family substrings that imply a technique when no ATT&CK id was supplied.
_TAG_TECHNIQUES: tuple[tuple[str, str], ...] = (
    ("brute", "T1110"),
    ("ssh", "T1110"),
    ("phish", "T1566"),
    ("ransom", "T1486"),
    ("locker", "T1486"),
    ("ddos", "T1498"),
    ("dos attack", "T1499"),
    ("port scan", "T1595"),
    ("scanner", "T1595"),
    ("web app attack", "T1190"),
    ("sql injection", "T1190"),
    ("exploit", "T1190"),
    ("proxy", "T1090"),
    ("tor", "T1090"),
    ("c2", "T1071"),
    ("botnet", "T1071"),
    ("cobalt", "T1071"),
    ("loader", "T1105"),
    ("stealer", "T1105"),
    ("payload", "T1105"),
)


@dataclass
class Contribution:
    provider: str
    signal: float
    weight: float
    weighted: float
    authority: float
    rationale: str


@dataclass
class IndicatorVerdict:
    indicator: Indicator
    score: int
    verdict: str
    confidence: float
    contributions: list[Contribution] = field(default_factory=list)
    modifiers: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    malware_families: list[str] = field(default_factory=list)
    attack_techniques: list[dict] = field(default_factory=list)
    providers_queried: int = 0
    providers_answered: int = 0

    @property
    def is_actionable(self) -> bool:
        return self.score >= settings.score_medium_threshold


def verdict_for(score: int) -> str:
    if score >= settings.score_high_threshold + 15:
        return "critical"
    if score >= settings.score_high_threshold:
        return "high"
    if score >= settings.score_medium_threshold:
        return "medium"
    if score >= settings.score_low_threshold:
        return "low"
    return "informational"


def derive_attack_ids(results: Iterable[ProviderResult]) -> list[str]:
    """Union of vendor-supplied ATT&CK ids plus tag/family heuristics."""
    found: list[str] = []

    def add(tid: str) -> None:
        tid = tid.strip().upper()
        if tid and tid not in found:
            found.append(tid)

    haystack: list[str] = []
    for result in results:
        for tid in result.attack_ids:
            add(tid)
        haystack.extend(t.lower() for t in result.tags)
        haystack.extend(f.lower() for f in result.malware_families)
        for key in ("top_categories", "threat_types"):
            value = result.facts.get(key)
            if isinstance(value, list):
                haystack.extend(str(v).lower() for v in value)

    blob = " ".join(haystack)
    for needle, tid in _TAG_TECHNIQUES:
        if needle in blob:
            add(tid)
    return found


def describe_techniques(attack_ids: Iterable[str]) -> list[dict]:
    described: list[dict] = []
    for tid in attack_ids:
        name, tactic = ATTACK_TECHNIQUES.get(tid, ("Unmapped technique", "Unknown"))
        described.append(
            {
                "id": tid,
                "name": name,
                "tactic": tactic,
                "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
            }
        )
    return described


def _weight_for(signal: Signal) -> float:
    return signal.weight_hint or settings.provider_weights.get(signal.key, 0.5)


def score_indicator(
    indicator: Indicator,
    results: list[ProviderResult],
    *,
    list_entry: ListEntry | None = None,
) -> IndicatorVerdict:
    contributions: list[Contribution] = []
    modifiers: list[str] = []
    weighted_sum = 0.0
    weight_total = 0.0
    authority_floor = 0.0

    answered = [r for r in results if r.answered]
    for result in answered:
        for signal in result.signals:
            weight = _weight_for(signal)
            if weight <= 0:
                continue
            value = signal.clamped()
            authority = AUTHORITY.get(signal.key, 0.5)
            weighted_sum += weight * value
            weight_total += weight
            authority_floor = max(authority_floor, value * authority)
            contributions.append(
                Contribution(
                    provider=result.provider,
                    signal=round(value, 3),
                    weight=weight,
                    weighted=round(weight * value, 3),
                    authority=authority,
                    rationale=signal.rationale,
                )
            )

    weighted_mean = (weighted_sum / weight_total) if weight_total else 0.0
    raw = max(weighted_mean, authority_floor)
    score = raw * 100

    # --- modifiers -------------------------------------------------------
    greynoise = next((r for r in answered if r.provider == "greynoise"), None)
    if greynoise and greynoise.facts.get("classification") == "benign":
        score *= settings.greynoise_benign_multiplier
        modifiers.append(
            f"GreyNoise classifies this as benign internet background noise "
            f"({greynoise.facts.get('actor') or 'known scanner'}) — score damped "
            f"x{settings.greynoise_benign_multiplier}"
        )
    if greynoise and greynoise.facts.get("riot"):
        score = min(score, 45)
        modifiers.append("GreyNoise RIOT: common business service, capped below High")

    if list_entry and list_entry.list_type == "allow":
        score = 0
        modifiers.append(f"analyst allowlist: {list_entry.reason or 'no reason recorded'}")
    elif list_entry and list_entry.list_type == "block":
        score = max(score, 90)
        modifiers.append(f"analyst blocklist: {list_entry.reason or 'no reason recorded'}")

    score_int = int(round(max(0.0, min(100.0, score))))

    # --- confidence -------------------------------------------------------
    # Confidence answers "how much should an analyst trust this number?", and it
    # has to cut both ways: a 0/100 backed by one source is not a clean bill of
    # health any more than an 85/100 backed by one source is a conviction.
    applicable = [r for r in results if r.status != "skipped"]
    coverage = (len(answered) / len(applicable)) if applicable else 0.0
    corroborating = sum(1 for c in contributions if c.signal >= 0.5)
    agreement = (
        min(1.0, corroborating / 2)
        if score_int >= settings.score_medium_threshold
        else min(1.0, len(answered) / 3)
    )
    confidence = round(min(1.0, 0.2 + 0.5 * coverage + 0.3 * agreement), 2)
    if list_entry:
        confidence = 1.0

    tags: list[str] = []
    families: list[str] = []
    for result in answered:
        for tag in result.tags:
            if tag not in tags:
                tags.append(tag)
        for family in result.malware_families:
            if family not in families:
                families.append(family)

    contributions.sort(key=lambda c: c.weighted, reverse=True)
    return IndicatorVerdict(
        indicator=indicator,
        score=score_int,
        verdict="allowlisted" if (list_entry and list_entry.list_type == "allow") else verdict_for(score_int),
        confidence=confidence,
        contributions=contributions,
        modifiers=modifiers,
        tags=tags[:12],
        malware_families=families[:8],
        attack_techniques=describe_techniques(derive_attack_ids(answered)),
        providers_queried=len(results),
        providers_answered=len(answered),
    )


def case_verdict(verdicts: list[IndicatorVerdict]) -> tuple[str, int]:
    """A case inherits its worst indicator — an analyst triages the worst first."""
    if not verdicts:
        return "informational", 0
    top = max(v.score for v in verdicts)
    return verdict_for(top), top
