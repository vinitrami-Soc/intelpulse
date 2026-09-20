from app.enrichment.base import STATUS_OK, ProviderResult, Signal
from app.ioc import Indicator
from app.models import ListEntry
from app.scoring import derive_attack_ids, score_indicator, verdict_for

IP = Indicator(value="185.220.101.34", type="ip")


def result(provider: str, key: str, value: float, **kwargs) -> ProviderResult:
    return ProviderResult(
        provider=provider,
        label=provider,
        ioc=IP.value,
        status=STATUS_OK,
        signals=[Signal(key, value, f"{provider} says {value}")],
        **kwargs,
    )


def test_single_authoritative_hit_still_reaches_high():
    """A confirmed ThreatFox C2 listing must not be averaged into oblivion."""
    results = [
        result("threatfox", "threatfox", 0.95, malware_families=["QakBot"]),
        result("abuseipdb", "abuseipdb", 0.0),
        result("otx", "otx", 0.0),
        result("geoip", "geoip", 0.0),
    ]
    verdict = score_indicator(IP, results)
    assert verdict.score >= 85
    assert verdict.verdict in ("high", "critical")


def test_unanswered_providers_do_not_deflate_the_score():
    answered = [result("abuseipdb", "abuseipdb", 0.9)]
    skipped = ProviderResult(provider="otx", label="otx", ioc=IP.value, status="skipped")
    with_skip = score_indicator(IP, answered + [skipped]).score
    without_skip = score_indicator(IP, answered).score
    assert with_skip == without_skip


def test_greynoise_benign_damps_the_verdict():
    noisy = [
        result("abuseipdb", "abuseipdb", 0.8),
        ProviderResult(
            provider="greynoise",
            label="greynoise",
            ioc=IP.value,
            status=STATUS_OK,
            signals=[Signal("greynoise", 0.05, "benign scanner")],
            facts={"classification": "benign", "actor": "Shodan"},
        ),
    ]
    damped = score_indicator(IP, noisy)
    undamped = score_indicator(IP, [result("abuseipdb", "abuseipdb", 0.8)])
    assert damped.score < undamped.score
    assert any("background noise" in m for m in damped.modifiers)


def test_allowlist_forces_zero_and_blocklist_forces_high():
    results = [result("threatfox", "threatfox", 0.95)]
    allowed = score_indicator(
        IP, results, list_entry=ListEntry(value=IP.value, list_type="allow", reason="our CDN")
    )
    assert allowed.score == 0 and allowed.verdict == "allowlisted"

    blocked = score_indicator(
        IP,
        [result("abuseipdb", "abuseipdb", 0.0)],
        list_entry=ListEntry(value=IP.value, list_type="block", reason="IR-2024-11"),
    )
    assert blocked.score >= 90


def test_confidence_rises_with_corroboration():
    one_source = score_indicator(IP, [result("abuseipdb", "abuseipdb", 0.9)])
    many_sources = score_indicator(
        IP,
        [
            result("abuseipdb", "abuseipdb", 0.9),
            result("otx", "otx", 0.8),
            result("threatfox", "threatfox", 0.9),
        ],
    )
    assert many_sources.confidence > one_source.confidence


def test_attack_ids_are_derived_from_tags_when_absent():
    results = [
        result("abuseipdb", "abuseipdb", 0.7, tags=["SSH", "Brute-Force"]),
        result("urlhaus", "urlhaus", 0.9, malware_families=["Emotet loader"]),
    ]
    ids = derive_attack_ids(results)
    assert "T1110" in ids and "T1105" in ids
    verdict = score_indicator(IP, results)
    assert any(t["tactic"] == "Credential Access" for t in verdict.attack_techniques)


def test_verdict_bands():
    assert verdict_for(5) == "informational"
    assert verdict_for(20) == "low"
    assert verdict_for(50) == "medium"
    assert verdict_for(72) == "high"
    assert verdict_for(95) == "critical"
