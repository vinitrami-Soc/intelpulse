"""What changed since the last time this indicator was triaged.

An analyst re-scanning an address five days later does not want the same verdict
screen again — they want the delta: did it get worse, did a new source start
answering, did a fresh ThreatFox pulse appear. Everything needed to answer that
is already stored per indicator; these tests pin the arithmetic that reads it.

The comparison is a pure function over two snapshots, so it is testable without
a database and can be mirrored in the browser engine for demo mode.
"""
from __future__ import annotations

from app.services.history import BANDS, diff_snapshots, snapshot_from_payload


def snap(score=50, verdict="medium", sources=("otx",), families=(), attack=()):
    return {
        "score": score,
        "verdict": verdict,
        "answering": sorted(sources),
        "malware_families": sorted(families),
        "attack_ids": sorted(attack),
    }


def test_a_first_sighting_is_marked_as_one():
    d = diff_snapshots(snap(), None)
    assert d.first_seen is True
    assert d.score_delta == 0
    assert d.verdict_changed is False
    assert d.escalated is False
    assert d.summary == "First time this indicator has been triaged."


def test_an_unchanged_indicator_reports_nothing_changed():
    before = snap(score=62, verdict="medium", sources=("otx", "abuseipdb"))
    d = diff_snapshots(dict(before), before)
    assert d.first_seen is False
    assert d.changed is False
    assert d.score_delta == 0
    assert d.sources_added == [] and d.sources_removed == []
    assert d.summary == "No change since the last triage."


def test_a_rising_score_is_a_delta_and_an_escalation():
    before = snap(score=62, verdict="medium")
    after = snap(score=91, verdict="critical")
    d = diff_snapshots(after, before)
    assert d.score_delta == 29
    assert d.verdict_changed is True
    assert d.escalated is True
    assert d.previous_verdict == "medium"
    assert "medium" in d.summary and "critical" in d.summary


def test_a_falling_score_is_a_de_escalation_not_an_escalation():
    d = diff_snapshots(snap(score=20, verdict="low"), snap(score=80, verdict="high"))
    assert d.score_delta == -60
    assert d.verdict_changed is True
    assert d.escalated is False
    assert d.de_escalated is True


def test_a_source_that_started_answering_is_named():
    before = snap(sources=("otx",))
    after = snap(sources=("otx", "threatfox"))
    d = diff_snapshots(after, before)
    assert d.sources_added == ["threatfox"]
    assert d.sources_removed == []
    assert "threatfox" in d.summary


def test_a_source_that_stopped_answering_is_named():
    d = diff_snapshots(snap(sources=("otx",)), snap(sources=("otx", "greynoise")))
    assert d.sources_removed == ["greynoise"]
    assert d.sources_added == []


def test_new_malware_families_and_techniques_are_listed():
    before = snap(families=("SampleLoader",), attack=("T1071",))
    after = snap(families=("SampleLoader", "SampleBot"), attack=("T1071", "T1105"))
    d = diff_snapshots(after, before)
    assert d.new_malware_families == ["SampleBot"]
    assert d.new_attack_ids == ["T1105"]


def test_families_that_disappeared_are_not_reported_as_new():
    d = diff_snapshots(snap(families=("A",)), snap(families=("A", "B")))
    assert d.new_malware_families == []


def test_the_band_order_runs_from_informational_to_critical():
    assert BANDS.index("informational") < BANDS.index("low") < BANDS.index("medium")
    assert BANDS.index("medium") < BANDS.index("high") < BANDS.index("critical")


def test_an_unknown_band_does_not_crash_the_comparison():
    """Bands come out of storage, and storage outlives any one release."""
    d = diff_snapshots(snap(verdict="medium"), snap(verdict="weird-old-band"))
    assert d.verdict_changed is True
    assert d.escalated is False and d.de_escalated is False


def test_a_snapshot_reads_answering_sources_out_of_a_stored_payload():
    payload = {
        "score": 90,
        "verdict": "critical",
        "malware_families": ["SamplePhishKit"],
        "attack_techniques": [{"id": "T1566.002"}, {"id": "T1566"}],
        "sources": [
            {"provider": "urlhaus", "status": "ok"},
            {"provider": "otx", "status": "clean"},
            {"provider": "threatfox", "status": "skipped"},
            {"provider": "greynoise", "status": "error"},
        ],
    }
    s = snapshot_from_payload(payload)
    assert s["answering"] == ["otx", "urlhaus"], "skipped and errored sources did not answer"
    assert s["attack_ids"] == ["T1566", "T1566.002"]
    assert s["malware_families"] == ["SamplePhishKit"]
    assert s["score"] == 90


def test_a_snapshot_survives_a_payload_that_is_missing_everything():
    s = snapshot_from_payload({})
    assert s == {"score": 0, "verdict": "informational",
                 "answering": [], "malware_families": [], "attack_ids": []}


def test_the_summary_leads_with_the_escalation_not_the_sources():
    """An analyst reads the first clause. It should be the part that matters."""
    before = snap(score=40, verdict="medium", sources=("otx",))
    after = snap(score=92, verdict="critical", sources=("otx", "threatfox"))
    d = diff_snapshots(after, before)
    assert d.summary.startswith("Escalated")
