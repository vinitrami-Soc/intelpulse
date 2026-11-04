"""The report's executive briefing: the bottom line, the first steps and how sure the case is.

The cases and the words are pinned in fixtures/briefing.json, which web/tests/engine.test.mjs reads
too: the demo and a server have to brief an analyst identically."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.ioc import Indicator
from app.reporting import bottom_line, first_steps, how_sure, to_markdown, to_ticket_json
from app.scoring import Contribution, IndicatorVerdict

CASES = json.loads((Path(__file__).parent / "fixtures" / "briefing.json").read_text())["cases"]


def verdicts_of(case: dict) -> list[IndicatorVerdict]:
    return [IndicatorVerdict(
        indicator=Indicator(value=i["value"], type=i["type"]), score=i["score"], verdict=i["verdict"],
        confidence=i["confidence"], malware_families=i["malware_families"],
        providers_queried=i["providers_queried"], providers_answered=i["providers_answered"],
        contributions=[Contribution(provider=e["provider"], signal=e["signal"], weight=e["weight"],
                                    weighted=e["signal"] * e["weight"], authority=0.5, rationale="")
                       for e in i["evidence"]])
        for i in case["indicators"]]


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_the_briefing_says_what_the_fixture_pins(case):
    verdicts = verdicts_of(case)
    assert bottom_line(case["verdict"]) == case["expected"]["bottom_line"]
    assert first_steps(verdicts) == case["expected"]["first_steps"]
    assert how_sure(verdicts) == case["expected"]["how_sure"]


def test_the_report_opens_with_the_priority_and_briefs_before_the_detail():
    case = CASES[0]
    report = to_markdown("c1", "IR-2026-120", verdicts_of(case), "critical", 90)
    lines = report.splitlines()
    assert lines[0] == "# SOC Triage Report: IR-2026-120"
    assert lines[2] == "> **P1: contain within 1 hour** · case CRITICAL, 90/100 · 3 of 4 indicators actionable"
    summary = report.split("## 1. Executive summary")[1].split("## 2.")[0]
    order = [summary.index(part) for part in ("**Bottom line:**", "**What we found:**", "**What to do now:**", "**How sure:**")]
    assert order == sorted(order)
    assert "1. Block the full URL" in summary and "3. Block the address" in summary


def test_each_address_keeps_its_own_block_step_in_the_checklist():
    """Two addresses, one action text: the second used to be dropped, so nothing said to block it."""
    report = to_markdown("c1", "IR-2026-120", verdicts_of(CASES[0]), "critical", 90)
    checklist = report.split("## 4. Recommended containment actions")[1].split("## 5.")[0]
    assert checklist.count("- [ ] Block the address at the perimeter firewall") == 2
    assert checklist.count("Raise a major-incident bridge") == 1


def test_an_indicator_nobody_reported_on_says_so():
    report = to_markdown("c1", "IR-2026-120", verdicts_of(CASES[0]), "critical", 90)
    evidence = report.split("### `mail[.]example[.]net`: INFORMATIONAL (0/100)")[1].split("##")[0]
    assert "- No source reported anything about this indicator." in evidence
    assert "| `mail[.]example[.]net` | domain | 0/100 `░░░░░░░░░░` | **INFORMATIONAL** | 20% | none answered |" in report


def test_the_notes_give_the_levels_and_the_json_carries_the_briefing():
    report = to_markdown("c1", "IR-2026-120", verdicts_of(CASES[0]), "critical", 90)
    assert "- **Levels:** critical 85 and up, high 70 to 84, medium 40 to 69, low 15 to 39, informational below 15." in report
    briefing = to_ticket_json("c1", "IR-2026-120", verdicts_of(CASES[0]), "critical", 90)["briefing"]
    assert briefing["bottom_line"] == CASES[0]["expected"]["bottom_line"]
    assert briefing["first_steps"][1] == "Block the address at the perimeter firewall and on egress proxies: 198[.]51[.]100[.]7."
