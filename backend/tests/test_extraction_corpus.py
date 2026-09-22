"""Aggregate extraction accuracy over the multi-format corpus.

`test_extraction_findings.py` pins individual bugs by name. This file holds the
number: precision and recall over 3,400 generated lines in 15 log formats, with
a floor low enough not to break when a format is added and high enough that any
of the five bugs the corpus originally found would fail it again.

Run `python -m tests.corpus.report` to regenerate docs/EXTRACTION-BENCHMARK.md.
"""
from __future__ import annotations

import pytest

from app.config import settings
from tests.corpus import build_corpus
from tests.corpus.measure import measure


@pytest.fixture(scope="module", autouse=True)
def documentation_ranges_on():
    """The corpus addresses the only space it is safe to generate.

    RFC 5737 documentation ranges are non-routable, so extraction drops them by
    default. The corpus uses them precisely because they can never be a real
    target, which means it has to opt back in — otherwise every expected address
    reads as a miss and the recall number measures the setting, not the parser.
    """
    previous = settings.allow_documentation_ranges
    settings.allow_documentation_ranges = True
    yield
    settings.allow_documentation_ranges = previous

# Measured at 100.0%/100.0% (see docs/EXTRACTION-BENCHMARK.md). The floor sits
# below that deliberately: pinning a test to a perfect score makes adding a
# format a test failure rather than a measurement. 99% of 9,325 expected
# indicators still means fewer than 94 errors, and each of the five findings
# cost far more than that — the username bug alone was 318.
MIN_PRECISION = 0.99
MIN_RECALL = 0.99
# Per format the sample is smaller, so one bad line moves the number further.
MIN_FORMAT_PRECISION = 0.97
MIN_FORMAT_RECALL = 0.97


@pytest.fixture(scope="module")
def result():
    return measure(build_corpus())


def test_the_corpus_is_the_size_it_claims(result):
    assert result.overall.lines == 3400
    assert len(result.per_format) == 15


def test_overall_precision(result):
    score = result.overall
    worst = result.false_positives.most_common(3)
    assert score.precision >= MIN_PRECISION, (
        f"precision {score.precision:.3%} ({score.fp} false positives); worst: {worst}"
    )


def test_overall_recall(result):
    score = result.overall
    worst = result.misses.most_common(3)
    assert score.recall >= MIN_RECALL, (
        f"recall {score.recall:.3%} ({score.fn} missed); worst: {worst}"
    )


def test_every_format_holds_its_own(result):
    """An average hides a format that fails completely."""
    poor = {
        fmt: (s.precision, s.recall)
        for fmt, s in result.per_format.items()
        if s.precision < MIN_FORMAT_PRECISION or s.recall < MIN_FORMAT_RECALL
    }
    assert not poor, f"formats below floor: {poor}"


def test_no_trap_is_ever_sprung(result):
    """Zero tolerance, unlike the percentages above.

    A trap is a private address, a CGNAT address, a filename or a version string
    that the line explicitly marks as must-not-extract. Extracting one is not a
    rounding error in a score — it is an internal address or an employee's file
    name being sent to a third-party API, which is the failure this whole
    corpus exists to prevent.
    """
    assert not result.sprung_traps, (
        f"{sum(result.sprung_traps.values())} traps sprung: "
        f"{result.sprung_traps.most_common(10)}"
    )


def test_the_corpus_actually_contains_traps():
    """Guards the test above from passing because there was nothing to catch."""
    corpus = build_corpus()
    with_traps = [line for line in corpus if line.traps]
    assert len(with_traps) > len(corpus) // 2, (
        f"only {len(with_traps)}/{len(corpus)} lines carry a trap; "
        "test_no_trap_is_ever_sprung would be vacuous"
    )


def test_the_corpus_is_deterministic():
    """A number quoted from this corpus has to be reproducible."""
    first, second = build_corpus(200), build_corpus(200)
    assert [line.text for line in first] == [line.text for line in second]
    assert [sorted(line.expect) for line in first] == [sorted(line.expect) for line in second]
