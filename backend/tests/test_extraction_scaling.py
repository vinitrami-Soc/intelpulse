"""Extraction must stay linear in the size of the input.

The /triage/upload endpoint hands `extract()` up to 5 MB in one string, from a
synchronous call inside an async handler — so a quadratic term there does not
merely run slowly, it blocks every other request on the worker for the duration.
It has happened once already: masking URLs with one `str.replace` per URL, and
re-finding each indicator's offset with `str.find`, together made a legal 5 MB
upload take 14.1 seconds. After both were made single-pass the same input takes
1.4 seconds.

This test compares cost per character at two sizes rather than asserting a
wall-clock budget, so it means the same thing on a fast laptop and a loaded CI
box. Quadratic growth shows up here as a ratio near the size multiple (8x);
linear growth sits near 1.
"""
from __future__ import annotations

import gc
import time

import pytest

from app.config import settings
from app.ioc import extract
from tests.corpus import build_corpus

SMALL, LARGE = 250, 8000          # a 32x size step

# The step and the bar are both measured, not guessed. Over 250 -> 8,000 lines
# (65 KB -> 2.1 MB) the two versions of extract() separate cleanly:
#
#     quadratic (before the fix)   1.00x -> 3.60x
#     linear    (after the fix)    1.00x -> 0.94x
#
# 2.0 sits between them with roughly 2x headroom on each side. An 8x step was
# tried first and rejected: the quadratic term had not taken over yet at 2,000
# lines, so the old code passed and the guard was worth nothing.
MAX_GROWTH = 2.0


@pytest.fixture(scope="module", autouse=True)
def documentation_ranges_on():
    previous = settings.allow_documentation_ranges
    settings.allow_documentation_ranges = True
    yield
    settings.allow_documentation_ranges = previous


def seconds_per_char(lines: int, repeats: int = 3) -> float:
    """Best of `repeats`: a slow run is another process, not this code."""
    text = "\n".join(line.text for line in build_corpus(lines))
    extract(text[:2000])                      # warm the regex caches
    best = None
    for _ in range(repeats):
        gc.collect()
        started = time.perf_counter()
        extract(text)
        elapsed = time.perf_counter() - started
        best = elapsed if best is None else min(best, elapsed)
    return best / len(text)


def test_one_large_paste_costs_no_more_per_character_than_a_small_one():
    small = seconds_per_char(SMALL)
    large = seconds_per_char(LARGE)
    growth = large / small
    assert growth < MAX_GROWTH, (
        f"cost per character grew {growth:.2f}x over an "
        f"{LARGE // SMALL}x larger input ({small * 1e9:.1f} -> {large * 1e9:.1f} ns/char). "
        "Something in extract() is scanning the whole input per match again."
    )
