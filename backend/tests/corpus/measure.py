"""Score the extractor against the corpus. Shared by the test and the report.

Kept separate from both so the number in `docs/EXTRACTION-BENCHMARK.md` and the
number the test enforces come from one piece of code and cannot drift.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field

from app.ioc import extract

from .generate import CorpusLine, build_corpus


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    lines: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0


@dataclass
class Measurement:
    overall: Score = field(default_factory=Score)
    per_format: dict[str, Score] = field(default_factory=lambda: defaultdict(Score))
    false_positives: Counter = field(default_factory=Counter)
    misses: Counter = field(default_factory=Counter)
    # A trap the extractor fell for: a value the line explicitly marked as
    # must-not-extract. These are the security-relevant failures — a private
    # address or an employee's filename leaving the building — so they are
    # counted apart from ordinary false positives.
    sprung_traps: Counter = field(default_factory=Counter)


def measure(corpus: list[CorpusLine] | None = None) -> Measurement:
    corpus = build_corpus() if corpus is None else corpus
    m = Measurement()
    for line in corpus:
        got = {(i.value, i.type) for i in extract(line.text)}
        want = line.expect
        fmt = m.per_format[line.fmt]
        fmt.lines += 1
        m.overall.lines += 1
        for score in (m.overall, fmt):
            score.tp += len(got & want)
            score.fp += len(got - want)
            score.fn += len(want - got)
        for value, kind in got - want:
            m.false_positives[(line.fmt, kind, value)] += 1
            if value in line.traps:
                m.sprung_traps[(line.fmt, value)] += 1
        for value, kind in want - got:
            m.misses[(line.fmt, kind, value)] += 1
    return m
