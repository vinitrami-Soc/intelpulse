"""How fast extraction runs, and whether it stays linear as the paste grows.

Two questions a SOC lead asks before pointing a tool at a day of logs:

* **Throughput** — lines per second, and indicators per second. An analyst
  pasting a 5,000-line export wants an answer, not a spinner.
* **Linearity** — does 10x the input cost 10x the time, or 100x? The extractor
  masks URLs by string replacement inside a loop, which is the kind of code that
  turns quadratic without anybody noticing until the day it matters.

Run: `python -m tests.corpus.benchmark`
"""
from __future__ import annotations

import gc
import time
import tracemalloc
from dataclasses import dataclass

from app.config import settings
from app.ioc import extract

from .generate import build_corpus


@dataclass
class Run:
    lines: int
    seconds: float
    indicators: int
    peak_kib: float
    per_line_ms: list[float]

    @property
    def lines_per_second(self) -> float:
        return self.lines / self.seconds

    @property
    def indicators_per_second(self) -> float:
        return self.indicators / self.seconds

    def percentile(self, p: float) -> float:
        ordered = sorted(self.per_line_ms)
        idx = min(int(len(ordered) * p), len(ordered) - 1)
        return ordered[idx]


def peak_kib(texts: list[str]) -> float:
    """Peak allocation, measured in its own pass.

    tracemalloc traces every allocation, so running it around the timing loop
    costs roughly 7x and the throughput number then describes the profiler
    rather than the parser. Memory and time are measured separately for that
    reason; do not fold them back together.
    """
    gc.collect()
    tracemalloc.start()
    for text in texts:
        extract(text)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return peak / 1024


def time_lines(count: int, repeats: int = 3) -> Run:
    """One line at a time — how the /extract endpoint is actually driven.

    Reports the best of `repeats` passes: on a shared machine the slow runs are
    other people's work, and the fastest pass is the closest available estimate
    of what the code costs.
    """
    texts = [line.text for line in build_corpus(count)]
    best: tuple[float, list[float], int] | None = None
    for _ in range(repeats):
        gc.collect()
        per_line: list[float] = []
        found = 0
        started = time.perf_counter()
        for text in texts:
            t0 = time.perf_counter()
            found += len(extract(text))
            per_line.append((time.perf_counter() - t0) * 1000)
        elapsed = time.perf_counter() - started
        if best is None or elapsed < best[0]:
            best = (elapsed, per_line, found)
    elapsed, per_line, found = best
    return Run(count, elapsed, found, peak_kib(texts), per_line)


def time_one_paste(count: int, repeats: int = 3) -> tuple[int, float, int]:
    """The whole corpus as a single paste — the quadratic risk lives here."""
    text = "\n".join(line.text for line in build_corpus(count))
    best = None
    found = 0
    for _ in range(repeats):
        gc.collect()
        started = time.perf_counter()
        found = len(extract(text))
        elapsed = time.perf_counter() - started
        best = elapsed if best is None else min(best, elapsed)
    return count, best, found


def main() -> None:
    settings.allow_documentation_ranges = True
    # Warm the regex caches so the first size does not pay for the rest.
    extract("warmup 192.0.2.1 example.com https://example.net/a")

    sizes = [1000, 2500, 5000, 10000]

    print("line at a time (as the API is driven)")
    print(f"{'lines':>7}{'sec':>9}{'lines/s':>11}{'iocs/s':>10}"
          f"{'p50 ms':>9}{'p95 ms':>9}{'p99 ms':>9}{'peak KiB':>10}")
    runs = []
    for size in sizes:
        r = time_lines(size)
        runs.append(r)
        print(f"{r.lines:>7}{r.seconds:>9.3f}{r.lines_per_second:>11,.0f}"
              f"{r.indicators_per_second:>10,.0f}{r.percentile(.50):>9.3f}"
              f"{r.percentile(.95):>9.3f}{r.percentile(.99):>9.3f}{r.peak_kib:>10,.0f}")

    print("\nsingle paste (whole corpus as one string)")
    print(f"{'lines':>7}{'sec':>9}{'lines/s':>11}{'iocs':>8}{'ms/line':>10}")
    pastes = []
    for size in sizes:
        n, secs, found = time_one_paste(size)
        pastes.append((n, secs))
        print(f"{n:>7}{secs:>9.3f}{n / secs:>11,.0f}{found:>8}{secs / n * 1000:>10.4f}")

    print("\nlinearity  (cost per line vs the smallest run; 1.0 = perfectly linear)")
    base_line = runs[0].seconds / runs[0].lines
    base_paste = pastes[0][1] / pastes[0][0]
    print(f"{'lines':>7}{'per-line':>12}{'per-paste':>12}")
    for r, (n, secs) in zip(runs, pastes, strict=True):
        print(f"{n:>7}{(r.seconds / r.lines) / base_line:>12.2f}"
              f"{(secs / n) / base_paste:>12.2f}")


if __name__ == "__main__":
    main()
