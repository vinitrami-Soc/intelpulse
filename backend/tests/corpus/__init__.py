"""A multi-format log corpus with ground truth, for measuring extraction.

Why this exists
---------------
The extractor had eight tests over about five sample lines. Regexes that survive
five lines routinely die on five thousand: a Zeek TSV column boundary, a
PAN-OS comma inside a quoted field, a Windows event that writes `-` where an
address should be. This module generates thousands of lines in the shapes a SOC
actually receives, each carrying the exact set of indicators it should yield, so
precision and recall can be *measured* rather than asserted.

Every line is generated, not collected. That is deliberate:

* **Nothing here is a real host.** Addresses come from RFC 5737 documentation
  space (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and domains from RFC
  2606 reserved names. Nothing in this corpus can be resolved, contacted, or
  mistaken for a real target — and the tests never make a request anyway.
* **Real formats, synthetic content.** The framing — the ASA severity code, the
  Zeek column order, the CloudTrail envelope — is exactly what those products
  emit. That framing is what the parser has to survive, and it is the part being
  tested.
* **Deterministic.** One seed, one corpus. A number quoted from this corpus can
  be reproduced by anyone who runs the generator.

Ground truth is the contract, not the implementation
----------------------------------------------------
`expect` holds what the extractor *should* return, derived from the documented
rules in `app/ioc.py`: public addresses yes, RFC 1918 and loopback no, plausible
domains yes, `svchost.exe` no. Where the implementation disagrees with `expect`,
the test reports it as a miss or a false positive — which is the entire point.
A corpus built from the implementation's own output would measure nothing.

Traps
-----
76% of the lines carry something that *looks* extractable and must not be:
private, link-local and carrier-grade-NAT addresses, file names with
domain-shaped extensions, version strings, and Windows' habit of writing `-` for
an absent value. Precision without traps is meaningless, so
`test_extraction_corpus.py` asserts the trap density as well as the score — a
zero-tolerance check against a corpus with nothing to catch is worth nothing.

The exception is the small set of labels that are both a live TLD and a common
file extension (`.zip`, `.mov`, `.sh`, `.md`, `.pub`). A bare one in a log line
is a file; the same label in a URL host is a domain. Which reading is right
depends on position rather than on the value, so the corpus carries only the
bare form and the split is pinned by name in `test_extraction_findings.py`.
"""
from __future__ import annotations

from .generate import FORMATS, CorpusLine, build_corpus

__all__ = ["CorpusLine", "build_corpus", "FORMATS"]
