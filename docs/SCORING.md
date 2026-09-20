# The composite scoring model

## Why not just use one vendor's number?

Each free source is wrong in a different, predictable direction:

| Source | Known failure mode |
| --- | --- |
| AbuseIPDB | Over-reports shared cloud egress and NAT ranges; a single angry reporter can push a score to 100 |
| AlienVault OTX | Inflates on syndication — one popular feed republished by forty users looks like forty independent sightings |
| GreyNoise | Labels a large share of the internet's scanners `benign`, which is correct but easy to over-apply |
| abuse.ch (ThreatFox / URLhaus) | Precise but narrow: it only knows what it has confirmed, so silence means nothing |
| GeoIP / ASN | Context, never evidence — plenty of legitimate traffic comes from cheap hosting |

Triaging on any one of them is how a false positive reaches a firewall change ticket. The engine's job
is to combine them in a way an analyst can argue with.

## The formula

```
weighted_mean  = Σ(weight_p × signal_p) / Σ(weight_p)     over providers that ANSWERED
authority_floor = max(signal_p × authority_p)             over the same providers

score = 100 × max(weighted_mean, authority_floor)
```

Then modifiers, in order:

1. **GreyNoise `benign`** → `score ×= 0.45` and the reason is recorded on the result.
2. **GreyNoise RIOT** (common business service: Microsoft, Google, CDNs) → `score = min(score, 45)`.
3. **Analyst allowlist** → `score = 0`, verdict becomes `allowlisted`.
4. **Analyst blocklist** → `score = max(score, 90)`.

### Why two numbers and not just an average

A plain mean punishes narrow-but-certain evidence. If ThreatFox confirms an IP as live QakBot C2 and
five other sources simply have no record, the mean drags the verdict toward "informational" — which is
exactly backwards. The **authority floor** keeps a confirmed listing at the top of the queue.

Conversely, the floor alone would over-convict on weak single sources, so the mean still governs when
many sources each contribute a little.

### Why "providers that answered"

Normalising over the providers that returned data means an unconfigured key or a rate-limited vendor
cannot deflate a verdict. A missing source reduces **confidence**, never the score.

## Default weights and authority

| Provider | Weight | Authority | Reasoning |
| --- | --- | --- | --- |
| ThreatFox | 1.2 | 0.95 | Confirmed, curated C2/payload IOCs |
| URLhaus | 1.1 | 0.95 | Confirmed malware distribution URLs |
| AbuseIPDB | 1.0 | 0.80 | Large corpus, noisy; damped upstream by reporter count |
| Local historical feeds | 1.0 | 0.90 | Feodo/FireHOL/ThreatFox dumps — curated, offline, no quota |
| AlienVault OTX | 0.9 | 0.70 | Broad but syndication-prone |
| GreyNoise | 0.6 | 0.50 | Primarily a context provider |
| GeoIP / ASN | 0.25 | 0.30 | Hosting context only, never evidence on its own |

All seven are environment variables (`WEIGHT_THREATFOX`, …). `GET /api/scoring/model` returns the live
values so any verdict can be reproduced and audited.

## Per-provider signal normalisation

* **AbuseIPDB** — `(confidence / 100) × corroboration`, where corroboration rises from 0.45 to 1.0 with
  the number of distinct reporters. One reporter at 100% is not eighty reporters at 100%.
* **OTX** — `log1p(pulses) / log1p(12)`, capped at 1.0, floored at 0.75 when a malware family or named
  adversary is attached. 40 pulses is not four times as damning as 10.
* **ThreatFox** — `max(0.6, confidence_level / 100)` on any exact match.
* **URLhaus** — 0.95 if the URL/host is currently online, 0.7 for a historic listing.
* **GreyNoise** — malicious 0.85 · suspicious 0.55 · unknown 0.30 · benign 0.05 · unseen 0.35
  (an IP that has never been seen scanning is *more* consistent with targeted activity, not less).
* **Local feeds** — `max(0.8, feed_confidence)` on a hit; a curated C2 list is high-confidence evidence.
* **GeoIP** — 0.35–0.4 only for elevated-risk ASNs or geographies, otherwise 0.
* **NVD (CVE indicators)** — `cvss / 10`, raised to ≥ 0.9 when CISA KEV marks it exploited in the wild.

## Verdict bands

| Score | Verdict | Ticket priority |
| --- | --- | --- |
| 85–100 | `critical` | P1 — contain within 1 hour |
| 70–84 | `high` | P2 — contain within 4 hours |
| 40–69 | `medium` | P3 — investigate within 1 business day |
| 15–39 | `low` | P4 — monitor |
| 0–14 | `informational` | P5 — record only |

Thresholds are configurable (`SCORE_HIGH_THRESHOLD`, …).

## Confidence is a separate number

```
coverage    = answered_providers / applicable_providers
agreement   = min(1, corroborating_signals / 2)        when score ≥ medium
            = min(1, answered_providers / 3)           otherwise
confidence  = 0.2 + 0.5 × coverage + 0.3 × agreement
```

It cuts both ways deliberately: a 0/100 backed by one source is not a clean bill of health any more
than an 85/100 backed by one source is a conviction. The dashboard and the report both show
`answered/queried` alongside the score.

## Worked example

Input: `203.0.113.10` (from the bundled demo dataset)

| Provider | Signal | Weight | Weighted | Authority | Floor |
| --- | --- | --- | --- | --- | --- |
| ThreatFox | 1.00 | 1.2 | 1.20 | 0.95 | **0.95** |
| AbuseIPDB | 0.96 | 1.0 | 0.96 | 0.80 | 0.77 |
| Local feeds | 0.95 | 1.0 | 0.95 | 0.90 | 0.86 |
| OTX | 0.87 | 0.9 | 0.78 | 0.70 | 0.61 |
| GreyNoise | 0.85 | 0.6 | 0.51 | 0.50 | 0.43 |
| GeoIP | 0.40 | 0.25 | 0.10 | 0.30 | 0.12 |
| URLhaus | 0.00 | 1.1 | 0.00 | 0.95 | 0.00 |

```
weighted_mean   = 4.50 / 6.05 = 0.744
authority_floor = 0.95
score           = 100 × max(0.744, 0.95) = 95  → CRITICAL, P1
confidence      = 0.2 + 0.5×1.0 + 0.3×1.0 = 1.0
```

Now the same IP with GreyNoise returning `benign` instead: the floor still puts it at 95, the benign
multiplier takes it to 43 — *medium*, investigate, do not page anyone at 03:00. That single modifier is
the difference between a night shift spent on Censys scanning noise and one spent on the actual C2.

## MITRE ATT&CK mapping

Technique IDs come from OTX pulses where the vendor supplies them, and otherwise from a small local map
of tags and malware families to techniques (`brute`/`ssh` → T1110, `c2`/`botnet` → T1071, `loader`/
`stealer` → T1105, `phish` → T1566, `port scan` → T1595, …). The map is deliberately small: it only
covers techniques this data can actually evidence, rather than decorating a ticket with plausible-looking
IDs nobody verified.
