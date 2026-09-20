# API reference

Base URL: `http://localhost:8000`. Interactive docs: `/docs` (Swagger) and `/redoc`.
Everything is JSON unless stated; `POST /api/triage/report?fmt=markdown` returns `text/markdown`.

---

## `GET /api/health`

Which sources are live, what storage is in use, how big the offline datasets are. The dashboard calls
this on load so it can state honestly how many sources are configured.

```json
{
  "status": "ok",
  "database": "postgresql (ok)",
  "cache": { "backend": "redis", "hits": 128, "misses": 44, "hit_rate": 0.744, "ttl_seconds": 86400 },
  "providers": [
    { "name": "abuseipdb", "label": "AbuseIPDB", "supported_types": ["ip"], "requires_key": true, "configured": true },
    { "name": "greynoise", "label": "GreyNoise", "supported_types": ["ip"], "requires_key": true, "configured": false }
  ],
  "offline_datasets": { "feed_entries": 41233, "cve_records": 8812, "stored_cases": 96, "geoip_city": true, "geoip_asn": true }
}
```

## `GET /api/scoring/model`

Returns the live weights, authority values, thresholds and modifiers — the audit trail behind any
verdict. See [SCORING.md](SCORING.md).

---

## `POST /api/extract`

Parse-only. Costs no API quota; useful to show an analyst what is about to be triaged.

```bash
curl -s -X POST localhost:8000/api/extract -H 'Content-Type: application/json' \
  -d '{"text":"SRC=185.220.101.34 DST=10.0.0.5 hxxp://bad[.]site/x.exe"}'
```

```json
{
  "count": 3,
  "counts_by_type": { "ip": 1, "domain": 1, "url": 1 },
  "indicators": [
    { "value": "185.220.101.34", "type": "ip", "original": "185.220.101.34", "context": "SRC=185.220.101.34 DST=10.0.0.5 …" }
  ]
}
```

`10.0.0.5` is absent by design: private, loopback, link-local, CGNAT and documentation ranges are
dropped before anything is sent to a third party.

---

## `POST /api/triage`

The core endpoint. Accepts either a raw blob or an explicit indicator list.

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `text` | string | — | Raw paste: IOC list, syslog, JSON alert export |
| `indicators` | string[] | — | Explicit list; unparseable entries fall back to the extractor |
| `title` | string | `"Ad-hoc triage"` | Shown on the case and the ticket |
| `analyst` | string | `null` | Recorded in the audit log and the report header |
| `use_cache` | bool | `true` | `false` forces fresh vendor lookups (spends quota) |
| `persist` | bool | `true` | `false` runs the triage without storing a case |
| `limit` | int | `100` | Caps indicators per request |

```json
{
  "case_id": "8f2c…",
  "verdict": "critical",
  "score": 95,
  "duration_ms": 612,
  "cache_hits": 3,
  "summary": "3 indicator(s) were triaged across the configured intelligence sources…",
  "indicators": [
    {
      "value": "185.220.101.34", "type": "ip", "score": 95, "verdict": "critical", "confidence": 1.0,
      "malware_families": ["QakBot"],
      "attack_techniques": [{ "id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control", "url": "https://attack.mitre.org/techniques/T1071/" }],
      "evidence": [{ "provider": "threatfox", "signal": 0.95, "weight": 1.2, "weighted": 1.14, "rationale": "listed as active botnet_cc infrastructure for QakBot (abuse.ch confidence 100%)" }],
      "modifiers": [],
      "providers_queried": 7, "providers_answered": 5,
      "containment": ["Block the address at the perimeter firewall and on egress proxies.", "…"],
      "sources": [{ "provider": "greynoise", "status": "skipped", "error": "API key not configured" }]
    }
  ],
  "graph": { "nodes": [], "edges": [] }
}
```

Every source is listed with its status (`ok`, `clean`, `skipped`, `error`, `rate_limited`), its latency
and whether the answer came from cache. A source that could not answer is never presented as clean.

## `POST /api/triage/upload`

`multipart/form-data` with `file` (≤ 5 MB), optional `title` and `analyst`. Accepts `.log`, `.txt`,
`.csv`, `.json`, including EVTX converted to JSON.

```bash
curl -s -X POST localhost:8000/api/triage/upload -F 'file=@firewall.log' -F 'title=IR-2026-114'
```

## `POST /api/triage/report?fmt=markdown|json`

Same body as `/api/triage`; returns the finished SOC ticket instead of the raw result.

```bash
curl -s -X POST 'localhost:8000/api/triage/report?fmt=markdown' \
  -H 'Content-Type: application/json' \
  -d '{"indicators":["185.220.101.34"],"title":"IR-2026-114"}' > ticket.md
```

---

## Cases

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/cases?limit=25&offset=0&verdict=high` | Newest first |
| `GET` | `/api/cases/{id}` | Full stored result including every provider payload |
| `GET` | `/api/cases/{id}/report?fmt=markdown\|json` | Regenerates the ticket from stored evidence |
| `DELETE` | `/api/cases/{id}` | Removes the case and its indicators |
| `GET` | `/api/stats` | Counts by verdict and the most frequent malware families |
| `GET` | `/api/audit?limit=50` | Append-only trail of triages and list changes |

## Allow / block lists

```bash
curl -s -X POST localhost:8000/api/lists -H 'Content-Type: application/json' \
  -d '{"value":"203.0.113.9","ioc_type":"ip","list_type":"allow","reason":"our egress NAT"}'
```

An allowlist entry forces a score of 0 and the verdict `allowlisted`; a blocklist entry forces ≥ 90.
Both record the reason, which is printed in the report's modifier list — local knowledge beats vendor
opinion, but it has to be justified in writing.

## Offline datasets

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/intel/feeds` | Row counts and last refresh per feed |
| `POST` | `/api/intel/feeds/{feed}/refresh` | `feodo-tracker`, `threatfox-dump`, `firehol-level1`, `cisa-kev`, `nvd` |
| `GET` | `/api/intel/cve/{cve_id}` | CVSS, severity, KEV status from the local NVD slice |
| `GET` | `/api/intel/cache` · `POST /api/intel/cache/invalidate?ioc=…` | Cache stats and targeted invalidation |

In Docker the Celery beat worker refreshes these on a schedule (Feodo hourly, ThreatFox every 6 h,
FireHOL/KEV/NVD daily); the refresh endpoint exists so a single-container demo works without Celery.

---

## Errors

| Status | Meaning |
| --- | --- |
| `422` | No usable indicators in the input, or neither `text` nor `indicators` supplied |
| `413` | Upload exceeds the 5 MB limit |
| `404` | Unknown case, list entry, feed or CVE |
| `409` | List entry already exists |

Provider-level failures are **not** request failures: they appear as `status: "error"` on that source
with the reason, and the remaining sources still produce a scored verdict.
