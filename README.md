# IntelPulse — Automated Threat Intelligence & Triage Workbench

**Live demo:** https://vinitrami-soc.github.io/intelpulse/ · **API docs:** `/docs` once the backend is running

A SOC analyst opens six tabs for one alert: AbuseIPDB for the reputation, OTX for the campaign,
GreyNoise to check whether it is just Shodan again, ThreatFox and URLhaus for the payload, GeoIP/WHOIS
for the hosting. Six tabs × forty alerts a shift is where triage time goes — and where indicators get
missed.

IntelPulse does that pass in **one request**: it parses indicators out of whatever you paste (IOC list,
raw syslog, JSON alert export), queries every applicable source **concurrently**, scores them into a
single auditable verdict, maps the relationships between them, and writes the ticket — executive
summary, evidence, MITRE ATT&CK mapping and containment actions included.

![Indicator triage view](docs/screenshots/triage.png)

<p align="center">
  <img src="docs/screenshots/command-palette.png" width="49%" alt="Command palette">
  <img src="docs/screenshots/light-mode.png" width="49%" alt="Light theme">
</p>

---

## What it actually does

| Capability | Detail |
| --- | --- |
| **Multi-format ingestion** | Plain IOC lists, firewall/proxy syslog, Windows EVTX-as-JSON, SIEM alert exports, `.log/.txt/.csv/.json` upload up to 5 MB. Defanged notation (`1.2.3[.]4`, `hxxp://`) is refanged; RFC1918/loopback/CGNAT space and filenames like `svchost.exe` are dropped before anything leaves the building. |
| **Parallel enrichment** | One `httpx.AsyncClient`, one task per (indicator × provider), a global semaphore, per-provider timeouts and `return_exceptions=True`: a dead vendor degrades the result instead of failing the request. |
| **Composite scoring** | A weighted mean of the sources that actually answered, floored by the most authoritative single hit, then modified by GreyNoise noise-filtering and analyst allow/block lists. Confidence is reported separately from score. [Full model →](docs/SCORING.md) |
| **Quota-aware caching** | Every provider response — including failures, at a shorter TTL — is cached by `(provider, ioc)` in Redis (24 h default). The same IP triaged three times in a shift costs one quota unit, not three. |
| **Offline datasets** | Feodo Tracker, FireHOL level 1, ThreatFox daily dump, CISA KEV and an NVD CVE slice are imported into Postgres/SQLite; MaxMind GeoLite2 resolves geo/ASN locally. The platform keeps working when the free API quotas run out or the box has no internet. |
| **Investigation graph** | Indicators, malware families, ASNs, countries, campaigns and payload hashes as a Cytoscape.js graph, so "is this one thing or five things?" is answerable at a glance. |
| **SOC ticket output** | One click produces Markdown or JSON: severity + priority SLA, executive summary, per-indicator evidence with the rationale each source gave, ATT&CK techniques, and a containment checklist written as defender actions. |
| **Case history & audit** | Every triage is persisted with its full provider payload, so a report can be regenerated later and an auditor can see who ran what and when. |
| **Hardened by default** | Outbound host allowlist with resolution checks, per-endpoint rate limits, bounded payloads, security headers, JSON logs with credential masking, and a UI that treats every log line as hostile. [Full posture →](docs/SECURITY.md) |

---

## Architecture

```
                 ┌──────────────────────────────────────────────┐
  paste / upload │  Dashboard (static HTML/CSS/JS + Cytoscape)  │
  ──────────────▶│  demo mode: scores a bundled dataset in-page │
                 └───────────────┬──────────────────────────────┘
                                 │ REST (JSON)
                 ┌───────────────▼──────────────────────────────┐
                 │  FastAPI  ── /api/extract  /api/triage        │
                 │           ── /api/triage/report  /api/cases   │
                 │  ┌────────────────────────────────────────┐  │
                 │  │ ioc.py      regex + refang + RFC filter │  │
                 │  │ enrichment/ one class per source        │  │
                 │  │ scoring.py  weights, authority, modifiers│ │
                 │  │ graph.py    relationship builder        │  │
                 │  │ reporting.py Markdown / JSON ticket     │  │
                 │  └────────────────────────────────────────┘  │
                 └───┬──────────────┬─────────────┬─────────────┘
                     │              │             │
              ┌──────▼─────┐ ┌──────▼──────┐ ┌────▼─────────────┐
              │ Redis      │ │ PostgreSQL  │ │ Celery + beat    │
              │ quota cache│ │ cases,lists │ │ feed refreshes   │
              └────────────┘ │ feeds, CVEs │ └──────────────────┘
                             └─────────────┘
   live APIs: AbuseIPDB · AlienVault OTX · GreyNoise · ThreatFox · URLhaus
   offline:   MaxMind GeoLite2 · Feodo Tracker · FireHOL · CISA KEV · NVD
```

**Stack:** Python 3.12 · FastAPI · httpx (async) · SQLAlchemy 2.0 (async) · PostgreSQL/SQLite ·
Redis · Celery + beat · vanilla JS dashboard · Cytoscape.js · Docker Compose.

**Dashboard:** keyboard-first and dense, in the shape analysts already know — a command palette on
<kbd>⌘K</kbd>, `g i` / `g g` / `g t` / `g h` to move between views, deep-linkable tabs, a collapsible
rail, and dark/light themes that were each designed against their own surface. The data-viz colours
are computed, not chosen: the evidence ramp passes the full ordinal gate on both surfaces, and
severity is encoded three times over (hue + glyph + text) because SOC semantics force red, orange and
amber to sit next to each other. No framework, no build step — three static files serve identically
from GitHub Pages, nginx or `python -m http.server`. [Design system →](docs/DESIGN.md)

---

## Quickstart

### Docker (everything, one command)

```bash
cp .env.example .env        # optional: paste any free API keys you have
docker compose up --build
# API       → http://localhost:8000/docs
# Dashboard → http://localhost:8080   (switch to "Live API" → http://localhost:8000)
```

No API keys? It still runs. Unconfigured providers report themselves as `skipped` in
`/api/health` and in every result — the platform never presents a missing source as a clean verdict.

### Local, without Docker

```bash
make install                 # venv + dependencies
make test                    # 25 tests, no network required
make dev                     # http://localhost:8000/docs

make seed                    # optional: bundled sample feed rows for an offline demo
make feeds                   # optional: import the real offline datasets (needs internet)
python -m http.server 8080 --directory web   # the dashboard
```

### Terminal triage

```bash
cd backend
python -m app.cli triage 185.220.101.34 --report     # prints a Markdown SOC ticket
python -m app.cli feeds --all                        # refresh every offline dataset
```

---

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/extract` | Parse-only: see what would be triaged without spending a single API call |
| `POST` | `/api/triage` | Enrich every indicator in parallel, score, correlate, persist |
| `POST` | `/api/triage/upload` | Same, from a `.log/.txt/.csv/.json` file |
| `POST` | `/api/triage/report?fmt=markdown\|json` | Triage and return a ready-to-paste SOC ticket |
| `GET` | `/api/cases`, `/api/cases/{id}`, `/api/cases/{id}/report` | Case history and report regeneration |
| `GET`/`POST`/`DELETE` | `/api/lists` | Analyst allowlist / blocklist |
| `GET` | `/api/intel/feeds`, `POST /api/intel/feeds/{feed}/refresh` | Offline dataset status and refresh |
| `GET` | `/api/health`, `/api/scoring/model` | Which sources are live, and the exact weights behind a verdict |

Full reference with request/response examples: [docs/API.md](docs/API.md).

```bash
curl -s -X POST localhost:8000/api/triage \
  -H 'Content-Type: application/json' \
  -d '{"text":"SRC=185.220.101.34 blocked; hxxp://bad-domain[.]top/x.exe"}' | jq '.verdict, .score'
```

---

## The scoring model in one paragraph

Each source is normalised to a 0–1 signal. The engine then takes the **higher** of a weighted mean
(over the providers that actually answered, so a dead API cannot deflate a verdict) and an **authority
floor** (`max(signal × authority)`, so one confirmed abuse.ch C2 listing still reads *critical* when
five quieter sources shrug). Modifiers encode analyst judgement: GreyNoise `benign` — Shodan, Censys,
academic scanners — damps the score ×0.45; an allowlist entry forces 0; a blocklist entry forces ≥ 90.
**Confidence** is computed and displayed separately, because "85/100 from one source" and "85/100 from
five" are different instructions to an analyst. Weights are configuration, not code, and
`GET /api/scoring/model` returns them so any verdict can be audited.

Worked examples and the full rationale: [docs/SCORING.md](docs/SCORING.md).
Security controls and their tests: [docs/SECURITY.md](docs/SECURITY.md).
Design system, colour validation and interaction model: [docs/DESIGN.md](docs/DESIGN.md).

---

## Investigation graph and ticket output

![Relationship graph](docs/screenshots/graph.png)

![Generated SOC ticket](docs/screenshots/report.png)

The Markdown ticket is written to be pasted straight into Jira or ServiceNow: severity with a priority
SLA, an executive summary, the evidence each source gave in its own words, ATT&CK techniques, and a
containment checklist (`- [ ] Block the address at the perimeter firewall…`) scoped to the indicator
type and verdict. Indicators are defanged in the report so a ticket comment can never be click-through.

---

## Using it

| Key | Action |
| --- | --- |
| `⌘K` / `Ctrl-K` | Command palette — every action, fuzzy-searched |
| `⌘↵` | Run triage |
| `/` | Focus the ingest box |
| `g i` · `g g` · `g t` · `g h` | Indicators · Graph · SOC ticket · History |
| `t` | Cycle theme (dark → light → system) |
| `[` | Collapse the rail |
| `?` | Shortcut sheet |

Every indicator opens to show **why** it scored what it did: a contribution bar per source (with a
table view), the rationale each vendor gave in its own words, the modifiers that were applied, and a
**Scoring math** button that prints the actual arithmetic — weighted mean, authority floor, final
verdict. Nothing about a score is hidden behind the number.

There are a few easter eggs. They are listed in [docs/DESIGN.md](docs/DESIGN.md), which rather
defeats the point, so: the Konami code does something, and so does starting a paste with `sudo`.

## Demo mode vs live mode

The GitHub Pages deployment runs **demo mode**: `web/assets/engine.js` is a faithful port of the
backend's extraction, scoring and reporting modules, so the browser scores a bundled dataset with the
same weights, authority floor and verdict bands as the API. That dataset is **synthetic** — RFC 5737
documentation addresses and RFC 2606 reserved domains — and the UI says so on every screen and in
every generated report. Nothing in demo mode describes a real host, and no vendor API is called.

Switch the toggle to **Live API**, point it at a running backend, and the same screens are driven by
real AbuseIPDB / OTX / GreyNoise / abuse.ch responses.

---

## Testing

```bash
make test        # 63 backend tests: extraction, scoring, API contract, reports, security controls
make test-web    # 13 browser-engine tests: parity with the backend's rules
make test-ui     # 48 Chromium checks: XSS, hostile URLs, degradation, palette, theming, a11y
make lint        # ruff
make audit       # pip-audit against the pinned requirements
```

Provider classes are stubbed in the API tests, so assertions describe pipeline behaviour rather than
whatever AbuseIPDB happens to say today. The backend suite needs no network, no API keys and no Redis.
The browser-engine suite pins the JavaScript implementation to the same extraction rules, weights,
authority floor and verdict bands as the Python one, so demo mode cannot quietly drift away from the
real pipeline. The UI suite drives a real Chromium: it pastes `<script>`, `<img onerror>` and
`javascript:` payloads into the ingest field and asserts nothing executes, feeds the renderer a
hostile provider response and asserts the link is dropped, and kills the backend mid-request to check
the page degrades instead of freezing. It also drives the command palette, the key sequences, the
theme cycle and the charts, and asserts zero horizontal overflow at 390 / 768 / 1024 / 1440px.

---

## Security and honesty notes

Full detail, with the test that proves each control, is in [docs/SECURITY.md](docs/SECURITY.md).
The short version:

* **Egress is allowlisted.** Twelve known intelligence hosts, HTTPS only, resolution checked against
  private/loopback/link-local/metadata space on every hop including redirects. IntelPulse never
  fetches an analyst-supplied URL, and the allowlist means it never could.
* **Internal addresses never leave.** Private, loopback, link-local, CGNAT and documentation space is
  filtered during extraction, before any provider is called.
* **Quota and CPU are budgeted.** Per-client rate limits sized per endpoint (triage 30/min, writes
  60/min, reads 240/min), 1 MiB JSON bodies, 5 MiB uploads, 200 000 characters of text, 100 indicators
  per request. `X-Forwarded-For` is ignored unless explicitly trusted.
* **Logs are JSON and masked.** Request id, client, route, status, duration — with configured secrets
  and anything credential-shaped redacted from messages, arguments and tracebacks.
* **The UI treats every log line as hostile.** Output encoding everywhere, `http(s)`-only URL
  validation on links that come from providers, and a CSP that blocks inline script and `eval`.
* **Dependencies are audited.** `make audit`; the pins moved forward when `pip-audit` found advisories
  in the originals.
* **Nothing is overstated.** There is no authentication yet — the design target is a deployment behind
  the SOC's own boundary, and the roadmap says so. Unconfigured or failing sources are reported as
  `skipped`/`error`, never as "clean", and every report states its source coverage.
* Secrets live in `.env` only; the API container runs as an unprivileged user with a healthcheck.
* Containment guidance is defensive only: block, hunt, isolate, revoke, patch.

---

## Roadmap

- [ ] VirusTotal and Shodan providers (keys already read from config)
- [ ] STIX 2.1 / MISP export alongside Markdown and JSON
- [ ] Webhook ingestion so a SIEM can push alerts directly
- [ ] Per-analyst auth and API keys for multi-user deployments (the one real gap today)
- [ ] Redis-backed rate limiting for multi-replica deployments (the interface is already one method)

---

Built by [Vinit Rami](https://vinitrami-soc.github.io/) — offensive-security background, defensive
engineering focus.
