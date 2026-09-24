# Changelog

All notable changes to IntelPulse are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/): the REST API under `/api` and the
JSON report are the public interface.

## [Unreleased]

## [1.0.0] - 2026-09-24

The first release as a standalone repository. IntelPulse was built inside the
author's portfolio repository, and its full history moved here with it.

### Added

- **Ingestion** of plain IOC lists, firewall and proxy syslog, Windows
  EVTX-as-JSON and SIEM alert exports, or an uploaded `.log`, `.txt`, `.csv` or
  `.json` file up to 5 MB. Defanged indicators are refanged, and private,
  loopback and CGNAT space is dropped before anything is looked up.
- **Concurrent enrichment** against AbuseIPDB, AlienVault OTX, GreyNoise,
  ThreatFox and URLhaus, with per-provider timeouts. A failing vendor degrades
  the result instead of failing the request, and an unconfigured one reports
  itself as `skipped`, never as clean.
- **Composite scoring** into one auditable verdict: a weighted mean of the
  sources that answered, floored by the most authoritative hit, adjusted by
  GreyNoise and the analyst's allow and block lists, with confidence reported
  separately. See [docs/SCORING.md](docs/SCORING.md).
- **Quota-aware caching** of every provider response in Redis, so an indicator
  triaged three times in a shift costs one quota unit.
- **Offline datasets:** Feodo Tracker, FireHOL level 1, the ThreatFox daily
  dump, CISA KEV, an NVD CVE slice and MaxMind GeoLite2, refreshed by Celery
  beat, so triage keeps working when API quotas run out.
- **Investigation graph** of indicators, malware families, ASNs, countries and
  campaigns, and a **campaign graph** with a first-seen timeline.
- **SOC tickets** in Markdown or JSON: severity and priority SLA, executive
  summary, per-source evidence, MITRE ATT&CK techniques and containment steps,
  with optional delivery to Jira and ServiceNow.
- **Case history, audit log and triage diffs** that show what changed for an
  indicator since it was last triaged.
- **Browser demo** on GitHub Pages that scores a bundled synthetic dataset
  in the page, with no backend and no API keys.
- **Security hardening:** write protection against cross-origin requests,
  optional bearer token, an outbound host allowlist with resolution checks,
  per-endpoint rate limits, bounded payloads, masked JSON logs and a strict
  CSP. The September 2026 OWASP audit's thirteen findings are fixed and pinned
  by tests ([docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md)).
- **Tests in CI on every change:** 200 backend tests with ruff, 56 node tests
  for engine parity and design guards, and four Playwright suites covering the
  workbench, the site and console, phones and tablets, and hostile input.
  `pip-audit` runs weekly.

[Unreleased]: https://github.com/vinitrami-Soc/intelpulse/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/vinitrami-Soc/intelpulse/releases/tag/v1.0.0
