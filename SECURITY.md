# Security policy

IntelPulse ingests hostile input by design: logs written by attackers, and
responses from third-party intelligence vendors. Bugs in how it handles that
input matter. Thank you for reporting them responsibly.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | Yes |

## Reporting a vulnerability

**Please do not open a public issue.** Report it privately through GitHub:
[Security → Report a vulnerability](https://github.com/vinitrami-Soc/intelpulse/security/advisories/new).

Include:

- what an attacker can do, and under what conditions;
- a minimal reproducer, built from synthetic data (RFC 5737 addresses,
  RFC 2606 domains). Never send live malware or a real organisation's logs;
- the commit or version you tested, and whether it was the demo build or the
  backend (Docker or local).

You should get an acknowledgement within 7 days. Once the issue is confirmed, a
fix will be prepared in a private advisory and released as quickly as the
severity warrants, and you will be credited unless you prefer not to be.

## In scope

- Script execution, markup injection or a hostile link in the dashboard or the
  generated ticket, from pasted input, an uploaded file, a provider response or
  browser storage.
- A cross-origin page that can write to the API (allow/block lists, cases)
  through an analyst's browser.
- Server-side request forgery: any way to make the backend contact a host
  outside its egress allowlist, or private, loopback, link-local or metadata
  address space.
- Denial of service: input that makes extraction take far longer than linear
  time, or that gets past the payload, upload and rate limits.
- API keys, tokens or database credentials leaking through responses, logs,
  tickets, the cache or the container image.

## Out of scope

- A wrong verdict or a missed indicator. That is a scoring or extraction issue;
  please open a [verdict report](https://github.com/vinitrami-Soc/intelpulse/issues/new/choose).
- Vulnerabilities in AbuseIPDB, AlienVault OTX, GreyNoise, ThreatFox, URLhaus or
  the offline feeds themselves.
- Deployments exposed to the internet without `API_TOKEN` set. Authentication
  is one shared token and the design target is a deployment behind the SOC's
  own network boundary; see [docs/SECURITY.md](docs/SECURITY.md).
- Issues that need an attacker who can already change the configuration,
  environment variables or the host.

## How it is defended

The threat model, every control and the test that proves it are in
[docs/SECURITY.md](docs/SECURITY.md). The September 2026 OWASP audit, with its
thirteen findings reproduced, fixed and pinned by tests, is in
[docs/SECURITY-AUDIT.md](docs/SECURITY-AUDIT.md).
