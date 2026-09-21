# Security posture

A triage workbench is an unusual target: the data it holds is threat
intelligence, which is public by design. The things worth protecting are the
SOC's API quota, the box it runs on, the analyst's browser, and the internal
network the backend can see. Every control below exists for one of those four.

Each control names the test that proves it works — `backend/tests/test_security.py`
for the service, `web/tests/ui.spec.mjs` and `web/tests/suite.spec.mjs` for the browser.

---

## Threat model

| Adversary | What they can reach | What they want |
| --- | --- | --- |
| Anyone who can send a request to the API | every unauthenticated endpoint | burn API quota, exhaust CPU/memory, use the backend as a scanner |
| Whoever wrote the log an analyst pastes | the ingest field, therefore the DOM | script execution in the analyst's browser, a click-through link |
| A compromised or hijacked intelligence vendor | provider responses rendered in the UI | inject markup or a hostile URL into the analyst's session |
| Someone who can read logs or an image layer | stdout, the built container | API keys, database credentials |

Out of scope today, and honestly so: there is **no authentication**. The design
target is a single-analyst or single-team deployment behind the SOC's own
network boundary. Multi-tenant use needs the auth layer on the roadmap first.

---

## Backend controls

### Outbound egress policy — `app/net.py`

IntelPulse never fetches a URL an analyst supplies; indicators go to fixed
vendor endpoints as path or body parameters, so there is no classic SSRF sink.
The controls exist anyway, because "no sink today" is not a control:

* **Host allowlist.** Every outbound request must target one of twelve known
  intelligence hosts. A new provider, a typo in a URL template or a manipulated
  path can only ever reach a known service.
* **HTTPS only.** Plain HTTP is refused before a socket is opened.
* **Resolution check.** The resolved addresses are tested against private,
  loopback, link-local (including `169.254.169.254`), CGNAT, benchmarking and
  documentation space. An allowlisted host whose DNS answer points inward —
  rebinding, a poisoned resolver, a hijacked domain — is refused.
* **Redirects are re-validated.** httpx re-enters the transport for every hop,
  so a vendor redirecting to an internal host is blocked at the hop that tries
  it.
* **Path encoding.** Indicators interpolated into vendor URLs are
  percent-encoded with no safe characters, so a value containing `/`, `?`, `#`
  or `@` cannot reshape the request.

*Known limit:* there is a window between resolution and connection that only
IP-pinned connections close. The host allowlist is the control that holds; the
DNS check is defence in depth.

*Tests:* reserved-range detection, non-allowlisted host, plain HTTP, metadata
IP, an allowlisted host resolving to `127.0.0.1`, and a test that fails if any
feed URL in the codebase is missing from the allowlist.

### Indicator filtering — `app/ioc.py`

Private, loopback, link-local, CGNAT and documentation addresses are dropped
during extraction, so internal addresses pasted from a firewall log are never
sent to a third party. This is a data-leakage control, not an SSRF one, and it
runs before any provider is called.

### Rate limiting — `app/security.py`

Per-client sliding windows, sized by what an endpoint actually costs:

| Bucket | Default | Covers |
| --- | --- | --- |
| `triage` | 30/min | `/api/triage*`, feed refreshes — these spend vendor quota |
| `write` | 60/min | other `POST`/`DELETE` |
| `read` | 240/min | `GET` — the dashboard polls health |

Exceeding a bucket returns `429` with `Retry-After` and `X-RateLimit-*`.
`X-Forwarded-For` is **ignored unless `TRUST_FORWARDED_FOR=true`**: trusting it
without a proxy in front hands every attacker an unlimited supply of
identities.

### Payload bounds

* `MAX_REQUEST_BYTES` (1 MiB) on JSON bodies, checked from `Content-Length`
  before FastAPI buffers anything → `413`.
* `MAX_UPLOAD_BYTES` (5 MiB) on file uploads.
* `MAX_INPUT_CHARS` (200 000) on the pasted text, enforced in the schema → `422`.
* `MAX_IOCS_PER_REQUEST` (100) caps the fan-out, so a 10 000-address paste is
  truncated rather than turned into 70 000 vendor lookups.

*Tests:* oversized body, oversized text, malformed JSON, binary/RTL-override
garbage, and a 10 000-indicator paste.

### Response headers — `app/security.py`

`Content-Security-Policy` (`default-src 'none'` for API routes, a narrower
Swagger-compatible policy for `/docs`), `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`,
`Permissions-Policy`, HSTS when `ENVIRONMENT=production`, and an
`X-Request-ID` on every response.

CORS is explicit about methods and headers. `CORS_ORIGINS=*` is fine for a
local demo; the app logs a warning if it sees `*` in a production environment.

### Logging — `app/logging_config.py`

JSON lines with request id, client address, method, path, status and duration,
so the output ships into the SIEM this tool feeds. A masking filter redacts
configured secret values and anything shaped like a credential — `key=`,
`api_key:`, `Authorization: Bearer`, a password inside a Postgres URL — in the
message, the arguments and the exception text.

The filter masks string arguments only. Coercing every argument would corrupt
`%d`-style format strings, which is a bug this project shipped for exactly one
commit and now has a test for.

### Dependencies

`make audit` runs `pip-audit` against the pinned requirements. The pins were
moved forward when that audit found advisories in the original
`starlette`/`python-multipart` versions; the current set reports clean.

### Container

The API image runs as an unprivileged user (uid 10001), with a healthcheck and
no build toolchain in the final layer. Secrets come from `.env` at runtime,
never from the image.

---

## Frontend controls

* **Output encoding.** Everything rendered from a log line, a provider response
  or a stored case goes through `escapeHtml`. The browser test pastes
  `<script>`, `<img onerror>`, `"><svg onload>` and a `javascript:` URL into the
  ingest field and asserts nothing executes and no element is injected.
* **URL scheme validation.** Escaping makes a URL safe to sit in an attribute;
  it does not make it safe to follow. `safeUrl()` rejects everything that is not
  `http:`/`https:`, so a hostile provider `reference` or ATT&CK link renders as
  text instead of a link. Tested with a hostile result payload and a scheme
  matrix.
* **CSP.** A `<meta>` policy blocks inline script, `eval`, objects and form
  submission, and limits script to this origin plus the graph CDN.
  `frame-ancestors` cannot be set from a meta tag, so the nginx service sends
  it as a real header (`web/nginx.conf`) — GitHub Pages cannot send headers,
  which is why the app never depends on them for correctness.
* **No secrets in browser storage.** `localStorage` holds the mode, the backend
  URL, the rail state, local list entries and case history. There is no token
  to leak, because there is no auth yet.
* **Degradation.** A slow or dead backend produces a skeleton, then a message,
  never a frozen page. Tested by aborting every `/api/**` request after 2.5 s.

---

## Verifying it yourself

```bash
cd backend && pytest -q                 # 63 tests incl. the security suite
cd backend && pip-audit -r requirements.txt
python3 -m http.server 8123 --directory web &
node web/tests/ui.spec.mjs              # workbench browser checks (needs Playwright)
node web/tests/suite.spec.mjs           # site + console browser checks
node web/tests/mobile.spec.mjs          # phones, tablets, and the assistant panel
```

## Reporting

This is a portfolio project, not a hosted service. If you find something wrong
with it, open an issue on the repository.
