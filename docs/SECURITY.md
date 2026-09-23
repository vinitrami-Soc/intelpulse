# Security posture

A triage workbench is an unusual target: the data it holds is threat
intelligence, which is public by design. The things worth protecting are the
SOC's API quota, the box it runs on, the analyst's browser, and the internal
network the backend can see. Every control below exists for one of those four.

Each control names the test that proves it works — `backend/tests/test_security.py`
and `backend/tests/test_security_audit.py` for the service; `web/tests/ui.spec.mjs`,
`web/tests/suite.spec.mjs`, `web/tests/mobile.spec.mjs` and
`web/tests/security.spec.mjs` for the browser. The OWASP-mapped audit that
produced the second file of each pair, with its evidence, is in
[`SECURITY-AUDIT.md`](SECURITY-AUDIT.md).

---

## Threat model

| Adversary | What they can reach | What they want |
| --- | --- | --- |
| Anyone who can send a request to the API | every endpoint when no token is set | burn API quota, exhaust CPU/memory, use the backend as a scanner |
| Any web page the analyst has open | the API on `localhost`, through the analyst's browser | allowlist an attacker's address, delete cases, plant a case |
| Whoever wrote the log an analyst pastes | the ingest field, therefore the DOM and the ticket | script execution in the analyst's browser, a forged section in a ticket, a regex that never finishes |
| A compromised or hijacked intelligence vendor | provider responses rendered in the UI and written into tickets | inject markup or a hostile URL into the analyst's session |
| Someone who can write to the browser's storage | `localStorage` for this origin | crash the console, plant markup in case history, pollute prototypes |
| Someone who can read logs or an image layer | stdout, the built container | API keys, database credentials |

Authentication is one shared bearer token, off by default for the local demo
and on the moment `API_TOKEN` is set. It proves a caller holds the token; it
does not tell analysts apart, so there are no roles and no per-user audit trail.
The design target is a single-analyst or single-team deployment behind the
SOC's own network boundary. Multi-tenant use needs real identity (OIDC) and
roles first.

---

## Backend controls

### Who may write — `app/security.py`

* **Cross-origin write guard.** CORS decides whether a page may *read* a
  response; it never stops a simple `POST` from being sent. Before this guard,
  any page the analyst had open could allowlist an attacker's address through
  their local API with a plain form post (the audit proved it). A `POST` or
  `DELETE` whose `Origin` is not in `CORS_ORIGINS` (or not the API's own), whose
  `Origin` is `null`, or which Fetch Metadata marks `cross-site`, is refused
  with `403`. Scripts and `curl` send neither header and are unaffected; the
  token governs them. `CORS_ORIGINS=*` turns the guard off, and the app logs a
  warning at startup when it sees that.
* **Bearer token.** With `API_TOKEN` set, every `/api/` route except
  `/api/health` and `/api/scoring/model` needs `Authorization: Bearer <token>`,
  compared with `hmac.compare_digest`. A missing or wrong token is `401` with
  `WWW-Authenticate`. The rate limiter sits in front, so guessing is throttled.
  Production without a token logs a warning at startup.
* **Audit actors are verified, not claimed.** The audit log used to record
  whatever name the request body typed into `analyst` or `created_by`. The
  actor is now what the server verified (`api-token` or `anonymous`); the typed
  name is kept as a label in the entry's detail as `claimed_by`.

*Tests:* a foreign page's list write and multipart upload, a look-alike
origin, `null` and a `cross-site` write without an `Origin` are all refused;
the dashboard and a script without an `Origin` can still write; token missing,
wrong, wrong scheme and correct; health and preflight stay open; a `401` is
readable by the dashboard; a typed `created_by` does not become the actor.

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

* `MAX_REQUEST_BYTES` (1 MiB) on JSON bodies and `MAX_UPLOAD_BYTES` (5 MiB) on
  uploads → `413`. The declared `Content-Length` is checked before anything is
  read, and the body is also counted as it streams in: a chunked request
  declares no length, and before the audit a 20 MB chunked body sailed past the
  1 MiB limit into memory.
* `MAX_INPUT_CHARS` (200 000) on the pasted text, enforced in the schema → `422`.
* `MAX_IOCS_PER_REQUEST` (100) caps the fan-out, so a 10 000-address paste is
  truncated rather than turned into 70 000 vendor lookups.
* **Linear-time extraction.** The domain and email patterns used to backtrack:
  `a.a.a.…` made extraction quadratic, and a paste at the 200 000-character
  limit held a worker for about ten minutes. Their repetition is bounded now,
  in the backend and in the browser engine alike, and the same input takes
  under half a second.
* **Uploads must be text.** A file with a NUL byte in its first 8 KiB is `415`;
  an executable used to come back as a triaged case.
* **Every string field has a length.** Titles, analyst names, reasons and list
  values are bounded in the schema; path and query integers are bounded to
  SQLite's range, so an out-of-range ID is a `422`, not a `500`.

*Tests:* oversized body, chunked body over and under the limit, oversized text,
malformed JSON, binary/RTL-override garbage, a 10 000-indicator paste, four
backtracking shapes at the full input limit, and a binary upload.

### Input that is stored or written into tickets — `app/text.py`

* **List entries must be indicators.** A value is refanged and classified; if
  it is not a single routable IP, domain, URL, hash, email or CVE it is `422`.
  The server derives the type instead of trusting the client's `ioc_type`.
* **Labels are one visible line.** Titles, filenames, reasons and analyst
  names lose control characters, zero-width characters and bidi overrides
  ("Trojan Source"), and are truncated.
* **Tickets are escaped.** Everything that reaches the Markdown report from a
  paste, an upload name or a vendor — title, analyst, family names, technique
  names, tags, rationales — is flattened to one line, has its URL schemes
  defanged to `hxxp(s)://`, and has `[ ] < > | \` and backticks escaped.
  Before, a title could open a fake "Recommended containment" section, and a
  vendor's family name could embed a tracking image in a Jira ticket.
  Indicators themselves go in code spans, defanged.

*Tests:* hostile list values (`CRLF`, markup, private address, prose), the
server-side type, a forged ticket section, a filename with a bidi override and
a newline, and the escaping of links, images, HTML and table cells.

### Errors

* A validation error says where and what, never repeats the value: FastAPI's
  default echoed a 250 KB body back as a 250 KB error.
* An unhandled exception is logged with its traceback and answered as JSON
  `500` with the request ID, never as a stack trace or plain text.
* The `X-Request-ID` a client sends is cut down to ASCII letters, digits, `-`
  and `_`, 64 at most, before it reaches a log line or a response header; if
  nothing is left, a fresh one is issued.
* GeoIP lookups no longer swallow every exception silently: a missing address
  is expected, anything else is logged.

### Response headers — `app/security.py`

`Content-Security-Policy` (`default-src 'none'` for API routes, a narrower
Swagger-compatible policy for `/docs`), `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`,
`Permissions-Policy`, HSTS when `ENVIRONMENT=production`, and an
`X-Request-ID` on every response.

CORS is explicit about methods and headers, and the default origin list is
the local dashboards and the published site, not `*`. With `*` any page in any
browser may call the API and the write guard is off, so the app logs a warning
whenever it sees it.

### Logging — `app/logging_config.py`

JSON lines with request id, client address, method, path, status and duration,
so the output ships into the SIEM this tool feeds. A masking filter redacts
configured secret values (including `API_TOKEN` and the Jira and ServiceNow
credentials) and anything shaped like a credential — `key=`,
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

* **Output encoding.** Everything the workbench renders from a log line, a
  provider response or a stored case goes through `esc()`
  (`web/assets/console-panes.js`); the generated report is set with
  `textContent`. The browser test pastes `<script>`, `<img onerror>`,
  `"><svg onload>` and a `javascript:` URL into the ingest field and asserts
  nothing executes and no element is injected.
* **Toasts are text.** The console's toast took markup until the workbench
  moved into the console, where it announces indicator values — which come out
  of pasted logs. It sets `textContent` now, and a test hands it an `<img>`.
* **URL scheme validation.** Escaping makes a URL safe to sit in an attribute;
  it does not make it safe to follow. `safeUrl()` rejects everything that is not
  `http:`/`https:`, so a hostile provider `reference` or ATT&CK link renders as
  text instead of a link. Tested with a hostile result payload and a scheme
  matrix.
* **CSP.** A `<meta>` policy blocks inline script, `eval`, objects and form
  submission, and limits script to this origin — no CDN, now that neither graph
  loads a library. The two redirect stubs (`workbench.html`, `explorer.html`)
  run no script at all: `default-src 'none'`.
  `frame-ancestors` cannot be set from a meta tag, so the nginx service sends
  it as a real header (`web/nginx.conf`) — GitHub Pages cannot send headers,
  which is why the app never depends on them for correctness.
* **Nothing from outside is trusted as a shape.** Every result the API returns
  goes through `normalizeResult()` before anything renders it: numbers become finite numbers, lists become arrays,
  a verdict is recomputed from the score. Before, a string where a count was
  expected went into `innerHTML` unescaped (`cache_hits`, `providers_queried`,
  the contribution chart's weights), and a wrong type crashed the pane in 89
  places.
  The browser test mutates a real result one field at a time — markup, `null`,
  a number, a boolean, an object, an array — and asserts no script, no injected
  element and no uncaught error.
* **Stored state is validated.** The mode must be `live` or `demo`, the backend
  URL must pass `safeUrl()`, lists and history must be arrays of objects, and
  snapshots are read into a map with no prototype; a `javascript:` backend
  address is never used. Poisoned `localStorage` used
  to crash the workbench; now it falls back to defaults, and a `__proto__` key
  pollutes nothing.
* **The token lives in `sessionStorage`.** When the backend asks for one, the
  connect form takes it as a password field; it is sent as
  `Authorization: Bearer` with `credentials: "omit"`, never written to
  `localStorage`, and gone when the tab closes.
* **Degradation.** A slow or dead backend produces a skeleton, then a message,
  never a frozen page. Tested by aborting every `/api/**` request after 2.5 s.

---

## Verifying it yourself

```bash
cd backend && pytest -q                 # 200 tests incl. the security suite and the audit's regressions
cd backend && pip-audit -r requirements.txt
python3 -m http.server 8123 --directory web &
node web/tests/ui.spec.mjs              # workbench + campaign graph checks (needs Playwright)
node web/tests/suite.spec.mjs           # site + console browser checks
node web/tests/mobile.spec.mjs          # phones, tablets, and the assistant panel
node web/tests/security.spec.mjs        # hostile API, poisoned storage, CSP, tabnabbing
```

## Reporting

This is a portfolio project, not a hosted service. If you find something wrong
with it, open an issue on the repository.
