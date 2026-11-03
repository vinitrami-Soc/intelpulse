# Security posture

A triage workbench is an unusual target: the data it holds is threat
intelligence, which is public by design. The things worth protecting are the
SOC's API quota, the box it runs on, the analyst's browser, and the internal
network the backend can see. Every control below exists for one of those four.

Each control names the test that proves it works: `backend/tests/test_security.py`
and `backend/tests/test_security_audit.py` for the service; `web/tests/ui.spec.mjs`,
`web/tests/suite.spec.mjs`, `web/tests/mobile.spec.mjs` and
`web/tests/security.spec.mjs` for the browser. The OWASP-mapped audit that
produced the second file of each pair, with its evidence, is in
[`SECURITY-AUDIT.md`](SECURITY-AUDIT.md).

---

## Threat model

| Adversary | What they can reach | What they want |
| --- | --- | --- |
| Anyone who can send a request to the API | sign-in, setup, and every endpoint with a guessed or stolen credential | burn API quota, exhaust CPU/memory, use the backend as a scanner, guess a password |
| A member of one workspace | the API, with their own session or token | read or change another workspace's cases, lists or tokens; act beyond their role |
| Any web page the analyst has open | the API on `localhost`, through the analyst's browser | allowlist an attacker's address, delete cases, plant a case |
| Whoever wrote the log an analyst pastes | the ingest field, therefore the DOM and the ticket | script execution in the analyst's browser, a forged section in a ticket, a regex that never finishes |
| A compromised or hijacked intelligence vendor | provider responses rendered in the UI and written into tickets | inject markup or a hostile URL into the analyst's session |
| Someone who can write to the browser's storage | `localStorage` for this origin | crash the console, plant markup in case history, pollute prototypes |
| Someone who can read logs or an image layer | stdout, the built container | API keys, database credentials |

Since v2 every caller is someone: a person signed in (argon2id passwords,
sessions stored only as SHA-256, CSRF tokens on writes), or a script with an API
token scoped to `read`, `triage` or `ingest`. Every person and token belongs to
one workspace, as admin or analyst, and sees only that workspace's data. The
1.x shared `API_TOKEN` still reaches the endpoints 1.x had, in the original
organization, and is deprecated. Single sign-on (OIDC) is not built yet.

---

## Backend controls

### Who may write (`app/security.py`)

* **Cross-origin write guard.** CORS decides whether a page may *read* a
  response; it never stops a simple `POST` from being sent. Before this guard,
  any page the analyst had open could allowlist an attacker's address through
  their local API with a plain form post (the audit proved it). A `POST` or
  `DELETE` whose `Origin` is not in `CORS_ORIGINS` (or not the API's own), whose
  `Origin` is `null`, or which Fetch Metadata marks `cross-site`, is refused
  with `403`. Scripts and `curl` send neither header and are unaffected; their
  API token governs them. `CORS_ORIGINS=*` turns the guard off, and the app logs a
  warning at startup when it sees that.
* **Who is asking (`app/platform/deps.py`).** Every `/api/` route except
  health, the scoring model, `/api/session` and the one-time `/api/setup` needs
  a session cookie or `Authorization: Bearer`. Routers get the check as a
  router-wide dependency, so a route that forgets to name its caller is a `401`,
  not a leak; a test calls every route without credentials. A wrong bearer token
  is refused even when a session cookie comes with it. Missing or wrong is `401`
  with `WWW-Authenticate`.
* **Sessions (`app/platform/auth.py`).** argon2id passwords of at least 12
  characters; a random cookie (`HttpOnly`, `Secure`, `SameSite=Strict`) of
  which only the SHA-256 is stored; 8 hours idle, 7 days at most; a disabled
  account is signed out on its next request. Every write made with a session
  must carry its CSRF token in `X-CSRF-Token`. After three failed sign-ins for a
  name or an address, each attempt waits twice as long as the last, up to five
  minutes; the setup code is throttled the same way.
* **API tokens.** `ipt_` and 32 random bytes, shown once, stored as SHA-256,
  scoped (`read`, `triage`, `ingest`), revocable, with an optional end date and
  the time of last use. Only a signed-in admin manages them.
* **Workspaces (`app/platform/scope.py`).** Every read of a row by its id goes
  through a scoped getter: another workspace's case, entry or token is `404`
  with the same body as one that does not exist. Lists, stats, history diffs
  and the allow and block lists that shape a verdict are filtered the same way.
* **Provider keys are the workspace's (`app/enrichment/credentials.py`).** A
  triage runs inside its workspace's credentials, so a lookup can only spend
  that workspace's keys; outside a workspace there are none. Keys are sealed,
  shown only as their last four characters, and limited to printable ASCII
  without spaces, because they travel in request headers. Every cached
  provider answer is filed under the workspace that asked, so another
  workspace neither reads it nor learns from the `cached` flag that someone
  looked at the same indicator.
* **The setup code.** The first account is the owner's, made with a one-time
  code that `python -m app.cli setup-code` prints on the operator's terminal.
  It is sealed in the database and never logged: whoever enters it first owns
  the server.
* **Audit actors are verified, not claimed.** The actor is what the server
  verified (a username, `token:<name>`, or `api-token` for the 1.x token); a
  name typed into `analyst` or `created_by` is kept as `claimed_by`.

*Tests:* a foreign page's list write and multipart upload, a look-alike
origin, `null` and a `cross-site` write without an `Origin` are all refused;
the dashboard and a script without an `Origin` can still write; token missing,
wrong, wrong scheme and correct; health and preflight stay open; a `401` is
readable by the dashboard; a typed `created_by` does not become the actor.
`tests/test_platform_sessions.py`, `test_platform_tokens.py` and
`test_platform_isolation.py` cover setup, sign-in, CSRF, the throttle, expiry,
roles, every token scope, revocation, and every id-taking route from another
workspace.

### Outbound egress policy (`app/net.py`)

IntelPulse never fetches a URL an analyst supplies; indicators go to fixed
vendor endpoints as path or body parameters, so there is no classic SSRF sink.
The controls exist anyway, because "no sink today" is not a control:

* **Host allowlist.** Every outbound request must target one of twelve known
  intelligence hosts. A new provider, a typo in a URL template or a manipulated
  path can only ever reach a known service.
* **HTTPS only.** Plain HTTP is refused before a socket is opened.
* **Resolution check.** The resolved addresses are tested against private,
  loopback, link-local (including `169.254.169.254`), CGNAT, benchmarking and
  documentation space. An allowlisted host whose DNS answer points inward
  (rebinding, a poisoned resolver, a hijacked domain) is refused.
* **Redirects are re-validated.** httpx re-enters the transport for every hop,
  so a vendor redirecting to an internal host is blocked at the hop that tries
  it.
* **Ticket sinks are per client and per workspace.** A workspace admin sets the
  workspace's Jira or ServiceNow address (https only, no credentials, query or
  fragment in it; a ServiceNow table is a plain name). The client that delivers
  that workspace's ticket may reach exactly that host, and no other client may.
  `TICKET_ALLOW_PRIVATE_HOST` opens private address space only to hosts the
  operator named (`JIRA_BASE_URL`, `SERVICENOW_BASE_URL`,
  `TICKET_PRIVATE_HOSTS`), never to one an admin typed into Settings, so the
  setting cannot be used to reach an internal service.
* **Path encoding.** Indicators interpolated into vendor URLs are
  percent-encoded with no safe characters, so a value containing `/`, `?`, `#`
  or `@` cannot reshape the request.

*Known limit:* there is a window between resolution and connection that only
IP-pinned connections close. The host allowlist is the control that holds; the
DNS check is defence in depth.

*Tests:* reserved-range detection, non-allowlisted host, plain HTTP, metadata
IP, an allowlisted host resolving to `127.0.0.1`, and a test that fails if any
feed URL in the codebase is missing from the allowlist; a workspace's sink host
reachable only by its own ticket client, and a typed internal host refused
even with the private opt-in on.

### Indicator filtering (`app/ioc.py`)

Private, loopback, link-local, CGNAT and documentation addresses are dropped
during extraction, so internal addresses pasted from a firewall log are never
sent to a third party. This is a data-leakage control, not an SSRF one, and it
runs before any provider is called.

### Rate limiting (`app/security.py`)

Per-client sliding windows, sized by what an endpoint actually costs:

| Bucket | Default | Covers |
| --- | --- | --- |
| `triage` | 30/min | `/api/triage*`, feed refreshes, which spend vendor quota |
| `write` | 60/min | other `POST`/`DELETE` |
| `read` | 240/min | `GET` (the dashboard polls health) |

Exceeding a bucket returns `429` with `Retry-After` and `X-RateLimit-*`.
`X-Forwarded-For` is **ignored unless `TRUST_FORWARDED_FOR=true`**: trusting it
without a proxy in front hands every attacker an unlimited supply of
identities. Behind Cloudflare, even trusting it is wrong: Cloudflare appends
the client to whatever `X-Forwarded-For` the client sent, so the first entry
is the client's to choose. `CLIENT_IP_HEADER=CF-Connecting-IP` reads the one
header Cloudflare alone sets instead; the deploy kit sets it, and publishes
the app on `127.0.0.1` only, so nothing but the tunnel can reach the app to
forge that header either.

Triage spends the server's provider quota, which every workspace shares, so
the triage routes and `POST /api/alerts` also pass two budgets
(`app/platform/budget.py`): `RATE_LIMIT_USER_TRIAGE` (30) a minute for each
person and each API token (keyed by the token, not its name), and a daily
budget for each workspace that the owner sets in the Server pane (500 triages
and pushed alerts in 24 hours until then). The check runs after the caller is
known and before anything is spent; a call refused for its session, scope or
CSRF token costs nothing. Each bucket keeps its own window, so the minute
sweep never drops a daily count. `tests/test_limits.py` covers both budgets.

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

### Input that is stored or written into tickets (`app/text.py`)

* **List entries must be indicators.** A value is refanged and classified; if
  it is not a single routable IP, domain, URL, hash, email or CVE it is `422`.
  The server derives the type instead of trusting the client's `ioc_type`.
* **Labels are one visible line.** Titles, filenames, reasons and analyst
  names lose control characters, zero-width characters and bidi overrides
  ("Trojan Source"), and are truncated.
* **Tickets are escaped.** Everything that reaches the Markdown report from a
  paste, an upload name or a vendor (title, analyst, family names, technique
  names, tags, rationales) is flattened to one line, has its URL schemes
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

### Response headers (`app/security.py`)

`Content-Security-Policy` (`default-src 'none'` for API routes, a narrower
Swagger-compatible policy for `/docs`), `X-Content-Type-Options`,
`X-Frame-Options`, `Referrer-Policy`, `Cross-Origin-Opener-Policy`,
`Permissions-Policy`, HSTS when `ENVIRONMENT=production`, and an
`X-Request-ID` on every response.

CORS is explicit about methods and headers, and the default origin list is
the local dashboards and the published site, not `*`. With `*` any page in any
browser may call the API and the write guard is off, so the app logs a warning
whenever it sees it.

### Logging (`app/logging_config.py`)

JSON lines with request id, client address, method, path, status and duration,
so the output ships into the SIEM this tool feeds. A masking filter redacts
configured secret values (including `API_TOKEN` and the Jira and ServiceNow
credentials) and anything shaped like a credential (`key=`,
`api_key:`, `Authorization: Bearer`, a password inside a Postgres URL) in the
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


The deploy kit (`deploy/compose.yml`) runs the app, the worker and beat with a
read-only root filesystem (they write only to the data volume and `/tmp`),
every Linux capability dropped and `no-new-privileges`. Postgres and Redis
publish no port, the app only `127.0.0.1:8000`; the Cloudflare Tunnel is the
way in from outside, so the machine needs no open inbound port.
`deploy/.env` is written mode 600 and is kept out of git and of the image's
build context. `tests/test_deploy_kit.py` holds the kit to all of this.

### Writes from behind a tunnel

The origin guard refuses a browser write whose `Origin` is not the server's
own. Behind the tunnel the app sees `http://` while the browser is on
`https://`, so the origin of `PUBLIC_URL` counts as the server's own as well,
compared exactly (scheme, host and port): `http://` of the same host, or a
lookalike host, is still refused (`tests/test_behind_a_proxy.py`).
---

## Frontend controls

* **Output encoding.** Everything the workbench renders from a log line, a
  provider response or a stored case goes through `esc()`
  (`web/assets/console-panes.js`); the generated report is set with
  `textContent`. The browser test pastes `<script>`, `<img onerror>`,
  `"><svg onload>` and a `javascript:` URL into the ingest field and asserts
  nothing executes and no element is injected.
* **Toasts are text.** The console's toast took markup until the workbench
  moved into the console, where it announces indicator values, which come out
  of pasted logs. It sets `textContent` now, and a test hands it an `<img>`.
* **URL scheme validation.** Escaping makes a URL safe to sit in an attribute;
  it does not make it safe to follow. `safeUrl()` rejects everything that is not
  `http:`/`https:`, so a hostile provider `reference` or ATT&CK link renders as
  text instead of a link. Tested with a hostile result payload and a scheme
  matrix.
* **CSP.** A `<meta>` policy blocks inline script, `eval`, objects and form
  submission, and limits script to this origin: no CDN, now that neither graph
  loads a library. The fonts are bundled too (`web/assets/fonts/`, SIL OFL), so
  a page loads nothing from any other host, and a browser test fails if one
  does. The two redirect stubs (`workbench.html`, `explorer.html`) run no
  script at all: `default-src 'none'`.
  The IntelPulse server serves the pages itself and sends the policy as a real
  header (`default-src 'self'; script-src 'self'; ... connect-src 'self';
  frame-ancestors 'none'`), which a meta tag cannot fully express; it serves
  only the pages and `assets/`, never the test suites beside them.
  `web/nginx.conf` does the same for anyone hosting the static demo. GitHub
  Pages cannot send headers, which is why the app never depends on them for
  correctness.
* **Nothing from outside is trusted as a shape.** Every result the API returns
  goes through `normalizeResult()` before anything renders it: numbers become finite numbers, lists become arrays,
  a verdict is recomputed from the score. Before, a string where a count was
  expected went into `innerHTML` unescaped (`cache_hits`, `providers_queried`,
  the contribution chart's weights), and a wrong type crashed the pane in 89
  places.
  The browser test mutates a real result one field at a time (markup, `null`,
  a number, a boolean, an object, an array) and asserts no script, no injected
  element and no uncaught error.
* **Stored state is validated.** The mode must be `live` or `demo`, the backend
  URL must pass `safeUrl()`, lists and history must be arrays of objects, and
  snapshots are read into a map with no prototype; a `javascript:` backend
  address is never used. Poisoned `localStorage` used
  to crash the workbench; now it falls back to defaults, and a `__proto__` key
  pollutes nothing.
* **No credential in the page.** Served by an IntelPulse server, the console
  signs in with an `HttpOnly` session cookie the page cannot read, and keeps
  the CSRF token the server hands out in memory only, sending it as
  `X-CSRF-Token` on writes (`web/assets/data.js`). There is no API address and
  no token field any more, so there is nothing to type, store or leak; scripts
  use API tokens instead. The hostile-server test also plays the session
  (a person's and a workspace's names as markup) and checks that no credential
  reaches `localStorage` or `sessionStorage`.
* **No case in the browser.** On a server the workbench keeps none of the
  workspace's cases in `localStorage`: the case history comes from
  `GET /api/cases` and the "what changed" comparison from the API. Until 2.0 it
  kept the last 25 titles and verdicts and every indicator it had seen there,
  where they outlived the session and were shown to whoever used the browser
  next; opening the workbench on a server now deletes what an older version
  left. The demo still keeps its own sample triages in the browser. The server
  suite checks that nothing of a case reaches `localStorage`.
* **Degradation.** A slow or dead backend produces a skeleton, then a message,
  never a frozen page. Tested by aborting every `/api/**` request after 2.5 s.

---

## Verifying it yourself

```bash
cd backend && pytest -q                 # 465 tests incl. the security suite and the audit's regressions
cd backend && pip-audit -r requirements.txt
python3 -m http.server 8123 --directory web &
node web/tests/ui.spec.mjs              # workbench + campaign graph checks (needs Playwright)
node web/tests/suite.spec.mjs           # site + console browser checks
node web/tests/mobile.spec.mjs          # phones, tablets, and the assistant panel
node web/tests/security.spec.mjs        # hostile API, poisoned storage, CSP, tabnabbing
```

## Reporting

Please report vulnerabilities privately, not as a public issue: the policy, the
scope and the private reporting link are in [`SECURITY.md`](../SECURITY.md).

## Tier 1: what a case was made from

The paste or uploaded file's text, and a pushed alert's description and evidence text, are sealed
with `ENCRYPTION_KEY` (AES-256-GCM, a fresh nonce each time) into `case_inputs`, bound to their case
(`case_inputs:sealed:<case id>` is the associated data, so a value copied to another case's row does
not open), with the SHA-256 of what was sealed beside them. A database backup without the key does
not show them. Migration 0007 moved every 1.x paste and alert text there and dropped
`cases.raw_input`; downgrading opens them and puts them back. Everything else about a case (the
verdict, indicators, provider answers, the alert's source, severity, entities and techniques) is
tier 2. `tests/test_case_inputs.py` covers the sealing, the binding, who reads the paste, the report
after deletion, and the migration both ways.

## Rotating `ENCRYPTION_KEY`

`python -m app.cli rotate-key` opens every sealed value with the current key and seals it again
with a new one: the settings' secrets (provider keys, tracker credentials, the setup code) and every
case's tier 1. It runs in one transaction, so if any value does not open with the current key
nothing is changed, and a half-rotated database (values neither key opens) cannot happen. The new
key comes from `NEW_ENCRYPTION_KEY` or `--new-key-file`, never from the command line, where it
would stay in the shell's history; the current key is refused as the new one. The rotation is
audited as `server.key_rotated` with how many values of each kind it re-sealed.

1. Stop the API and the worker, so nothing is sealed with the old key while the rotation runs.
2. `python -m app.cli new-key` prints a fresh key.
3. `NEW_ENCRYPTION_KEY=<the new key> python -m app.cli rotate-key` (with the current
   `ENCRYPTION_KEY` still set).
4. Put the new key in `ENCRYPTION_KEY` and start both again. Backups made before the rotation still
   need the old key: keep it as long as you keep them.

`tests/test_rotate_key.py` covers the re-sealing, the server reading everything on the new key,
the audit record, the all-or-nothing abort and the command's refusals.
