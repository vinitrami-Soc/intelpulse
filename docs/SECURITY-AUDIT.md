# Security audit, September 2026

An adversarial pass over the whole of IntelPulse: the FastAPI backend (21
operations), the console (workbench and campaign graph panes), the static site,
and the two ways it ships (GitHub Pages, and Docker Compose with nginx). The
aim was to break it, not to confirm it works. Every finding below was
reproduced against the code as it stood, fixed, and pinned by a test that
fails on the old code.

Findings are mapped to the **OWASP Top 10:2025**, the **OWASP API Security Top
10:2023**, and **OWASP ASVS 5.0**. The ASVS mapping is by chapter, not by
requirement number. The standing controls, and what each one's test proves,
are described in [`SECURITY.md`](SECURITY.md).

---

## Summary

Thirteen findings: two high, five medium, six low. All are fixed. What was
left alone, and why, is under [Residual risk](#residual-risk).

| # | Finding | Severity | Top 10:2025 | API 2023 | ASVS 5.0 |
| --- | --- | --- | --- | --- | --- |
| F1 | Any page the analyst had open could write to the local API | High | A01 | API8 | V3, V4 |
| F2 | No way to require credentials; the audit log recorded whoever the client claimed to be | High | A07, A09 | API2 | V6, V16 |
| F3 | A chunked body skipped the size limit | Medium | A10 | API4 | V4 |
| F4 | Errors echoed the request, and out-of-range numbers were `500`s | Low | A10, A02 | API8 | V16 |
| F5 | The allow/block list stored anything, with a type the client chose | Medium | A08 | API3 | V2 |
| F6 | Attacker text could write the Markdown ticket | Medium | A05 | API10 | V1 |
| F7 | A binary upload became a triaged case | Low | A06 | API4 | V5 |
| F8 | Catastrophic backtracking in indicator extraction (ReDoS) | Medium | A10 | API4 | V2 |
| F9 | Three result fields reached `innerHTML` unescaped | Medium | A05 | API10 | V1, V3 |
| F10 | A wrongly typed field crashed the workbench, in 89 places | Low | A10 | API10 | V2 |
| F11 | Poisoned `localStorage` crashed the workbench | Low | A08 | — | V3 |
| F12 | GeoIP swallowed every exception silently | Low | A09, A10 | — | V16 |
| F13 | Log masking did not know the newer secrets | Low | A09 | — | V14, V16 |

Severity is judged for the deployment this is built for: one analyst or team,
a backend on `localhost` or inside the SOC network, and a browser that is open
to the rest of the web while it runs.

---

## Findings

### F1: any page the analyst had open could write to the local API (High)

**What happened.** `CORS_ORIGINS` defaulted to `*`, and nothing else checked
where a write came from. CORS only decides whether a page may *read* a
response. It does not stop a form post, a `no-cors` fetch or a multipart upload
from being sent. So while the backend ran, any page in the analyst's browser
could send the backend a write.

**Proof.** A page on a foreign origin posted `185.220.101.34` to `/api/lists`
as an allowlist entry with the reason "looks internal". The API answered
`201`, and the next triage of that Tor exit node scored it as allowlisted. The
same page could delete cases, plant a case through `/api/triage/upload` (no
preflight needed), or flush the intelligence cache.

**Fix.**
- The CORS default is now the local dashboards and the published site.
- A new guard refuses a `POST` or `DELETE` when:
  - its `Origin` is not listed and is not the API's own;
  - its `Origin` is `null`;
  - it has no `Origin`, and Fetch Metadata says `Sec-Fetch-Site: cross-site`.
- Scripts and `curl` send neither header, so the guard does not affect them.
- `CORS_ORIGINS=*` turns the guard off, and the app says so in a warning at
  startup.

**Tests.** `test_security_audit.py`, section F1: eight tests. They cover the
proven write, an upload that needs no preflight, a Fetch Metadata write with no
`Origin`, a look-alike origin, `null`, writes that must still work, and reads
that are answered but not shared.

### F2: no way to require credentials, and a claimed identity in the audit log (High)

**What happened.**
- There was no authentication at all, and no way to switch any on.
- The audit log's `actor` field was whatever the request body put in
  `analyst` or `created_by`. Any client could write an entry as "the-ciso".

**Fix.**
- Setting `API_TOKEN` makes every `/api/` route need
  `Authorization: Bearer <token>`. The exceptions are `/api/health` and
  `/api/scoring/model`.
- The token is compared in constant time with `hmac.compare_digest`.
- A failed request gets `401` with `WWW-Authenticate`.
- The rate limiter runs before the token check, so guessing is throttled.
- In production without a token, the app logs a warning.
- The audit actor is now the identity the server verified: `api-token` or
  `anonymous`. The name the client typed is kept as `claimed_by`.
- The console has a password field for the token. It keeps the token in
  `sessionStorage` and sends it with `credentials: "omit"`.

**Tests.** F2 section: four backend tests, covering a missing, wrong or
wrong-scheme token, open routes, a `401` the dashboard can read, and the actor
field. The browser suite checks three more things: the token is sent only in the
header, never appears in a URL, and never reaches `localStorage`.

### F3: a chunked body skipped the size limit (Medium)

**What happened.** The 1 MiB limit only read `Content-Length`. A request with
`Transfer-Encoding: chunked` declares no length, so a 20 MB chunked body passed
the check and was parsed in memory.

**Fix.** The middleware is now pure ASGI and counts the body as it streams in.
When the count crosses the limit, it answers `413` and tells the application
the client has disconnected. Raising an exception was not enough, because
FastAPI turns any error during a body read into its own `400`.

**Tests.** A chunked body of about 2.6 MB that never declares its length gets
`413`. A small chunked body still works.

### F4: errors that echo, and `500`s from bad numbers (Low)

**What happened.**
- A `422` repeated every offending value back to the client. A 250 KB body,
  markup included, came back as a 250 KB error.
- A 26-digit ID in a path overflowed SQLite and returned `500`.
- Schema fuzzing found the same thing with `?offset=76671816770795520000`.
- An unhandled exception returned a plain-text `500`.
- A client-chosen `X-Request-ID` was copied into logs and response headers
  unchanged.

**Fix.**
- A `422` now reports only the type, location and message of each error, at
  most 20 of them.
- Integer path and query parameters are capped at SQLite's range.
- An unhandled exception is logged with its traceback and answered as a JSON
  `500` that carries the request ID.
- A request ID is cut down to ASCII letters, digits, `-` and `_`, 64 at most.
- Every refusal the API can make (`400`, `401`, `403`, `404`, `413`, `415`,
  `429`) is now in the OpenAPI contract.

**Tests.** F4 section: five tests.

### F5: the allow/block list stored anything, typed by the client (Medium)

**What happened.** Any of these could be saved as a list entry:
- a value containing `CRLF`;
- a `<script>` tag;
- a sentence of prose;
- a private address that triage would never look up.

The client also chose `ioc_type`, so a mistyped entry never matched the
indicator it was meant for. The fields had no length limits.

**Fix.**
- The value is refanged, then classified. Unless it is exactly one routable IP,
  domain, URL, hash, email or CVE, the request gets `422`.
- The server works out `ioc_type` itself.
- The reason and the name are cleaned into a single visible line.
- Every field has a length limit.

**Tests.** Four hostile values, and a test that the server decides the type
(`Evil[.]Example[.]com` with `ioc_type: "<script>"` is stored as the domain
`evil.example.com`).

### F6: attacker text could write the ticket (Medium)

**What happened.** The Markdown report is pasted into Jira or ServiceNow, and
several parts of it come from outside:
- the case title (typed, or taken from an uploaded file's name);
- malware family names, technique names, tags and rationales (sent by vendors).

Any of these could contain newlines, links, images or table rows. A title could
open a fake `## 4. Recommended containment actions` section that said
"No action". A vendor's family name could embed a tracking image in the ticket.

**Fix.** `app/text.py` adds `clean_label()` and `md_text()`, and the browser
engine has the same functions. Every string from outside that reaches the
ticket is treated like this:
- flattened to one line;
- stripped of control, zero-width and bidi characters;
- given defanged URL schemes (`hxxp://`, `hxxps://`);
- escaped where `[ ] < > | \` or a backtick appear.

Indicators go in code spans, and are defanged too.

**Tests.** A forged section and a forged table row in a title, a filename with
a bidi override and a newline, and a test that a hostile string cannot make a
link, image, HTML tag or table cell.

### F7: a binary upload became a triaged case (Low)

An ELF executable uploaded to `/api/triage/upload` was decoded, scanned and
saved as a case. Now a NUL byte in the first 8 KiB gets `415`.

### F8: catastrophic backtracking in extraction (Medium)

**What happened.** The domain and email patterns could match the same text in
many overlapping ways. Input like `a.a.a.…`, `1.1.1.…` or `CVE-CVE-…` made
extraction quadratic. At the 200,000-character input limit, one request kept a
worker busy for about ten minutes. The triage rate limit allows 30 requests a
minute, so this was an easy denial of service. The browser engine had the
same patterns, so pasting that text froze the tab.

**Fix.** The repetition in both patterns is now bounded, in Python and in
JavaScript. A domain may have 1 to 20 labels, and each part of an email
address has its RFC length limit. Extraction no longer backtracks, and the
3,400-line extraction corpus still passes.

**Evidence.** Measured with the same generator before and after the fix:

| Input (backend, 190,000 chars) | Before | After |
| --- | --- | --- |
| `a.` repeated | 595.6 s | 0.40 s |
| `1.` repeated | 551.5 s | 0.53 s |
| `1.1.1.` repeated | 546.3 s | 0.50 s |
| `CVE-` repeated | 95.3 s | 0.20 s |

| Input (browser engine, 32,000 chars) | Before | After |
| --- | --- | --- |
| `a.` repeated | 2,721 ms | 15 ms |
| `1.` repeated | 2,587 ms | 23 ms |
| `CVE-` repeated | 631 ms | 8.5 ms |

**Tests.** Four backtracking shapes at the full input limit must each finish
in under 3 s. On the old code these tests ran past 60 s. The browser suite
pastes 190,000 hostile characters and checks that the tab stays responsive.

### F9: three result fields reached `innerHTML` unescaped (Medium)

**What happened.** `cache_hits`, `providers_queried` and the contribution
chart's weights were concatenated into markup on the assumption that they
were numbers. A hostile or compromised backend could make them strings, and
those strings rendered as HTML.

**Fix.** There is now one trust boundary, `normalizeResult()`, which every
result from the API passes through before it is rendered. It makes sure:
- numbers are finite numbers;
- lists are arrays;
- the verdict is recomputed from the score.

The chart code coerces its own inputs as well, as defence in depth.

**Tests.** `security.spec.mjs` takes a real result and changes one field at a
time to each of: markup, `null`, a number, a boolean, an object, an array. That
is 4,770 renders over 883 field paths. It checks that no element is injected,
no script runs and no uncaught error is thrown. A second test makes every field
of the API hostile at once.

### F10: a wrongly typed field crashed the workbench (Low)

The same fuzzing found 89 crashes. In the first pass, 42 came from calling
`toFixed` on a string. A wider second pass found 47 more, from a verdict that
was `null` or a number, and from diff lists that were not arrays.
`normalizeResult()` closes all of them, and the fuzz re-runs on every CI build.

### F11: poisoned storage crashed the workbench (Low)

Whatever `localStorage` held was trusted: the mode, the backend URL, the list
entries, the case history and the snapshots. Now:
- values of the wrong shape fall back to defaults;
- the backend URL has to pass `safeUrl()`, so a `javascript:` address is never
  used;
- snapshots are read into an object with no prototype, so a `__proto__` key
  pollutes nothing.

**Tests.** Four checks in `security.spec.mjs`.

### F12 and F13: logging (Low)

- **F12.** GeoIP lookups caught `Exception` and passed. A corrupt database
  would have looked like "no data". Now only `AddressNotFoundError` is
  expected, and any other error is logged with its traceback.
- **F13.** The log masking filter redacts the values of named secrets.
  `API_TOKEN`, `JIRA_API_TOKEN` and `SERVICENOW_PASSWORD` were added after that
  list was written, so they were missing from it. They are on it now. The
  pattern-based masking had covered bearer headers all along.

### Found earlier in the same cycle

The console's toast took markup, and once the workbench moved into the console
it announced indicator values taken from pasted logs. It was fixed, and given a
test, when the panes were merged, before this audit started.

---

## Coverage by OWASP Top 10:2025

| Category | What was tested | Result |
| --- | --- | --- |
| A01 Broken Access Control | cross-origin writes, CORS grants, object access by ID, SSRF through the egress policy | F1 fixed. There is no per-user data to separate (see residual risk). SSRF controls held. |
| A02 Security Misconfiguration | CORS default, response headers, `/docs` CSP, debug output, error bodies | F1 (CORS default), F4. Headers held. |
| A03 Software Supply Chain Failures | `pip-audit` on the pinned requirements; third-party script in the pages | No known vulnerabilities. No third-party script runs in any page. |
| A04 Cryptographic Failures | secrets at rest and in transit, token comparison | Secrets come from the environment and are masked in logs. The token is compared in constant time. HSTS in production. TLS is for the proxy in front. |
| A05 Injection | XSS through every rendered field, Markdown ticket injection, SQL injection (ORM only), header injection through the request ID | F6 and F9 fixed. No raw SQL. |
| A06 Insecure Design | upload types, fan-out limits, what the design trusts | F7 fixed. The fan-out cap held. |
| A07 Authentication Failures | whether auth could be switched on at all, token handling in the browser | F2 fixed. |
| A08 Software or Data Integrity Failures | what the server accepts as stored data, what the browser accepts from storage | F5 and F11 fixed. |
| A09 Security Logging & Alerting Failures | audit actor integrity, swallowed exceptions, secret masking, refusals logged | F2, F12 and F13 fixed. Refused writes and failed tokens are logged at WARNING. |
| A10 Mishandling of Exceptional Conditions | oversized, chunked, malformed and binary bodies; out-of-range integers; ReDoS; wrong-typed data in the browser | F3, F4, F8 and F10 fixed. |

---

## Method and tools

**Static analysis**

| Tool | Scope | Result on the final code |
| --- | --- | --- |
| bandit | `backend/app`, 4,728 lines | 0 issues. One earlier issue (B613, a literal bidi character in `text.py`) was fixed by writing the pattern as escapes. |
| ruff `S` rules | `backend/app` | clean |
| pip-audit | `backend/requirements.txt` | no known vulnerabilities |
| ESLint, `no-unsanitized` with `no-eval`, `no-implied-eval`, `no-new-func` and `no-script-url` | `web/assets/*.js` | 30 `innerHTML` assignments flagged. Each was traced by hand: it is either static markup, the site's own bundled demo data, or values passed through `esc()` and `safeUrl()`. The workbench ones are also covered by the render fuzz. |
| a search for bidi control characters | the whole repository | none |

**Dynamic testing of the API.** Hand-written attacks for each category above,
kept as tests in `backend/tests/test_security_audit.py` (34 tests). Then
property-based fuzzing with Schemathesis 4.28 across all 21 operations, with
every check on, including stateful links.

- Before the fixes, its first run (1,151 cases) found one server error, the
  `offset` `500`, and nine responses with status codes the contract did not
  document.
- On the final code, it ran 2,218 cases with a fixed seed and found **no
  server errors**.
- Nine contract notes remain, all understood:
  - Four are semantic `422`s the schema cannot express, such as "provide
    either `text` or `indicators`" and "must be a single routable indicator".
  - Two are cases where those `422`s carry a string `detail` rather than
    FastAPI's list.
  - Two are a bare `OPTIONS` without CORS headers getting `405` with no
    `Allow` header.
  - One is an oversized body answered with `413`, which Schemathesis does not
    count as a rejection.

**ReDoS.** Fourteen pathological input shapes at 190,000 characters, timed
through the backend extractor and the browser engine.

**Browser.** `web/tests/security.spec.mjs` has 27 checks in Chromium:
- the render fuzz;
- a hostile API on every endpoint the console calls;
- token handling;
- poisoned storage and prototype pollution;
- hostile hash routes, and the redirect stub;
- the CSP, tested live: an injected inline script, an event-handler attribute,
  `eval` and `new Function` from a same-origin script, and an image beacon to
  another host;
- `target=_blank` without `noopener`;
- a pathological paste;
- a final check that no page contacted a host it should not.

**Regressions.** Every backend finding test was run against the pre-audit
code, and 25 of them failed there. The ReDoS tests did not finish.
`security.spec.mjs` also fails on the pre-audit console, catching the
injection and the poisoned-storage crash. A test that cannot fail proves
nothing.

---

## Residual risk

These are the known gaps left after the audit. Each is either a design limit
or a trade-off made deliberately.

- **One shared token, no users.** The token proves possession, not identity.
  There are no roles, and the audit log records `api-token`, not a person. It
  is off by default so the local demo works without setup. A multi-analyst
  deployment needs OIDC in front and per-user authorisation.
- **CSP compromises.**
  - `style-src 'unsafe-inline'`: the charts and the graph position elements
    with inline styles.
  - `connect-src https:`: the analyst can point the console at any backend.
  - The Google Fonts stylesheet is loaded without Subresource Integrity,
    because it is generated per browser and SRI cannot pin it. It is CSS
    only; no third-party script runs.
- **GitHub Pages cannot send headers.** The published demo has only the
  `<meta>` CSP: no `frame-ancestors`, no HSTS, no `nosniff`. The nginx
  deployment sends all of them. The demo holds no data, and its backend is
  optional.
- **Rate limits are per process.** The limiter keeps its state in memory, so
  four workers allow four times the rate. Put the limit in Redis, or at the
  proxy, before scaling out.
- **DNS rebinding window.** The egress check resolves and then connects. Only
  pinning the IP for the connection closes that gap. The host allowlist is the
  control that holds.
- **Schema contract notes.** The nine described above.

---

## Reproducing it

```bash
cd backend
pytest -q tests/test_security_audit.py tests/test_security.py
pip-audit -r requirements.txt
ruff check --select S app
bandit -q -r app

cd .. && python3 -m http.server 8123 --directory web &
node web/tests/security.spec.mjs

# API fuzzing, against a running backend with RATE_LIMIT_ENABLED=false
st run http://127.0.0.1:8000/openapi.json --checks all
```
