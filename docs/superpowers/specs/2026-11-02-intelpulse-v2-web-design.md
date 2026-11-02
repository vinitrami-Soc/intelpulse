# IntelPulse v2: self-hosted, multi-user web app (design)

Status: approved in brainstorming on 2026-11-02; written spec awaiting owner review
Owner: Vinit Rami
Builds on: IntelPulse 1.0.1 plus the unreleased webhook ingestion (`POST /api/alerts`), and
PhishHawk v3's web platform, whose design is in `docs/superpowers/specs/` of
[vinitrami-Soc/phishhawk](https://github.com/vinitrami-Soc/phishhawk): `2026-10-06-phishhawk-v3-web-design.md`
and `2026-10-13-workspaces-signup-feedback-design.md`.

## 1. Summary

IntelPulse today is a triage engine with a good console in front of it, but it is a single-user
tool: one shared `API_TOKEN`, an API on one port and a static dashboard on another, and a console
whose views, apart from the workbench, draw a synthetic dataset. v2 makes it a product a SOC team
can sign in to, the way PhishHawk 3 is: accounts and workspaces, two roles, invitations, email
for confirmation and password reset, provider keys set in the browser and kept encrypted, a
hash-chained audit log, raw alert text encrypted and deleted on a schedule, one origin for the
site, the console and the API, every console view on the workspace's own cases, and a deploy kit
for one small server behind a Cloudflare Tunnel.

The triage engine (extraction, providers, scoring, graph, reporting) does not change in v2,
except where a provider must read its key from the workspace instead of the environment. The
GitHub Pages demo keeps working exactly as it does now. Integrations (new providers,
notifications, STIX and MISP, the PhishHawk handoff, SIEM adapters) are the next spec, built on
this one.

## 2. Decisions

| # | Question | Decision | Why |
|---|---|---|---|
| D1 | Frontend | Grow the existing vanilla-JS console. New pages (sign-in, settings, team, tokens, audit, profile) use the console's tokens and style, in new files beside the existing ones. No framework, no build step. | The console carries 309 browser checks and a design that has been through many rounds; the GitHub Pages demo stays a plain static copy. |
| D2 | Accounts | PhishHawk's model: one server owner; sign-up that the owner turns on and off; **Individual** and **Organization** workspaces; `admin` and `analyst` roles; one-use invite links. | A public server is only safe when every workspace's data is apart; the same rules as PhishHawk, already reviewed and tested there. |
| D3 | Identity | Accounts are separate from PhishHawk's. The products connect through API tokens (a later spec stores PhishHawk's token, encrypted, in an IntelPulse workspace). No SSO or OIDC in v2. | Each product stays whole on its own; PhishHawk's `/api/v1` was already built for IntelPulse to call. |
| D4 | Raw alert text | Two tiers. Tier 1 (the paste, the uploaded file's text, a pushed alert's description and evidence) is encrypted and deleted after `RETENTION_DAYS` (30) unless held. Tier 2 (verdicts, indicators, provider results, case workflow, tickets) is kept until deleted by hand. | Alerts carry user names, host names and internal addresses; the threat intelligence does not need them after the working window. |
| D5 | Provider keys | Each workspace brings its own keys. The offline feeds (Feodo, FireHOL, ThreatFox export, CISA KEV, NVD, GeoLite2) serve every workspace. The owner's keys are never lent to other workspaces. | No one can spend the owner's quota, and free tiers that forbid sharing a key are not broken. |
| D6 | Platform code | Port PhishHawk's server modules (auth, accounts, scope, crypto, audit, retention, mailer, limits, rotation) into IntelPulse, rewritten for IntelPulse's async SQLAlchemy, with their tests. Alembic replaces `create_all`. | Proven rules, one repository to change; PhishHawk is synchronous and not on PyPI, which rules out a shared library for now. |
| D7 | API compatibility | Every existing `/api` path keeps working. The old `API_TOKEN` keeps the access it has today, to the existing endpoints, inside the default organization; it is logged as deprecated and goes in v3. | DwellWatch already pushes to `POST /api/alerts`; the CHANGELOG names `/api` as the public interface. |
| D8 | Delivery | Four milestones (section 13), each a series of small PRs; v2.0.0 after M4. Integrations get their own spec after that. | Every PR leaves the demo, the API and the tests working. |

## 3. Scope

In v2.0:

- Owner setup with a one-time code; sign-up (Individual or Organization) while the owner allows
  it; invitations; profiles.
- Sessions with CSRF protection; API tokens with scopes; login throttling.
- Workspaces: every case, alert, indicator, list entry, setting, token and audit record belongs to
  one, and no workspace reads another's.
- Optional email (any SMTP server): address confirmation and password reset.
- Per-workspace settings: provider keys (encrypted), Jira and ServiceNow credentials (encrypted),
  retention days, allow and block lists.
- A case workflow: status, assignee, closing reason.
- Every console view on the workspace's own data; Settings, Team, API tokens, Audit, Profile and
  Server pages.
- Tier 1 encryption, retention, hold, delete; key rotation.
- Hash-chained audit log with verification.
- One origin serving the site, the console and the API; self-hosted fonts.
- Product, privacy and help pages; a deploy kit (Compose, Postgres, Cloudflare Tunnel, backups,
  updates); `/healthz`; `SERVER.md` and `DEPLOY.md`.

Out of scope for v2.0 (later specs): new providers (VirusTotal, MalwareBazaar, Shodan InternetDB,
EPSS, RDAP, urlscan.io); notifications (Slack, Teams, PagerDuty, webhooks); STIX 2.1 and MISP
export; the PhishHawk handoff; SIEM adapters (Wazuh, Graylog, Splunk, Sentinel); OIDC and SSO;
a plain-language view for individual accounts; LLM features; anything that acts on a firewall or
an endpoint.

## 4. Architecture and components

One FastAPI process serves three things: the static site and console at `/`, the JSON API under
`/api`, and `/healthz`. Celery, as today, runs the feed refreshes and now also the retention
sweep. Postgres in production, SQLite for development and tests; Redis for Celery and the
provider cache, as today.

| Unit | Responsibility | Depends on |
|---|---|---|
| `app/platform/crypto.py` | `Box`: AES-256-GCM seal and open, with associated data naming the table, column and row. | `cryptography` |
| `app/platform/settings_store.py` | Per-workspace settings, secrets sealed with `Box`; server-wide settings under workspace 0. | db, crypto |
| `app/platform/auth.py` | argon2id hashing, sessions, CSRF tokens, login throttle, API tokens and scopes, the `Actor` (user, workspace, role, via session or token). | db |
| `app/platform/accounts.py` | Setup code, owner setup, sign-up, invites, joining, profile rules, email confirmation and reset tokens. | db, auth, mailer |
| `app/platform/scope.py` | Scoped getters: every read of workspace data goes through them; another workspace's row is 404. | db |
| `app/platform/audit.py` | Append-only, hash-chained audit records and verification. | db |
| `app/platform/retention.py` | Retention sweep, delete now, delete completely, hold. | db, crypto |
| `app/platform/mailer.py` | SMTP, only when configured; messages built from fixed templates. | stdlib `smtplib` in a thread |
| `app/platform/limits.py` | Per-IP, per-user and per-workspace budgets (triage, sign-up, login). | Redis or memory |
| `app/routers/` | New routers: `session`, `accounts`, `users`, `tokens`, `settings`, `workspace` (indicators, campaigns, assets, sources). Existing routers gain an `Actor` dependency. | everything above |
| `app/migrations/` | Alembic environment and versions. | Alembic |
| `app/cli.py` | New commands: `migrate`, `setup-code`, `rotate-key`, `audit verify`. | everything above |
| `web/assets/data.js` | One data interface for the console with two sources: `DemoSource` (today's synthetic data and in-browser engine) and `ServerSource` (same-origin `fetch` with the CSRF header). | `engine.js`, `demo-data.js` |
| `web/assets/account.js` | Sign-in, sign-up, join, reset, confirm, setup and profile views. | `data.js` |
| `web/assets/admin.js` | Settings, Team, API tokens, Audit and Server panes. | `data.js` |

New Python dependencies: `alembic`, `argon2-cffi`, `cryptography`. Each is pinned and audited with
`pip-audit`, as the existing pins are.

**Mode.** At load the console calls `GET /api/session`. A JSON answer means server mode: the
console needs a session (or shows the public pages) and draws the workspace's data. Any other
answer (the static GitHub Pages copy, or a file opened from disk) means demo mode, which is today's
behaviour unchanged. The workbench's "Live API" box and its `sessionStorage` token go away: a
server serves its own console, and scripts use API tokens.

**One origin.** The Docker image is built from the repository root and carries `web/`. Compose
loses the separate dashboard container on port 8080; the app answers on one port. `web/nginx.conf`
stays for anyone hosting the static demo themselves. Outfit and JetBrains Mono are bundled under
`web/assets/fonts/` (OFL), so neither the server nor the demo calls Google Fonts.

## 5. Accounts, workspaces and roles

### 5.1 Concepts

- **Workspace**: `kind` (`organization` or `individual`), name, created time. Holds cases, pushed
  alerts, indicator results, list entries, settings, API tokens, invites and its part of the audit
  log. It never sees another workspace's data.
- **Member**: every user belongs to exactly one workspace, as `admin` or `analyst`. An individual
  workspace has one member, its admin.
- **Owner**: the person who runs the server (`users.owner = true`), created at setup, also the
  admin of their own organization. Only the owner turns sign-up on and off, sets server-wide limits
  and refreshes the shared feeds. The owner does not see other workspaces' cases.

### 5.2 Setup

A server with no accounts says at start to run `intelpulse setup-code`, which prints a one-time
code on the operator's own terminal; the code is never written to the log. At `#/setup` the owner
enters the code, their username, email (required when email is configured), password and
organization name. The "Default organization", which holds every row from before the upgrade, is
renamed to it, and the code stops working.

### 5.3 Sign-up

While the owner allows it (off by default), anyone can create:

- **Just me**: an individual workspace;
- **My organization**: an organization workspace, of which they are admin.

The form asks for a username, a display name, a password (at least 12 characters, as in
PhishHawk), an organization name for an organization, and an email address when email is
configured. Sign-ups are limited per address and by a daily cap of new workspaces for the whole
server (100 until the owner sets another).

### 5.4 Invitations

An organization admin creates a one-use link for a role. It expires after 7 days; only its SHA-256
is stored. Opening `#/join/<token>` creates the member's account in that workspace.

### 5.5 Email (optional)

With `SMTP_*` and `PUBLIC_URL` set:

- **Confirmation**: a link confirms an address. The link opens a page whose button confirms, so a
  mail scanner that follows links confirms nothing. Nothing else is sent to an unconfirmed address.
- **Forgot password**: the answer is the same whether or not an account matches. The reset link
  works once, for one hour, and the new password ends every session of the account.

Without email, an admin sets a member's password (the owner sets an admin's), and the member must
change it at the next sign-in.

### 5.6 Roles

| Action | Analyst | Admin | Owner (in addition) |
|---|---|---|---|
| Triage (paste, upload), view every case of the workspace, assign, change status, create a ticket | yes | yes | |
| Read or delete a case's raw input (tier 1) | own cases | any | |
| Hold and release, delete a case completely | no | yes | |
| Allow and block lists | read | read and change | |
| Provider keys, Jira and ServiceNow, retention days | no | yes | |
| Members, invitations, API tokens | no | yes | |
| Audit log | own actions | whole workspace | |
| Sign-up on and off, server limits, feed refresh | | | yes |

### 5.7 Sessions, CSRF and API tokens

- **Session**: 32 random bytes in cookie `ip_session` (`HttpOnly`, `Secure` unless the server runs
  on plain `http://localhost`, `SameSite=Strict`, `Path=/`). The server stores only its SHA-256.
  Idle timeout 8 hours, absolute limit 7 days. Signing out deletes it.
- **CSRF**: `GET /api/session` returns a per-session token; every state-changing request made with
  a session cookie must carry it in `X-CSRF-Token`. Requests with a bearer token carry no cookie,
  so CSRF does not apply to them. The existing origin guard stays.
- **Login throttle**: per username and per address, with a growing delay after failures.
- **API tokens**: created by an admin, shown once, stored as SHA-256, prefixed `ipt_`, optional
  expiry, revocable, last use recorded. Scopes:
  - `read`: every `GET` of the workspace;
  - `triage`: `read` plus `POST /api/extract`, `/api/triage`, `/api/triage/upload`;
  - `ingest`: `POST /api/alerts` only (DwellWatch, SIEM integrations).
- **Legacy `API_TOKEN`**: still accepted, inside the default organization, for every endpoint that
  existed before v2 (the access it has today) and for none of the new account, team, token or
  settings endpoints; each use logs a deprecation warning.

## 6. Data, encryption and retention

### 6.1 Workspace scoping

These tables gain `workspace_id` (not null, foreign key, index): `cases`, `pushed_alerts`,
`indicator_results`, `list_entries`, `api_tokens`, `invites`, `users`, `settings`, and
`audit_log` (null for server-wide records). Uniqueness becomes per workspace:
`(workspace_id, source, alert_id)` for pushed alerts and `(workspace_id, value, list_type)` for
list entries. The feed tables (`feed_entries`, `feed_runs`, `cve_records`) stay server-wide.

Every read of workspace data goes through `scope.py`; a row of another workspace is 404, never
403, so nothing reveals that it exists.

### 6.2 Migrations

Alembic replaces `create_all`. Migration 0001 is today's schema; on a database that already has it,
`intelpulse migrate` stamps 0001 instead of creating tables. 0002 adds workspaces and users and
puts every existing row in "Default organization". Later migrations follow the milestones. The
current environment keys (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY`,
`ABUSECH_AUTH_KEY`, the Jira and ServiceNow settings) are copied, sealed, into the default
organization's settings at the first start after the upgrade; afterwards the environment values are
ignored with a warning.

### 6.3 Two tiers

**Tier 1** (sealed; deleted after `RETENTION_DAYS`, default 30, unless held), in a `case_inputs`
table so that one database backup holds everything:

- the paste, or the uploaded file's text (`cases.raw_input` today);
- a pushed alert's `description` and every evidence item's `text`.

**Tier 2** (kept until deleted by hand):

- the case: title, source, verdict, score, indicator count, duration, created by, status,
  assignee, closing reason and times, ticket references;
- indicator results with their provider payloads, malware families and ATT&CK IDs;
- a pushed alert's source, alert ID, severity, title, entities and ATT&CK techniques.

A report or ticket rendered after tier 1 is gone leaves out the alert's evidence lines and says that
the raw input was deleted on that date under the retention policy.

### 6.4 Encryption

- `ENCRYPTION_KEY` (32 random bytes, base64, from the environment or a secret file) is required;
  without it the server refuses to start, and with the wrong key it refuses to open anything and
  deletes nothing. `make keys` and `deploy/setup.sh` generate it.
- Sealed with it: tier 1, provider keys, Jira and ServiceNow credentials, the setup code. Each value
  has a fresh 96-bit nonce and associated data `table:column:row`, so a value copied to another row
  fails to open.
- Sessions, CSRF tokens, invites, reset links and API tokens are random values stored as SHA-256
  hashes, so no signing key is needed.
- `intelpulse rotate-key` re-seals everything under a new key and records the rotation in the audit
  log.

### 6.5 Retention, deletion and hold

- A `retention_sweep` Celery job runs hourly: it deletes tier 1 older than the workspace's
  retention days unless the case is held, marks the case `input_deleted_at`, and writes one audit
  record per workspace with the count.
- **Delete input now** (tier 1): an analyst for their own cases, an admin for any.
- **Delete completely** (admin): the case and its tier 2. The audit log keeps the case ID and the
  SHA-256 of the input.
- **Hold** (admin) exempts a case from the sweep; holding and releasing are audited.

### 6.6 Provider cache

A cached answer from a keyed provider belongs to the workspace whose key fetched it: the cache key
gains the workspace ID. Otherwise a workspace without a key would read answers fetched with another
workspace's key, and the `cached` flag would reveal that someone else had looked at the indicator.
Offline-feed lookups stay shared.

## 7. Workspace settings and providers

- Each provider has, per workspace, an on/off switch and its key. Keys are shown masked (last four
  characters) and can be replaced, not read back. "Test connection" makes one harmless lookup and
  reports the answer.
- Providers read their key from the workspace's settings, passed in with the triage request's
  `Actor`; nothing reads provider keys from the environment after the upgrade (6.2).
- Scoring weights and authority values stay server configuration, so that a verdict means the same
  thing on every workspace and the console's in-browser engine stays in parity.
- Jira and ServiceNow credentials move from the environment into the workspace's settings, sealed.
- Allow and block lists are per workspace.
- Retention days: 1 to 365, default 30.

## 8. Data flows

1. **Console triage**: `POST /api/triage` with the session cookie and CSRF token. The `Actor` gives
   the workspace and the user; the workspace's enabled providers run; the case is stored with
   `workspace_id` and `created_by`, its input sealed in tier 1; audit `triage`; the result returns
   as today.
2. **Pushed alert**: `POST /api/alerts` with an `ingest` token. The token gives the workspace;
   everything else is today's flow, with the retry rule per workspace.
3. **Case workflow**: `PATCH /api/cases/{id}` with `status` (`new`, `in_progress`, `closed`),
   `assignee_id` (a member of the workspace) and, when closing, `closed_reason`
   (`true_positive`, `false_positive`, `benign`, `duplicate`). `closed_at` is set on closing and
   cleared on reopening. Audited.
4. **Feeds**: refreshed by Celery beat as today; a manual refresh is owner-only, since the feeds are
   shared by every workspace.
5. **Retention**: section 6.5.

## 9. User interface

### 9.1 Routes

Public: `#/` (the site), `#/signin`, `#/signup`, `#/join/<token>`, `#/reset/<token>`,
`#/confirm/<token>`, `#/setup`, and in M4 `#/product`, `#/privacy`, `#/help`. Console routes
(`#/console/...`) need a session in server mode and redirect to `#/signin` without one. In demo
mode every route behaves as today.

### 9.2 Views on real data

| View | Server mode |
|---|---|
| Workbench | Today's triage under the session; the case lands in the workspace. |
| Overview | Counts per verdict band and status (awaiting, in progress, closed), from the workspace's cases; trends over 90 days; mean time to close from `closed_at`. The console model's arithmetic is reused unchanged. |
| Attack surface | Hosts and users named in pushed alerts' entities, each with its cases and highest verdict. Empty state: what fills it (an integration pushing alerts) and how to connect one. |
| Triage history | Every case, newest first, with search (indicator, title) and filters (status, verdict, source, assignee, date). |
| Triage queue | Open cases by priority and score, with assign and status controls. |
| All indicators | Each indicator once: latest verdict and score, first and last seen, number of cases, providers that flagged it. |
| Campaign graph | Cases of the last 90 days joined when they share a malware family or infrastructure (an indicator, or a relation's target such as an ASN). Today's graph component draws it. |
| Attack narratives | Each case's ATT&CK techniques in tactic order, with the evidence for each. |
| Intelligence sources | The workspace's providers: on or off, key set or not, last error, median latency and rate-limit count over 7 days; the shared feeds' last refresh. |
| SOC tickets | Cases with a ticket: Jira or ServiceNow link, created by and when, Markdown and JSON downloads. |

A new workspace with no cases shows an empty state in every view that points to the workbench.

### 9.3 New panes

- **Settings** (admin): Providers, Tickets (Jira, ServiceNow), Retention, Lists.
- **Team** (admin): members and roles, invitations, password set (without email).
- **API tokens** (admin): create (name, scope, expiry), list, revoke.
- **Audit**: filterable table; analysts see their own actions; "Verify chain" for admins.
- **Profile**: display name, email, password.
- **Server** (owner): sign-up on and off, daily sign-up cap, triage budget per workspace.

### 9.4 Design

The console's tokens, fonts, both themes, 44 px touch targets on coarse pointers, one `h1` per page,
visible focus, keyboard reach and the contrast gates apply to every new pane, and the existing design
guards (`web/tests/tokens.test.mjs`) cover the new files.

### 9.5 Public pages (M4)

Product, privacy and help, each with its own title and description. With
`INTELPULSE_INDEX_PUBLIC_PAGES=true` the server answers `robots.txt` and `sitemap.xml` for them; off
by default. The privacy page says what the server stores, for how long, and that provider lookups
send indicators to the providers a workspace enabled.

## 10. API

All endpoints accept a session cookie (with `X-CSRF-Token` on state-changing requests) or a bearer
token. Error bodies gain a stable code: `{"error": code, "detail": text}`; `detail` stays, so
existing clients keep working. New and changed endpoints:

| Method and path | Purpose | Who |
|---|---|---|
| `GET /api/session` | Mode, user, workspace, role, CSRF token, whether sign-up and email are on | anyone |
| `POST /api/session`, `DELETE /api/session` | Sign in, sign out | anyone, member |
| `POST /api/setup` | Owner setup with the setup code | anyone, once |
| `POST /api/signup` | Create an account and workspace | anyone, while open |
| `POST /api/invites`, `GET /api/invites`, `DELETE /api/invites/{id}`, `POST /api/join` | Invitations | admin; anyone with a link |
| `POST /api/password/forgot`, `POST /api/password/reset`, `POST /api/email/confirm` | Email flows | anyone |
| `GET/PATCH /api/profile` | Own profile and password | member |
| `GET/PATCH/DELETE /api/users/...` | Members and roles | admin |
| `GET/POST/DELETE /api/tokens/...` | API tokens | admin |
| `GET/PATCH /api/settings`, `POST /api/settings/providers/{name}/test` | Workspace settings | admin |
| `GET/PATCH /api/server` | Server settings | owner |
| `PATCH /api/cases/{id}` | Status, assignee, closing reason | member |
| `DELETE /api/cases/{id}/input`, `DELETE /api/cases/{id}`, `POST/DELETE /api/cases/{id}/hold` | Tier 1 delete, full delete, hold | 6.5 |
| `GET /api/indicators`, `GET /api/campaigns`, `GET /api/assets`, `GET /api/sources` | Data for the views in 9.2 | member |
| `GET /api/audit` | Audit records, scoped by role | member |
| `GET /healthz` | Database, Redis, worker heartbeat, disk space | anyone |

Every existing endpoint keeps its path and body, now scoped to the caller's workspace. The OpenAPI
document is committed as `docs/api/openapi.json`, and a test fails when the routes change without it.

## 11. Security

### 11.1 Threats

Attacker-written alert text reaching the browser (stored XSS in lists, graphs and tickets); one
workspace reading or changing another's data; an authenticated user acting beyond their role;
session theft and CSRF; secrets reaching logs, exports or the browser; sign-up abuse and quota
burning; the server used to reach internal hosts (existing egress policy).

### 11.2 Measures

- **Headers on every response**: Content-Security-Policy `default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self';
  form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'`, plus
  `X-Content-Type-Options`, `Referrer-Policy: no-referrer` and HSTS over TLS. `'unsafe-inline'` for
  styles is today's and stays until the console stops setting inline style attributes.
- **Escaping**: every value from an alert, a provider or a user is inserted as text; the existing
  escaping helpers and `safeUrl()` apply to the new panes.
- **Hostile payload test**: a fixture with `<script>`, `<img onerror>`, `javascript:` links,
  bidirectional overrides and control characters goes through triage, a pushed alert, a list entry,
  a case title and a user's display name, and every API response and every page is checked to inject
  nothing.
- **Isolation tests**: every workspace route is called with another workspace's IDs and must answer
  404.
- **Secrets**: only from the environment or secret files; never logged; masked in the UI; never
  returned by the API after they are set.
- **Logs**: JSON, with request ID, user ID and workspace ID; never alert text or keys.
- **Rate limits**: per address (today's buckets), plus per user (30 triages a minute, today's
  per-address triage budget) and per workspace (500 triages and pushed alerts a day until the owner
  sets another), so one workspace cannot use the whole server's budget.
- **Egress**: `net.py`'s allowlist and address checks are unchanged.

## 12. Errors and operations

- A provider failing: the case completes "partially checked", as today.
- Another workspace's object: 404.
- A wrong `ENCRYPTION_KEY`: the server refuses to start and says so; nothing is deleted.
- `/healthz` for monitors: database, Redis, the last Celery beat heartbeat, free disk space.
- Backups: the database and `ENCRYPTION_KEY`, documented together; a backup without the key cannot
  be read, by design. `deploy/backup.sh` takes a Postgres dump on a schedule.
- SQLite is for development and tests; the deploy kit uses Postgres.

## 13. Milestones

Each milestone is a series of small PRs. After every PR the demo, the existing API and every
existing test still work.

**M1: platform core.** `crypto`, `settings_store`, Alembic with 0001 and 0002, workspaces and
users, sessions and CSRF, login throttle, the owner's setup code and `#/setup`, sign-in and sign-out,
scoped API tokens, the legacy token, the audit chain and `intelpulse audit verify`, one origin with
the CSP header and bundled fonts, `data.js` with both sources, and the workbench on the session.
*Done when:* on a fresh server the owner sets up, signs in and triages from the workbench; the case
is stored in their workspace and a second workspace (made by the test, since sign-up is M3) gets
404 for it; `intelpulse audit verify`
passes and fails after a record is edited; every existing test is green.

**M2: the console on real data.** The case workflow, the endpoints in 9.2, every view in server
mode, Settings, Team (with admin-set passwords), API tokens, Audit and Profile panes, per-workspace
provider keys and cache, Jira and ServiceNow per workspace.
*Done when:* after 20 triages and 5 pushed alerts in a new workspace, every view shows only that
workspace's numbers and matches the API; a second workspace's console shows none of them; demo mode
is unchanged.

**M3: accounts and privacy.** Sign-up (Individual and Organization) and the Server pane, invitations,
email confirmation and reset, tier 1 sealing in `case_inputs`, the retention sweep, hold and both
deletes, `rotate-key`, per-user and per-workspace rate limits.
*Done when:* with a fake clock, a case past retention loses its input and keeps its verdict and
indicators; a held case keeps both; a reset link works once within the hour and ends every session;
sign-up honours the owner's switch and cap.

**M4: ship.** Product, privacy and help pages, robots and sitemap; `deploy/` (Compose with Postgres,
Redis, the app and Celery, a Cloudflare Tunnel, `setup.sh`, `update.sh`, `backup.sh`); `/healthz`;
`docs/SERVER.md` and `docs/DEPLOY.md`; a security review round recorded in
`docs/SECURITY-REVIEW.md`; screenshots; README, CHANGELOG and release **v2.0.0**.
*Done when:* `deploy/setup.sh` brings up a working server on a clean machine, a smoke test signs up,
triages and gets a verdict over the tunnel's address, and the review's findings are fixed or
recorded.

## 14. Testing

- Every existing test stays green at every step: 200 backend tests, 56 Node tests and 309 browser
  checks, the browser suites in demo mode.
- New backend tests under `backend/tests/platform/`, test first:
  - a role matrix that calls every route as anonymous, analyst, admin, owner and each token scope,
    and checks the status;
  - workspace isolation for every route that takes an ID;
  - sessions (idle and absolute expiry), CSRF, login throttle, token scopes and revocation;
  - crypto: round trip, nonce uniqueness, a value moved to another row fails, key rotation;
  - audit: verification passes, and fails after a record is edited, removed or reordered;
  - retention with a fake clock, hold, both deletes;
  - migrations: 0001 stamps an existing database; 0002 moves existing rows to the default
    organization; the legacy token still works;
  - email flows against a fake SMTP server;
  - the hostile payload test (11.2).
- A new browser suite, `web/tests/server.spec.mjs`, against a real server on SQLite: setup, sign-in,
  triage, assign, close, invite and join, settings, tokens, audit, sign-out; keyboard only; widths
  320 to 1440 px; the contrast gates on the new panes.
- CI gains the server suite and a Docker smoke test (Compose up, `/healthz`, set up, triage a
  sample).

## 15. Risks

- **The server now holds alert text from several organizations.** Mitigated by tier 1 sealing and
  retention, workspace scoping with isolation tests, and the audit log.
- **A missed scope check exposes another workspace.** Mitigated by routing every read through
  `scope.py` and the isolation test that covers every route; a route without a scoped getter fails
  the role matrix test.
- **Migration of existing deployments.** Mitigated by stamping, by the default organization, by
  copying environment keys once, and by keeping the legacy token for one major version.
- **Size.** Four milestones, each shippable; the engine is untouched.
- **Console complexity.** `suite.js` and `console-panes.js` are already 1,500 and 1,900 lines; the
  new panes go in new files (`account.js`, `admin.js`), and the data layer in `data.js`, rather than
  growing them.

## 16. After v2

A separate spec for integrations, using the workspace settings this one adds: new providers
(MalwareBazaar, VirusTotal, Shodan InternetDB, EPSS, RDAP, urlscan.io), notifications (Slack, Teams,
PagerDuty, signed webhooks), STIX 2.1 and MISP export, the PhishHawk handoff, SIEM adapters, an
External Dynamic List for firewalls, Prometheus metrics and a Grafana dashboard.
