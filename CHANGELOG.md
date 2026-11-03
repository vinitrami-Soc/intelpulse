# Changelog

All notable changes to IntelPulse are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[semantic versioning](https://semver.org/): the REST API under `/api` and the
JSON report are the public interface.

## [Unreleased]

### Added

- `POST /api/alerts`: webhook ingestion, so a SIEM can push an alert and get back a triaged case. The
  alert's own account (source, severity, entities, ATT&CK techniques, the events behind it) is stored
  beside the case in a new `pushed_alerts` table and opens its ticket, and its severity can raise the
  ticket's priority. When threat intelligence finds nothing actionable, a medium, high or critical
  alert's ticket says what to do about the alert (confirm, isolate, reset, hunt) instead of "no
  action required". Its indicators are extracted from the evidence like a paste. A retried push
  (same `source` and `alert_id`) returns the first case without spending vendor quota, and an
  optional `ticket` field files the case in Jira or ServiceNow. Built for DwellWatch's correlated
  ransomware incidents; `GET /api/cases/{id}` now includes `alert`.
- The groundwork of IntelPulse v2, the multi-user web app
  ([design](docs/superpowers/specs/2026-11-02-intelpulse-v2-web-design.md)):
  - **Migrations.** The schema is owned by Alembic (`backend/app/migrations`). A new database is
    built by the migrations; a 1.x database is recognised, stamped at the baseline and upgraded in
    place, keeping every row. A test keeps the migrations and the models identical.
  - **Workspaces.** New `workspaces`, `users`, `sessions`, `api_tokens` and `settings` tables, and a
    `workspace_id` on every case, pushed alert, indicator result and list entry. Existing rows belong
    to "Default organization". Allow and block lists, and the duplicate check for pushed alerts, now
    apply within a workspace.
  - **Sealed settings.** Per-workspace settings, with secrets kept only sealed (AES-256-GCM, bound to
    their workspace and key, so a value copied elsewhere does not open).
  - **A tamper-evident audit log.** Each audit record carries the hash of the one before it;
    `python -m app.cli audit verify` reports any record that was changed, removed or reordered, or a
    log cut short. Records from before the upgrade are chained by the migration.
  - **Accounts and sign-in.** `python -m app.cli setup-code` prints a one-time code (never logged)
    that creates the owner's account with `POST /api/setup`. People sign in with
    `POST /api/session`: argon2id passwords, an `HttpOnly`, `SameSite=Strict` session cookie of
    which only the SHA-256 is stored, a CSRF token on every write, and a growing delay after three
    failed attempts.
  - **API tokens** (`/api/tokens`, admin): `ipt_` tokens shown once, scoped to `read`, `triage` or
    `ingest` (`POST /api/alerts` only), revocable, with an optional end date.
  - **Workspace isolation.** Every route acts in the caller's workspace: another workspace's case,
    list entry or token is a `404` like one that does not exist, and lists, stats, history diffs and
    the allow and block lists behind a verdict are filtered the same way. Admins change lists and
    delete cases; only the owner refreshes the shared feeds. Refusals carry a stable `error` code
    beside `detail`.
  - **One origin.** The server serves the console itself (`web/`, at `/`), with the page policy as
    a real header: everything from this origin, no inline script, `frame-ancestors 'none'`. Only the
    pages and `assets/` are served, never the browser test suites beside them.
  - **The console on the session.** Served by a server, the console is in server mode
    (`web/assets/data.js`): a new server opens `#/setup` for the one-time code, the console needs a
    sign-in (`#/signin`) and returns to the page that asked, the header names who is signed in with
    a Sign out button, and the workbench triages on the server into the workspace. The GitHub Pages
    demo is unchanged. A new browser suite, `web/tests/server.spec.mjs` (`make test-server`, and a
    CI job), runs it against a real new server.

- **The case workflow** (milestone M2 begins). Every case has a status (`new`, `in_progress`,
  `closed`), an assignee from its workspace, and when closed a reason and time; a signed-in member
  moves it with `PATCH /api/cases/{id}`, and each change is audited with its before and after.
  Tickets raised for a case are kept with it. `GET /api/cases` gains search (`q`, over titles and
  indicators) and filters (`status`, `source`, `assignee`, `since`, `until`). Migration 0004 makes
  every existing case `new` and unassigned.

- **Workspace settings and provider keys.** Each workspace keeps its own provider keys (sealed,
  shown only as set and their last four characters) and an on/off switch per provider, managed by
  an admin through `GET/PATCH /api/settings`, with `POST /api/settings/providers/{name}/test` making
  one harmless lookup with the key. A triage spends only its workspace's keys, and every cached
  answer belongs to the workspace that asked, so the `cached` flag reveals nothing across
  workspaces. `GET /api/workspace` tells every member which sources answer. Retention days (1 to
  365, default 30) are kept for the sweep that arrives in M3.

- **Jira and ServiceNow per workspace.** An admin sets the workspace's tracker in its settings (the
  token or password sealed, shown only as set and its last four characters); tickets raised from a
  case or a pushed alert go to that tracker with that credential, and `/api/workspace` says which
  trackers a workspace has. The client that delivers a ticket may reach that workspace's tracker host
  and no other. Tracker settings from 1.x's environment move into the first organization once.

- **Team and profile.** `/api/users`: every member sees the workspace's members (to assign cases);
  an admin adds members, changes roles, disables, resets passwords and removes accounts, under
  rules no request can lift (only the owner touches an admin's password or the owner's account,
  nobody demotes or disables themselves). A member given a password by an admin must choose their
  own at the next sign-in (the console's `#/password`). `/api/profile` changes one's own name,
  email and password (the current one required; every other session ends).
- **The audit log** gains filters (`action` prefix, `by`, `since`, `until`, `offset`) and
  `GET /api/audit/verify` for admins: whether the chain holds, and for the owner which records broke
  it.
- **The data behind every console view**, from the caller's workspace only: `GET /api/indicators`
  (each indicator once, with its latest verdict, first and last seen, its cases and the providers
  that flagged it), `/api/campaigns` (cases joined by a shared malware family or infrastructure),
  `/api/assets` (the hosts and people pushed alerts named), `/api/sources` (each provider's switch,
  key, errors, rate limits and median latency over 7 days, and the shared feeds), `/api/tickets` and
  `/api/narratives` (each case's ATT&CK techniques in tactic order, with their evidence).
  `GET /api/stats` adds each verdict band by status, a 90-day trend of cases opened and closed, and
  the mean and median time to close. A feed's status counts its rows in the database instead of
  loading them.

- **The console on a server's own data.** Signed in, every view reads the workspace's cases instead
  of the sample (`web/assets/console-server.js`): the overview (open, awaiting, closed in 90 days,
  time to close; each band by status through the same console model; cases opened per week), the
  attack surface named by pushed alerts, a searchable triage history, a triage queue with assign
  and status controls, every indicator once, the campaigns, the attack narratives, each source's
  week and the shared feeds, and the tickets with their evidence. A new workspace's views say what
  fills them. The header reads Live and the workspace's name on every view, and the assistant
  points to the views instead of quoting the sample. The demo is unchanged.

- **The workspace's panes.** In server mode a Workspace group in the sidebar opens Settings (each
  source on or off and tested, provider keys set, replaced or removed and shown only as their last
  four characters, Jira and ServiceNow, retention, allow and block lists), Team (add members with a
  first password, change roles, disable, reset a password, remove), API tokens (create with a scope
  and an expiry, shown once to copy, revoke), the Audit log (filters, and Verify the chain for an
  admin) and Profile (name, email, password). An analyst sees Audit and Profile only. Removing a
  member or revoking a token takes a second press instead of a dialog. The demo has none of them.

- **The campaign graph on a server's own campaigns.** The graph component draws any dataset now,
  not only the bundled one: on a server it draws the workspace's campaign (picked from a list when
  there are several), with the campaign as the hub, each shared family, indicator or piece of
  infrastructure as a cluster, the cases that share it as its members, and a cross-link wherever a
  case shares two. The campaign's cases are listed beneath it. The demo's graph is unchanged.

- **Sign-up** (milestone M3 begins). While the owner allows it (off by default), anyone can create
  an account and a workspace at `#/signup`: "Just me" (an individual workspace) or "My
  organization" (they are its admin). `POST /api/signup` signs them in; a new workspace sees only
  its own cases. The server takes at most 100 new workspaces a day until the owner sets another
  number, and one address signs up at most three times in 24 hours (`SIGNUP_PER_ADDRESS_DAILY`); a
  refused sign-up leaves nothing behind and costs no attempt. The owner's **Server** pane, and
  `GET/PATCH /api/server`, turn sign-up on and off and set the cap.

- **Invitations.** An organization's admin makes a one-use link for an analyst or an admin in the
  Team pane (`POST /api/invites`), good for seven days and shown once; only its SHA-256 is kept.
  Whoever opens `#/join/<token>` sees the workspace and the role, chooses their own username and
  password, and is signed in (`POST /api/join`). An unknown, used, revoked or expired link gets
  the same answer, and guessing is slowed down. Migration 0005 adds the `invites` table.
  `PUBLIC_URL`, when set, is where the links point.

- **Email, when the operator configures it** (`SMTP_HOST`, `SMTP_FROM`, `PUBLIC_URL`). A new or
  changed address gets a confirmation link whose page confirms with a button, so a mail scanner
  confirms nothing. "Forgot your password?" on the sign-in page sends a reset link to a confirmed
  address only, answering the same whether or not an account matches; the link works once, for an
  hour, and the new password ends every session of the account. Setup and sign-up then ask for an
  address. Without email nothing changes: an admin sets a member's password. Migration 0006 adds
  `email_tokens`. Delivery uses the standard library's SMTP client; a mail server that is down
  changes no answer.

- **Tier 1 sealed.** What a case was made from (the paste or uploaded file's text, a pushed alert's
  description and evidence text) is sealed with the server's key in a new `case_inputs` table,
  bound to its case, with the SHA-256 of what was sealed. Migration 0007 moves every existing row
  there and drops `cases.raw_input`. The paste is read by the analyst who made the case and by
  admins; the alert's text by the whole team. `input_deleted_at` and the reports are ready for
  the retention sweep: a report rendered after the input is gone says it was deleted, and when.

- **Retention, hold and both deletes.** Every hour (Celery beat, or `python -m app.cli sweep`) the
  input of each case older than its workspace's retention days is deleted, unless an admin holds
  the case; the verdict, the indicators and the workflow stay, the case says when its input went,
  and one audit record per workspace gives the count. An analyst deletes their own case's input
  now (`DELETE /api/cases/{id}/input`), an admin any; an admin holds and releases
  (`POST/DELETE /api/cases/{id}/hold`) and deletes a case completely, the audit keeping its ID and
  the input's SHA-256. The triage history shows each case's state with Hold, Delete input and
  Delete case controls (the deletes take a second press). Migration 0008 adds `cases.held`.
- **Triage budgets and key rotation** (milestone M3 ends). Each person and each API token runs at
  most `RATE_LIMIT_USER_TRIAGE` (30) triages a minute, and each workspace at most the owner's daily
  budget of triages and pushed alerts (500 until set in the Server pane or with
  `PATCH /api/server {"triage_daily_budget": ...}`); past either, `429` with `user_rate` or
  `workspace_budget` and `Retry-After`. `python -m app.cli rotate-key` re-seals every secret and
  every case's input under the key in `NEW_ENCRYPTION_KEY`, all or nothing, and audits it as
  `server.key_rotated` ([SECURITY.md](docs/SECURITY.md#rotating-encryption_key)).
- **`GET /healthz`** for uptime monitors (milestone M4 begins): `200` or `503` from four checks,
  the database, Redis, the Celery worker's heartbeat (a new `intelpulse.heartbeat` task beat runs
  every minute) and free disk space. It names no host, path, error or version
  ([API.md](docs/API.md#get-healthz)).

### Changed

- **The server needs `ENCRYPTION_KEY` to start** (32 random bytes, base64; or `ENCRYPTION_KEY_FILE`).
  `make keys` writes one to `.env` once, and `python -m app.cli new-key` prints one. A backup of the
  database cannot be read without the key it was made with.
- **The workbench's "Live API" box is gone**, with its API address field and the API token it kept
  in `sessionStorage`: a server serves its own console, and scripts use API tokens.
- **One port.** `docker compose up` answers on http://localhost:8000 for the console and the API;
  the separate nginx container on 8080 is gone (`web/nginx.conf` stays for hosting the static demo
  yourself). The image is built from the repository root (`Dockerfile`) and carries `web/`.
- **No Google Fonts.** Outfit and JetBrains Mono are bundled under `web/assets/fonts/` (SIL OFL
  1.1, Latin and Latin Extended), so neither the server nor the GitHub Pages demo asks a third party
  for anything when a page opens.
- **Provider keys move out of the environment.** On the first start of v2 the keys `.env` holds
  (`ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `GREYNOISE_API_KEY`, `ABUSECH_AUTH_KEY`) are sealed into the
  first organization's settings, once, and ignored after that (a warning says so if they are still
  set). `/api/health` reports keyed providers as configured only per workspace (`/api/workspace`).
- **`TICKET_ALLOW_PRIVATE_HOST` covers only hosts the operator named** (`JIRA_BASE_URL`,
  `SERVICENOW_BASE_URL`, and the new `TICKET_PRIVATE_HOSTS`), never an address a workspace admin types
  into Settings. `/api/health` no longer lists ticket sinks; they are per workspace.
- **The API needs a caller.** Without a session or a token every route but health, the scoring
  model, sign-in and setup answers `401`; there is no anonymous access any more. The 1.x `API_TOKEN`
  keeps its access to the endpoints 1.x had, in the original organization, and is deprecated (it
  goes in v3); its use is logged.

- The README opens with a five-line block for reviewers: the problem, what
  IntelPulse does, one metric, a demo GIF (`docs/screenshots/demo.gif`) and how
  to run it. The frontend design prose (the pages, the landing page, phones and
  tablets, the assistant, and how the interface is tested) moved to
  [docs/DESIGN.md](docs/DESIGN.md), and the README no longer uses dashes as
  punctuation.
- `docs/DESIGN.md` no longer uses dashes as punctuation either: each one is now
  a colon, a comma, brackets or a full stop, whichever the sentence needed, and
  the empty *Was* cell in the renamed-sections table reads *none*.
- The rest of the documentation follows: `API.md`, `SCORING.md`, `SECURITY.md`,
  `SECURITY-AUDIT.md`, `SPECIFICATION.md`, `EXTRACTION-BENCHMARK.md` and the
  design-system skill. Numeric ranges read "85 to 100", empty table cells read
  *none*, and the benchmark generator (`tests/corpus/report.py`) writes the
  same wording, so a regeneration does not bring the dashes back.

## [1.0.1] - 2026-09-24

### Security

- The console's view table is a `Map`, and only a function found in it is
  called, so no route (`#/console/constructor`, `__proto__`) can reach an
  object prototype. Routes were already checked with `hasOwnProperty`; this
  makes the table itself safe too. Resolves CodeQL alert 7.
- Tests check link hosts by parsing the URL instead of matching substrings,
  and strip markup until none is left. Resolves CodeQL alerts 1 to 6, 8 and 9.

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

[Unreleased]: https://github.com/vinitrami-Soc/intelpulse/compare/v1.0.1...HEAD
[1.0.1]: https://github.com/vinitrami-Soc/intelpulse/releases/tag/v1.0.1
[1.0.0]: https://github.com/vinitrami-Soc/intelpulse/releases/tag/v1.0.0
