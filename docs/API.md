# API reference

Base URL: `http://localhost:8000`. Interactive docs: `/docs` (Swagger) and `/redoc`.
Everything is JSON unless stated; `POST /api/triage/report?fmt=markdown` returns `text/markdown`.

---

## Signing in and API tokens

Every `/api` route needs a caller except `GET /api/health`, `GET /api/scoring/model`,
`GET`/`POST /api/session`, `POST /api/setup`, `POST /api/signup`, `POST /api/join/check`,
`POST /api/join`, and the email links' `POST /api/password/forgot`, `POST /api/password/reset` and
`POST /api/email/confirm`. Everything a caller reads or writes belongs to
their workspace; another workspace's case, list entry or token answers `404`, exactly like one that
does not exist.

**A new server.** Run `python -m app.cli setup-code` (in Docker: `docker compose exec api python -m
app.cli setup-code`). It prints a one-time code; the code is never written to the log. Then:

```bash
curl -s -c cookies.txt -X POST localhost:8000/api/setup -H 'Content-Type: application/json' -d '{
  "code": "ABCD-EFGH-JKLM-NPQR", "username": "ada", "password": "at least twelve characters",
  "organization": "Acme SOC"}'
```

That makes the owner's account, the admin of the organization that holds every case from before
the upgrade (renamed to `organization`), and signs them in. The code then stops working.

**Sign-up**, while the owner allows it (off by default), makes a new workspace and its admin, and
signs them in:

```bash
curl -s -c cookies.txt -X POST localhost:8000/api/signup -H 'Content-Type: application/json' -d '{
  "kind": "organization", "organization": "Fjord CERT", "username": "olaf",
  "display_name": "Olaf", "password": "at least twelve characters"}'
```

`kind` is `individual` ("just me": the workspace is named after the person) or `organization`
(which needs `organization`). `GET /api/session` says whether sign-up is open (`signup`). Refusals:
`403 signup_closed`, `409 not_set_up` before the setup, `422` for a bad field or a taken username
(nothing is created), and `429` when the server's daily cap of new workspaces is reached
(`signup_cap`) or one address has signed up three times in 24 hours (`SIGNUP_PER_ADDRESS_DAILY`); a
refused sign-up costs the address nothing.

**A person** signs in with `POST /api/session` (`{"username", "password"}`) and gets the cookie
`ip_session` (`HttpOnly`, `SameSite=Strict`, `Secure`) and a `csrf` token. Every `POST`, `PATCH` or
`DELETE` made with the cookie must send that token as `X-CSRF-Token`. A session ends after 8 hours
idle or 7 days, or with `DELETE /api/session`. After three failed sign-ins for a name or an address,
each attempt waits twice as long as the last. `GET /api/session` says who is signed in and whether
the server still needs setup.

**A script** sends `Authorization: Bearer ipt_...`. An admin, signed in, makes tokens:

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/tokens` | `{"name", "scope", "expires_in_days"}`; the answer carries `token`, shown this once |
| `GET` | `/api/tokens` | Name, scope, who made it, created, expires, last used, revoked |
| `DELETE` | `/api/tokens/{id}` | Revokes it at once |

| Scope | Reaches |
| --- | --- |
| `read` | Every `GET` of the workspace |
| `triage` | `read`, plus `POST /api/extract`, `/api/triage`, `/api/triage/upload` and `/api/triage/report` |
| `ingest` | `POST /api/alerts` only (DwellWatch, a SIEM) |

**The 1.x `API_TOKEN`** still works for the endpoints 1.x had, in the original organization, with
the access it had; it reaches none of the new account and token endpoints. It is deprecated, logged
on each use, and goes in v3: move scripts to API tokens.

**Roles.** An analyst triages, reads every case of the workspace and creates tickets; changing the
allow and block lists and deleting a case take an admin. Only the owner refreshes the shared feeds
or empties the provider cache. An analyst's `GET /api/audit` lists their own actions, an admin's the
whole workspace, the owner's also the server's own records (setup, feed refreshes, failed sign-ins).

The `curl` examples below leave out `-H 'Authorization: Bearer ipt_...'` to stay short.

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

Returns the live weights, authority values, thresholds and modifiers: the audit trail behind any
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
| `text` | string | *none* | Raw paste: IOC list, syslog, JSON alert export |
| `indicators` | string[] | *none* | Explicit list; unparseable entries fall back to the extractor |
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

## `POST /api/alerts`

Webhook ingestion: a SIEM or a detection pipeline pushes an alert, and IntelPulse triages it into a
case and a ticket. The alert's own account of what happened (the host, the account, the techniques,
the events behind it) opens the ticket; its indicators go through the same extraction and scoring
as a paste. [DwellWatch](https://github.com/vinitrami-Soc/dwellwatch) sends its correlated
ransomware incidents here.

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `source` | string | required | Who sent it: letters, digits, `.`, `_`, `-` |
| `alert_id` | string | required | The sender's id. With `source`, it makes a retried push the same alert |
| `title` | string | required | One line; shown on the case and the ticket |
| `severity` | string | `"medium"` | `informational`, `low`, `medium`, `high` or `critical`, as the sender judged it |
| `description` | string | `""` | Why the sender raised it (up to 4,000 characters) |
| `entities` | object[] | `[]` | `{"kind": "host", "name": "fs01"}`: what the alert is about |
| `attack_techniques` | string[] | `[]` | ATT&CK ids such as `T1490` |
| `first_seen`, `last_seen` | datetime | `null` | ISO 8601 |
| `indicators` | string[] | `[]` | Explicit indicators, defanged or not |
| `evidence` | object[] | `[]` | `{"time", "label", "text"}` per event, up to 200. Indicators are also extracted from `text` |
| `ticket` | string | `null` | `jira` or `servicenow`: also file the case there, if the workspace has it configured |

```json
{
  "case_id": "8f2c…",
  "duplicate": false,
  "alert_severity": "critical",
  "verdict": "informational",
  "score": 0,
  "indicator_count": 2,
  "ticket_level": "critical",
  "report": "/api/cases/8f2c…/report",
  "ticket": null,
  "ticket_error": null
}
```

* A new alert is `201`. The same `source` and `alert_id` again is `200` with `duplicate: true` and
  the first case: nothing is triaged twice, so a sender's retries cost no vendor quota. Two pushes of
  one alert at the same moment make one case; the other gets `409` and can retry.
* An alert with no enrichable indicator is still a case: the detection is what the SOC needs to see.
* `ticket_level` is the level the ticket is filed at, the higher of the threat-intelligence verdict
  and the sender's severity. A critical detection whose indicators no source has seen is a P1, and
  its ticket's summary and containment actions follow the alert (confirm the activity, isolate the
  hosts, reset the accounts, hunt the techniques) rather than calling it informational. The JSON
  ticket lists those actions as `alert_containment`.
* A tracker that is not configured, or that refuses the issue, does not lose the case: the answer is
  still `201`, with the reason in `ticket_error`.
* Pushes share the `triage` rate-limit bucket. A sender needs an `ingest` token (or the 1.x `API_TOKEN`).

```bash
curl -s -X POST localhost:8000/api/alerts -H 'Content-Type: application/json' -d '{
  "source": "dwellwatch", "alert_id": "dw-3f9a1c", "severity": "critical",
  "title": "DwellWatch: CRITICAL incident on host fs01",
  "entities": [{"kind": "host", "name": "fs01"}], "attack_techniques": ["T1490", "T1486"],
  "evidence": [{"time": "2026-09-20T14:30:41Z", "label": "stage 5: shadow copies deleted",
                "text": "vssadmin delete shadows /all /quiet"}]
}'
```

---

## Cases

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/cases?limit=25&offset=0&verdict=high` | Newest first; search and filters below |
| `GET` | `/api/cases/{id}` | Full stored result including every provider payload, `alert` for a pushed alert, and the workflow: `status`, `assignee`, `closed_reason`, `closed_at`, `tickets` |
| `PATCH` | `/api/cases/{id}` | Move a case along (a signed-in member); see below |
| `GET` | `/api/cases/{id}/report?fmt=markdown\|json` | Regenerates the ticket from stored evidence |
| `DELETE` | `/api/cases/{id}` | Delete completely (admin): the case, its indicators and its input. The audit record keeps the case ID and the input's SHA-256 |
| `DELETE` | `/api/cases/{id}/input` | Delete the input now (tier 1): the analyst who made the case, or an admin; a signed-in member. The verdict, indicators and workflow stay. `409 held` while the case is held |
| `POST`, `DELETE` | `/api/cases/{id}/hold` | Hold, and release (an admin, signed in): a held case keeps its input past the retention days |
| `GET` | `/api/stats?days=90` | The overview: counts by verdict, each band by status, cases opened and closed per day, time to close; see below |
| `GET` | `/api/audit?limit=50` | The hash-chained trail of triages, list changes, sign-ins and tokens; filters: `action` (a prefix, so `case.` is every case action), `by` (who acted), `since`, `until`, `offset` |
| `GET` | `/api/audit/verify` | An admin: recompute the chain. `intact`, `records`, `problems`; the owner also gets which records broke it, since the chain is the whole server's |

### Search and filters

`GET /api/cases` takes, all optional and combined with AND:

| Parameter | Matches |
| --- | --- |
| `q` | Words in the title, or part of any indicator in the case (case-insensitive; `%` and `_` are plain characters) |
| `status` | `new`, `in_progress`, `closed`, or `open` (new or in progress) |
| `verdict`, `source` | Exactly |
| `assignee` | `me`, `none`, or a member's id |
| `since`, `until` | Created at or after, and before (ISO 8601) |

**What a case was made from** (tier 1, spec 6.3) is kept sealed apart from the case: the paste or the
uploaded file's text, and a pushed alert's description and evidence text. `GET /api/cases/{id}`
returns the paste as `raw_input` to the analyst who made the case and to an admin (and to API tokens
and the 1.x `API_TOKEN`, which read what they could before); any other member gets `null` and the
rest of the case. A pushed alert's description and evidence are shown to every member, since the
team works the case from them. Once the input is deleted, `input_deleted_at` says when, and the
report says it was deleted under the retention policy instead of quoting the evidence.

**Retention.** Every hour (the Celery beat job `retention-hourly`, or `python -m app.cli sweep`
from cron) the input of every case older than its workspace's retention days (Settings, 30 by
default) is deleted unless the case is held, the case is marked `input_deleted_at`, and one
`retention.swept` audit record per workspace gives the count. Holding, releasing and deleting are
audited (`case.held`, `case.released`, `case.input_deleted` with the input's SHA-256).

Each row also carries `held`, `input_deleted_at`, `created_by` (a member's id), `status`, `assignee` (`id`, `username`, `display_name` or `null`),
`closed_reason`, `closed_at` and `ticket_count`; a 1.x client reads the fields it always did.

### The case workflow

A case starts `new`, is worked `in_progress` and is `closed` with a reason. Send only what changes:

```bash
curl -s -X PATCH localhost:8000/api/cases/$CASE -b cookies.txt -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' -d '{"status": "closed", "closed_reason": "false_positive"}'
```

* `status`: `new`, `in_progress` or `closed`. Closing needs `closed_reason` (`true_positive`,
  `false_positive`, `benign`, `duplicate`) and stamps `closed_at`; reopening clears both.
* `assignee_id`: a member of the case's workspace who can still sign in, or `null` to unassign.
* Any member, analyst or admin, may move a case; API tokens and the 1.x `API_TOKEN` may not.
  Every change is audited as `case.updated` with what each field was and became.
* A ticket raised for the case (`POST /api/cases/{id}/ticket`, or `ticket` on a pushed alert) is
  kept with it and listed under `tickets`.

## The console's views

What each console view draws (spec 9.2), read from the caller's workspace only. Any caller that
reads reaches them: a session of any role, an API token with the `read` or `triage` scope, and the
1.x `API_TOKEN` (in the default organization). Each view scans a bounded window, newest first, and
says so with `truncated` when there was more.

| Method | Path | Returns |
| --- | --- | --- |
| `GET` | `/api/stats?days=90` | The 1.x fields, plus `bands` (each verdict, most severe first, with its `new`, `in_progress` and `closed` counts), `by_status`, `open`, `unassigned_open`, `assigned_to_me_open` (a session; `null` for a token), `distinct_indicators`, `pushed_alerts`, `tickets`, `trend` (one `{date, opened, closed}` per UTC day, oldest first) and `time_to_close` (`cases`, `mean_seconds`, `median_seconds` over the cases closed in the window) |
| `GET` | `/api/indicators` | Each indicator once: its latest `verdict`, `score` and `confidence`, `first_seen`, `last_seen`, how many `cases` name it, `latest_case_id`, `malware_families`, and `flagged_by` (the providers whose last answer leaned malicious: a signal of 0.5 or more). Filters `q` (part of the value), `type`, `verdict` (the latest); `sort` is `last_seen` (default), `score` or `cases`; `limit` (up to 200), `offset` |
| `GET` | `/api/campaigns?days=90` | Cases joined when they share a malware family or infrastructure: an indicator, or a relation's target (an ASN, IP, domain, URL or hash; never a country). Only an indicator scored `low` or above joins cases. Each campaign has `label` (its most shared family, else its most shared link), `verdict`, `score`, `first_seen`, `last_seen`, `cases` and `links` (what is shared, by which cases). The newest 500 cases are considered |
| `GET` | `/api/assets` | The hosts and people pushed alerts named (`kind`: `host` for host, hostname, device and the like; `user` for user, account and the like; any other kind as sent), each with `alerts`, `cases`, `case_ids`, `open_cases`, the highest `verdict` and `score`, `first_seen`, `last_seen`. Filters `kind`, `q`; `limit` (up to 500). The newest 2,000 alerts are considered; empty until an integration pushes alerts |
| `GET` | `/api/sources?days=7` | Each provider: `enabled`, `needs_key`, `key_set` (`null` when it needs none), `ready`, and over the window `queries`, `answered`, `errors`, `rate_limited`, `skipped`, `median_latency_ms` (cached answers left out) and `last_error`. Also `feeds`: the shared offline feeds and their last refresh |
| `GET` | `/api/tickets` | Every Jira or ServiceNow ticket raised for a case, newest first: `sink`, `key`, `url`, `created_at`, `created_by`, the `case`, and its `report` downloads. Filter `sink`; `limit`, `offset` |
| `GET` | `/api/narratives?days=90` | Each recent case's ATT&CK techniques grouped by tactic, in the order an intrusion runs (reconnaissance first, impact last). A technique carries `evidence` (the indicators behind it, with the providers that `named_by` it, or `inferred` from tags and families) and `from_alert` when a pushed alert named it. Cases with no technique are left out; the newest 200 cases are considered, `limit` up to 100 |

## Team and profile

| Method | Path | Who | Notes |
| --- | --- | --- | --- |
| `GET` | `/api/users` | any member, signed in | The workspace's members (an analyst needs them to assign a case); an admin also sees email, last sign-in and `must_change_password` |
| `POST` | `/api/users` | admin, signed in | `{"username", "display_name", "role", "password"}`: the member must choose their own password at the first sign-in |
| `PATCH` | `/api/users/{id}` | admin, signed in | `display_name`, `role`, `disabled`, `password` (a reset: their sessions end and they choose a new one at the next sign-in) |
| `DELETE` | `/api/users/{id}` | admin, signed in | The account goes; their cases and audit records stay, unattributed |
| `GET` | `/api/profile` | the person | Their own account and workspace |
| `PATCH` | `/api/profile` | the person | `display_name`, `email`, and `current_password` with `new_password`, which ends every other session |

**Invitations** (an organization's admin, signed in; an individual workspace takes none):

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/invites` | `{"role": "analyst"}` or `"admin"`: a one-use link, good for 7 days. The answer carries `token` and `link` (`#/join/<token>`, on `PUBLIC_URL` when it is set) once; only the token's SHA-256 is kept |
| `GET` | `/api/invites` | Newest first, with `state` (`open`, `used`, `expired`), who made it and who used it; never a token |
| `DELETE` | `/api/invites/{id}` | Revoke an open invitation (`409` once it is used: remove the member instead) |
| `POST` | `/api/join/check` | Anyone with the link: `{"token"}` answers the workspace's name and the role |
| `POST` | `/api/join` | `{"token", "username", "display_name", "password"}` makes the account in that workspace and role and signs it in; the link then stops working |

An unknown, used, revoked or expired link gets the same `404`, and three of them from one address
slow the next attempts down like failed sign-ins. The token travels in the body, never in a URL a log
would keep. Making, revoking and using an invitation are audited (`invite.created`,
`invite.revoked`, `invite.used`).

Rules that hold whatever the request says: only the owner sets an admin's password or changes the
owner's account; nobody changes their own role, disables or removes themselves; the owner's account
cannot be removed or demoted. While an admin-set password stands, the session reaches only
`/api/profile` and sign-out (`403`, `"error": "password_change_required"` elsewhere), and the
console opens `#/password`.

## Email (optional)

With `SMTP_HOST`, `SMTP_FROM` and `PUBLIC_URL` set (and `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`,
`SMTP_TLS` = `starttls`, `ssl` or `none` as the mail server needs), `GET /api/session` says
`"email": true`, setup and sign-up ask for an address, and:

| Method | Path | Notes |
| --- | --- | --- |
| `POST` | `/api/email/confirm` | `{"token"}` from the link mailed when an address is given or changed. The link opens `#/confirm/<token>`, whose button sends this: a mail scanner that follows links confirms nothing. A link made for an address that has since changed confirms nothing |
| `POST` | `/api/profile/email/confirm` | A signed-in member: mail the confirmation again (three in an hour) |
| `POST` | `/api/password/forgot` | `{"login"}`, a username or an address: `202` with the same answer whether or not an account matches. A link goes only to a confirmed address, at most three an hour per account, and five requests an hour per caller address |
| `POST` | `/api/password/reset` | `{"token", "password"}`: the link works once, for one hour; every session of the account ends. A password too short keeps the link working |

A used, expired or unknown link is `404` with the same words, and wrong links from one address are
slowed down. Only each link's SHA-256 is stored. Without email the forgot route answers
`409 email_off`, and an admin sets a member's password (the owner sets an admin's).

## Server settings

The server's own settings are the owner's alone (a signed-in owner; no API token, and not the 1.x
`API_TOKEN`). They hold nothing of any workspace's cases.

| Method | Path | Notes |
| --- | --- | --- |
| `GET` | `/api/server` | `signup`, `signup_daily_cap` (100 until changed), `signups_today` (new workspaces in the last 24 hours), and how many `workspaces` and `users` the server holds |
| `PATCH` | `/api/server` | `{"signup": true, "signup_daily_cap": 20}`; send only what changes. Audited as `server.updated` |

## Workspace settings

Each workspace keeps its own provider keys and switches (spec 7), sealed, and its lookups spend
only those keys: a cached answer belongs to the workspace that asked for it, so another workspace
neither reads it nor learns from `cached` that someone looked. Scoring weights stay server
configuration, so a verdict means the same thing everywhere.

| Method | Path | Who | Notes |
| --- | --- | --- | --- |
| `GET` | `/api/workspace` | any caller | Name, kind, retention days, and each provider's `enabled` and `ready` (no key material) |
| `GET` | `/api/settings` | admin, signed in | Providers with their switch and key slot; each key slot's `set` and `hint` (the last four characters) |
| `PATCH` | `/api/settings` | admin, signed in | `{"providers": {"threatfox": {"enabled": false}}, "keys": {"otx": "..."}, "retention_days": 30, "tickets": {...}}`; a key of `""` removes it |
| `POST` | `/api/settings/providers/{name}/test` | admin, signed in | One lookup of a harmless indicator (8.8.8.8, example.com, the EICAR hash) with the workspace's key, past the cache |

**Trackers.** Each workspace raises tickets in its own Jira or ServiceNow:

```json
{"tickets": {"jira": {"base_url": "https://acme.atlassian.net", "email": "soc@acme.example",
                      "project_key": "SOC", "issue_type": "Task", "api_token": "..."},
             "servicenow": {"base_url": "https://acme.service-now.com", "user": "svc_intelpulse",
                            "table": "incident", "password": "..."}}}
```

A tracker address is `https://host[/path]` with no credentials, query or fragment; a table is a plain
name; the token and password are sealed and shown only as set and their last four characters. `GET
/api/workspace` lists the trackers a workspace can deliver to as `ticket_sinks` (and `/api/health`
no longer does). The client that delivers a ticket may reach that workspace's tracker host and no
other; see `docs/SECURITY.md` for private hosts.

Key slots: `abuseipdb`, `otx`, `greynoise`, and `abusech` (ThreatFox and URLhaus share it). A key is
1 to 512 printable characters without spaces, since it travels in a request header. Every change is
audited as `settings.updated` saying a key was set, replaced or removed, never its value. Keys left in
the environment by 1.x move into the first organization once, on the first start of v2
(`settings.keys_imported`).

## Allow / block lists

```bash
curl -s -X POST localhost:8000/api/lists -H 'Content-Type: application/json' \
  -d '{"value":"203.0.113.9","ioc_type":"ip","list_type":"allow","reason":"our egress NAT"}'
```

An allowlist entry forces a score of 0 and the verdict `allowlisted`; a blocklist entry forces ≥ 90.
Both record the reason, which is printed in the report's modifier list. Local knowledge beats vendor
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

## Rate limits

Every response carries `X-RateLimit-Limit` and `X-RateLimit-Remaining`. Buckets are per client
address and sized by what the endpoint costs:

| Bucket | Default | Endpoints |
| --- | --- | --- |
| `triage` | 30/min | `/api/triage*`, `/api/alerts`, `/api/intel/feeds*`, which spend vendor quota |
| `write` | 60/min | other `POST` / `DELETE`, including `/api/extract` |
| `read` | 240/min | `GET`, so dashboard health polling is never starved by a triage burst |

Exceeding a bucket returns `429` with `Retry-After`. `X-Forwarded-For` is ignored unless
`TRUST_FORWARDED_FOR=true` (see [SECURITY.md](SECURITY.md)).

## Security headers

Every response carries `Content-Security-Policy` (`default-src 'none'` on API routes), `X-Frame-Options:
DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy`,
`Permissions-Policy`, and an `X-Request-ID` that also appears in the JSON logs. HSTS is added when
`ENVIRONMENT=production`.

## Errors

Refusals from sign-in, roles and tokens carry a stable code beside the sentence:
`{"error": "csrf", "detail": "missing or wrong X-CSRF-Token: ..."}`. `detail` is a sentence as before.

| Status | Meaning |
| --- | --- |
| `401` | No session and no valid token (`error`: `unauthorized`), or a wrong password |
| `403` | Beyond the caller's role or token scope (`forbidden`), a missing CSRF token (`csrf`), a wrong setup code, or a browser write from an origin not in `CORS_ORIGINS` |
| `422` | No usable indicators, neither `text` nor `indicators` supplied, or input over `MAX_INPUT_CHARS` |
| `413` | Body over `MAX_REQUEST_BYTES` (1 MiB) or upload over `MAX_UPLOAD_BYTES` (5 MiB) |
| `429` | Rate limit exceeded; honour `Retry-After` |
| `404` | Unknown case, list entry, token, feed or CVE, or one that belongs to another workspace |
| `409` | List entry already exists, the same alert is being pushed by another request at that moment, or the server is set up already |

Provider-level failures are **not** request failures: they appear as `status: "error"` on that source
with the reason, and the remaining sources still produce a scored verdict.
