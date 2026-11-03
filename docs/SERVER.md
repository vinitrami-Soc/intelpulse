# Running an IntelPulse server

What the owner of a server and the admins of its workspaces look after, once it is up. Getting it up
is [DEPLOY.md](DEPLOY.md); what the server keeps and for how long is the
[privacy page](../web/privacy.html), served at `/privacy.html`.

## Who is who

| Role | Who | Can |
| --- | --- | --- |
| **Owner** | the first account, made with the setup code | everything an admin can in the first organization, plus the **Server** pane: sign-up, its daily cap, each workspace's triage budget |
| **Admin** | of one workspace | Settings (provider keys, Jira and ServiceNow, retention, allow and block lists), Team (members, roles, invitations, passwords), API tokens, the whole audit log, holding and deleting cases |
| **Analyst** | of one workspace | triage, work cases, see their own audit records, delete the input of their own cases |

A workspace is an organization (a team) or an individual (one person). Nobody, the owner included,
reads another workspace's cases: the Server pane shows counts, never content.

## People

- **Sign-up** is off until the owner turns it on in the Server pane. While it is on, anyone who can
  open the server makes an account and a workspace of their own, at most the daily cap a day for
  the whole server (100 until changed) and 3 a day from one address.
- **Invitations** add someone to an existing workspace: an admin makes a link in Team, as an
  analyst or an admin. It works once, within 7 days, and can be revoked.
- **Passwords** are at least 12 characters. An admin can set a member's password; the member then
  chooses their own at the next sign-in. With email set up, people reset their own.
- **Sign-in** slows down after wrong passwords, for the username and for the address.

## Email (optional)

With these set in `deploy/.env`, the server confirms email addresses and sends password reset
links. Without them, it sends nothing and an admin sets passwords.

| Setting | Example |
| --- | --- |
| `SMTP_HOST` | `smtp.example.org` |
| `SMTP_PORT` | `587` |
| `SMTP_TLS` | `starttls` (or `ssl` for port 465; `none` only on a trusted local relay) |
| `SMTP_USER`, `SMTP_PASSWORD` | the mailbox's login |
| `SMTP_FROM` | `IntelPulse <intel@example.org>` |
| `PUBLIC_URL` | `https://intel.example.org`, which the links in the messages point to |

After changing `deploy/.env`, apply it with `docker compose -f deploy/compose.yml up -d`.

## Providers and trackers

Each workspace's admins set its own provider keys (AbuseIPDB, AlienVault OTX, GreyNoise, the
abuse.ch key for ThreatFox and URLhaus) and its Jira or ServiceNow credentials in Settings. They are
sealed with `ENCRYPTION_KEY` and shown only by their last four characters. Keys still in the
environment from IntelPulse 1.x are moved into the first organization's settings once, at the first
start of 2.0, and ignored after that.

The offline datasets (Feodo Tracker, FireHOL, the ThreatFox dump, CISA KEV, NVD) are the server's,
shared by every workspace, and refreshed by the worker on beat's schedule.

## Limits

| Limit | Default | Set with |
| --- | --- | --- |
| Triages a minute, per person or API token | 30 | `RATE_LIMIT_USER_TRIAGE` |
| Triages and pushed alerts a day, per workspace | 500 | the Server pane |
| Requests a minute, per address: triage, write, read | 30, 60, 240 | `RATE_LIMIT_TRIAGE`, `RATE_LIMIT_WRITE`, `RATE_LIMIT_READ` |
| New workspaces a day, whole server | 100 | the Server pane |
| Sign-ups a day, per address | 3 | `SIGNUP_PER_ADDRESS_DAILY` |

## Retention

Each workspace keeps what a case was made from for its retention days (30 unless an admin sets 1 to
365); every hour the worker deletes what is older, unless an admin holds the case. The verdict,
indicators and workflow stay. Without the worker, run `python -m app.cli sweep` from cron instead.

## The audit log

Every sign-in, setting change, triage, deletion and server change is recorded in a hash chain. In
the console, admins press **Verify chain** in Audit. From the terminal:

```bash
docker compose -f deploy/compose.yml exec app python -m app.cli audit verify
```

It prints `the audit log is intact`, or exits `1` and lists each record that was edited, removed or reordered.

## API tokens

Scripts use API tokens, made by an admin in API tokens: `read` (every GET), `triage` (read, plus
extract and triage) or `ingest` (only `POST /api/alerts`). A token belongs to its workspace and is
shown once. The shared `API_TOKEN` of IntelPulse 1.x still works for the first organization, and
goes in 3.0; `setup.sh` leaves it empty.

## Monitoring and logs

- `GET /healthz`: `200` or `503`, from the database, Redis, the worker's heartbeat and free disk
  ([API.md](API.md#get-healthz)).
- `docker compose -f deploy/compose.yml logs -f app`: one JSON line per request (method, path,
  status, time taken, client address) with API keys masked. Docker keeps the logs; set its log
  rotation (`/etc/docker/daemon.json`, `"log-opts": {"max-size": "20m", "max-file": "5"}`) to bound
  them.

## Configuration

Set in `deploy/.env` (which `setup.sh` writes) and applied with `docker compose ... up -d`.
`.env.example` at the repository root lists the rest with comments.

| Setting | Default | What it is |
| --- | --- | --- |
| `ENCRYPTION_KEY` | none: the server will not start | 32 random bytes in base64; seals case inputs and credentials (`ENCRYPTION_KEY_FILE` reads it from a file) |
| `PUBLIC_URL` | empty | the address people use; links in invitations and email, the sitemap, and the origin the app accepts writes from behind the tunnel |
| `DATABASE_URL`, `REDIS_URL` | set by the kit | Postgres and Redis |
| `TRUST_FORWARDED_FOR`, `CLIENT_IP_HEADER` | `true`, `CF-Connecting-IP` with the tunnel | where the client's address comes from |
| `COOKIE_SECURE` | `true` | the session cookie needs HTTPS (or `localhost`) |
| `CORS_ORIGINS` | the local development addresses and the public demo | other origins whose pages may call the API |
| `INTELPULSE_INDEX_PUBLIC_PAGES` | `false` | let search engines read the product, privacy and help pages |
| `HEALTHZ_BEAT_MAX_AGE_SECONDS`, `HEALTHZ_MIN_FREE_PERCENT` | `300`, `5` | when `/healthz` fails |
| `CACHE_TTL_SECONDS` | `86400` | how long a provider's answer is reused |
| `LOG_LEVEL`, `JSON_LOGS` | `INFO`, `true` | logging |
