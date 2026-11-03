# Security review, November 2026 (IntelPulse 2.0)

This is the review round milestone M4 asks for, done before release 2.0.0. It covers what v2 added
to the [September audit](SECURITY-AUDIT.md)'s scope: accounts and sessions, workspaces and roles,
sign-up, invitations and email, sealed case inputs and retention, the audit chain, the triage
budgets, the public pages, and the way a server ships (the deploy kit, behind a Cloudflare Tunnel).

As in September, every finding was reproduced against the code as it stood, fixed, and pinned by a
test that fails on the old code. What was left alone, and why, is under
[Residual risk](#residual-risk).

## Summary

Ten findings: one rated high by CodeQL (low in practice), seven medium, and two low. All ten are
fixed. Two more bugs found while shipping were availability problems, not security ones; they are
listed [below the findings](#found-while-shipping).

| # | Finding | Severity | Fixed in | Top 10:2025 | ASVS 5.0 |
| --- | --- | --- | --- | --- | --- |
| R1 | A trusted `X-Forwarded-For` was read from its first entry, which the client chooses | Medium | this round | A07 | V4 |
| R2 | A new address for the reset link needed no password | Medium | this round | A07 | V6 |
| R3 | `/docs` and `/redoc` loaded CDN scripts onto the server's origin in production | Medium | this round | A08 | V3 |
| R4 | `/api/health` told anyone the database's error text | Low | this round | A02 | V16 |
| R5 | The tunnel's token reached the app, worker and beat | Low | this round | A02 | V13 |
| R6 | The limiter forgot daily counts after a quiet minute | Medium | #40 | A07 | V2 |
| R7 | The workbench kept a server's cases in the browser after sign-out | Medium | #42 | A01 | V14 |
| R8 | Behind Cloudflare, the client named its own address | Medium | #43 | A07 | V4 |
| R9 | A browser write through the tunnel looked cross-origin | Medium (it broke every write) | #43 | A01 | V3 |
| R10 | The smoke test printed the owner's password | High (CodeQL); low in practice | #43 | A09 | V16 |

R9 failed closed, refusing writes rather than allowing them, so it was an outage waiting for the
first deployment, not an exposure. It is listed because its fix widens what the origin guard
accepts, and a widened guard needs review.

## Findings

### R1: the first `X-Forwarded-For` entry is the client's to choose (Medium)

With `TRUST_FORWARDED_FOR=true`, `client_ip()` took the header's first entry. nginx
(`$proxy_add_x_forwarded_for`), Traefik and Cloudflare all *append* the address they saw to
whatever header the client sent. So the first entry was always a value the client wrote, and every
request could claim a fresh address. That bypassed the per-address rate limits, the sign-up limit
and the address half of the sign-in throttle.

**Fix.** The last entry is the client: it is the one the trusted proxy in front of the app appended.
Behind a chain of proxies that puts every client behind the outermost one; `CLIENT_IP_HEADER`
(R8) is the answer there. `tests/test_review_2026_11.py` sends forged first entries and checks
they share one bucket.

### R2: a stolen session could keep the account (Medium)

Changing the password asked for the current one; changing the email address did not. A session
left open on a shared machine, or stolen, could set the account's address to a mailbox the
attacker controls, confirm it through the link sent there, and then reset the password. That
turns eight hours of someone else's session into the account for good.

**Fix.** A new address needs the current password, like a new password does. Wrong guesses slow
down exactly as at sign-in: three free, then 1 s, 2 s, 4 s and onward up to 5 minutes, keyed by
the username. The Profile pane asks for the password when the address changes, and only then.
Tests cover the refusal, a wrong password, the throttle, and changes that need no password; the
server browser suite covers the form.

### R3: a third party's script on the server's origin (Medium)

FastAPI's `/docs` and `/redoc` load Swagger UI and ReDoc from a CDN, and the security headers
relax the CSP for those two paths so they can. On a server, that origin also holds the signed-in
admin's session: a script served there can read `/api/session` for the CSRF token and act as the
admin. A compromised or hijacked CDN package would have been enough.

**Fix.** The two pages are off when `ENVIRONMENT=production`, which the deploy kit sets, unless
`API_DOCS=true` asks for them. `/openapi.json` stays, since it is data, not script.

### R4: the health check described the database's failure (Low)

`GET /api/health` is open to anyone. When the database failed, it answered
`"database": "postgresql (error: <the exception>)"`, which names the host, the port and the user.
It now says `error`, and the exception goes to the log. `/healthz` was written this way from the
start.

### R5: the tunnel token where it is not needed (Low)

`setup.sh` wrote `CLOUDFLARE_TUNNEL_TOKEN` into `deploy/.env`, which the app, the worker and beat
all read as their environment. Code execution in any of the three would have yielded the token,
which can run the tunnel, and so the hostname, from anywhere. The token now goes to
`deploy/tunnel.env` (mode 600, kept out of git), which only `cloudflared` reads.

### R6: daily limits that reset after a quiet minute (Medium, fixed in #40)

The in-process limiter swept away every key whose newest hit was older than *the caller's* window,
which was the middleware's 60 seconds. So the three sign-ups a day per address, the five reset
requests an hour, and (in the same PR) the workspace's daily triage budget all started again after a
minute without activity. Each key now keeps its own window, and a test checks a daily key survives
the minute sweep.

### R7: a server's cases left in the browser (Medium, fixed in #42)

On a server, the workbench still wrote its last 25 cases (titles, verdicts) and every indicator it
had triaged to `localStorage`, as the demo does. That outlived signing out, and the next person on
the browser saw it. On a server it now keeps none: the history comes from `GET /api/cases`, and
opening the workbench deletes what an older version left. Found while writing the privacy page,
which now says what the browser keeps.

### R8: the client's own word for its address, behind Cloudflare (Medium, fixed in #43)

Cloudflare appends to `X-Forwarded-For`, so the deploy kit could not use it safely (R1 is the
general case). `CLIENT_IP_HEADER=CF-Connecting-IP` reads the one header Cloudflare alone sets.
The kit publishes the app on `127.0.0.1` only, so nothing but the tunnel can reach the app to forge
that header either.

### R9: writes through the tunnel (Medium, fixed in #43)

Behind the tunnel, the app sees `http://` while the browser is on `https://`, so the origin guard
saw every browser write as cross-origin and refused it. The fix adds the origin of `PUBLIC_URL` to
the origins the guard accepts. It is compared exactly (scheme, host and port), so `http://` on the
same host and lookalike hosts are still refused (`tests/test_behind_a_proxy.py`).

### R10: a password in the smoke test's output (CodeQL high, fixed in #43)

CodeQL flagged clear-text logging of sensitive data. Given a setup code, `deploy/smoke.py` made the
owner with a password it chose and printed it, so that the operator could keep it. That meant
terminal scrollback and CI logs. It now takes the password from `SMOKE_PASSWORD` and prints none.
The risk was small, since it applied only to a server the smoke test itself set up, but the alert
was right.

## Found while shipping

Two bugs found by running the deploy kit on Postgres, fixed in #43. Neither was a security
problem, but both would have broken the first real deployment:

- **Sign-up returned 500 on every new Postgres server.** The default organization is inserted as
  workspace 1, which does not advance Postgres's id sequence. Migration 0009 moves every sequence
  past its table's highest id.
- **The worker and beat crashed on a fresh install.** kombu 5.7 moved `packaging` under its `redis`
  extra. `requirements.txt` pins `celery[redis]`.

## What was checked and holds

- **Passwords:** argon2id, at least 12 characters. Unknown usernames are hashed too, so timing does
  not tell which exist.
- **Sessions:**
  - 256 random bits per session, stored only as SHA-256.
  - A new session at every sign-in. Sessions expire after 8 hours idle or 7 days absolute, and end
    on a password change, a reset, a disable or a removal.
  - The role and the account's state are read again on every request, so a demotion takes effect at
    once.
- **The cookie:** `HttpOnly`, `Secure` and `SameSite=Strict`. A cross-site request carries no
  session, which is why the GitHub Pages origin in `CORS_ORIGINS` reaches nothing on a server.
- **CSRF:** a token per session, compared in constant time on every session write, sign-out
  included.
- **The owner:** cannot be removed or made an analyst, and nobody else sets the owner's password.
  Only the owner sets another admin's password. The last active admin cannot be demoted or
  disabled.
- **One-time values:**
  - The setup code, and reset, invitation and confirmation tokens, are stored hashed, work once and
    expire. Wrong guesses are throttled.
  - The links carry their tokens after the `#`, so a token never reaches a server log or a
    `Referer`.
  - A forgotten-password request answers the same whether or not the account exists.
- **Workspaces:** every route that takes an ID is called from another workspace and answers 404.
  The role matrix calls every route as each role and token scope. The provider cache is per
  workspace for keyed answers.
- **Sealing:** AES-256-GCM with a fresh nonce per value and the row's place as associated data.
  `rotate-key` re-seals everything or nothing, and refuses the current key as the new one.
- **The audit chain:** `audit verify` catches an edited, removed or reordered record.
- **Background jobs:** Celery accepts JSON only, so no pickled payload is ever deserialized. Redis
  and Postgres publish no port in the kit.
- **Email:** an address must match a pattern without whitespace, so no header can be injected
  through it. The messages come from fixed templates.
- **Dependencies:** `pip-audit -r requirements.txt` reported nothing on 3 November 2026. CodeQL
  (Python, JavaScript, Actions) is clean on `main`.

## Residual risk

- **The limiter is per process.** With `uvicorn --workers 4`, each worker counts on its own. The
  kit runs one process; a multi-replica deployment needs a shared store behind the same interface.
- **The audit chain has no secret.** Someone who can write to the database can rewrite records and
  recompute every hash after them. The chain proves the log was not edited by anyone without that
  access. To extend that past database administrators, record the output of `audit verify` (or the
  head hash) somewhere they cannot write.
- **Usernames can be discovered.** Sign-up and join say when a name is taken. Usernames are not
  secrets: teammates see them. Sign-in is throttled per name and per address, and the passwords
  are argon2id.
- **The sign-up cap can be passed by a few.** It is checked and then written, so simultaneous
  sign-ups at the edge of the cap can each pass. The per-address limit still holds.
- **API tokens outlive the person who made them.** That is deliberate, so a script does not stop
  when its author leaves. The tokens list shows each token and its last use; admins revoke what is
  no longer theirs.
- **The session cookie has no `__Host-` prefix.** The prefix would stop a sibling subdomain from
  planting a cookie of the same name. It needs `Secure`, which `COOKIE_SECURE=false` (allowed for
  LAN testing) turns off. Worth doing in a release that can sign everyone out.
- **The page CSP allows inline styles** (`style-src 'unsafe-inline'`), as in September; no inline
  script is allowed.
- **Failed sign-ins are audited.** Each writes a record, throttled per username and per address. A
  flood from many addresses grows the log.
- **Backups are only partly sealed.** Case inputs and credentials in a dump are sealed; accounts,
  password hashes, verdicts, indicators and the audit log are not. DEPLOY.md says to guard dumps as
  you would the database.
- **The tunnel is not in CI.** It needs a Cloudflare account. `deploy/smoke.py` runs the same
  checks against the tunnel's address, and it is the first thing to run after setting one up.

## Method

1. Read every router and platform module that v2 added or changed, looking for the classes above:
   who may call what, what an attacker controls, and where a value is trusted.
2. Ran the deploy kit on Docker against Postgres, end to end:
   - setup, then the smoke test;
   - an update over a broken database;
   - a restore of a pre-migration dump;
   - a key rotation.

   The kit runs the same way in CI on every pull request.
3. Ran `pip-audit` on the pinned requirements, and read the CodeQL results on every pull request
   of the round.
4. Wrote a test for each finding before fixing it: `tests/test_review_2026_11.py` (R1 to R5),
   `tests/test_limits.py` (R6), the server browser suite (R2, R7), `tests/test_behind_a_proxy.py`
   (R8, R9) and `tests/test_deploy_kit.py`.
