# Deploying IntelPulse

This is the runbook for one public IntelPulse server: a small Linux machine (an Oracle Cloud Always
Free Ampere machine is enough), the app on Postgres and Redis, and a
[Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/)
that brings visitors in. The machine publishes no web port; only SSH is open. Everything for it is
in [`deploy/`](../deploy). Running the server once it is up (accounts, email, settings) is
[SERVER.md](SERVER.md).

| File | What it does |
| --- | --- |
| `deploy/compose.yml` | Postgres 16, Redis 7, the app, its Celery worker and beat, and `cloudflared` |
| `deploy/setup.sh` | the first start: writes `deploy/.env`, builds, starts, prints the setup code |
| `deploy/smoke.py` | signs a new account up, triages a sample alert and checks the verdict, against any address |
| `deploy/backup.sh` | a Postgres dump into `deploy/backups/`, keeping the newest 14 |
| `deploy/restore.sh` | a dump back into the database |
| `deploy/update.sh` | backs up, moves the code to a branch, tag or commit, rebuilds, restarts, verifies the audit log |
| `.github/workflows/deploy.yml` | runs `update.sh` from GitHub, over SSH, for every published release |

CI runs this kit on every pull request, on x86 and on ARM64: `setup.sh` on a fresh runner, the smoke
test, a backup and a restore, then `update.sh` in place.

The examples use `intel.example.org`; use your own name.

- [1. A server](#1-a-server)
- [2. A Cloudflare Tunnel](#2-a-cloudflare-tunnel)
- [3. Mail](#3-mail)
- [4. First start](#4-first-start)
- [5. Check it](#5-check-it)
- [6. Deploys from GitHub](#6-deploys-from-github)
- [7. Backups and restore](#7-backups-and-restore)
- [8. Updates by hand](#8-updates-by-hand)
- [Cloudflare settings and search engines](#cloudflare-settings-and-search-engines)
- [Rotating `ENCRYPTION_KEY`](#rotating-encryption_key)
- [Day to day](#day-to-day)
- [Troubleshooting](#troubleshooting)

## 1. A server

Any Linux machine with 2 GB of memory, 20 GB of disk and Docker will do: a small VPS, a spare box,
or an Oracle Cloud Always Free Ampere machine. The image builds on ARM64 as on x86: every Python
dependency ships an ARM64 wheel, Postgres, Redis and `cloudflared` publish ARM64 images, and CI runs
the whole kit on ARM64 on every pull request.

### On Oracle Cloud (Always Free)

In the Oracle Cloud console, open **Compute**, then **Instances**, then **Create instance**:

| Field | Value |
| --- | --- |
| Image | **Canonical Ubuntu 24.04** (with the Ampere shape, Oracle picks its aarch64 build) |
| Shape | **VM.Standard.A1.Flex** (Ampere, ARM64): 1 OCPU and 6 GB is enough, 2 OCPUs and 12 GB leave room |
| Networking | a public subnet (the default VCN's is one) and a public IPv4 address |
| SSH keys | your own public key |

- If it says the shape is **out of capacity**, try another availability domain, or again later.
- Leave the subnet's security list as Oracle makes it: SSH (port 22) in, nothing else. The tunnel
  connects out, so no web port is opened, there or on the machine. For deploys from GitHub
  ([step 6](#6-deploys-from-github)) SSH must stay open to any address, since GitHub's runners have
  no fixed one; the deploy key can run `update.sh` and nothing else.
- Oracle's Ubuntu images keep their own `iptables` firewall (SSH only, in `/etc/iptables/rules.v4`).
  **Do not turn on `ufw` there**: Oracle advises against it, and it can lock SSH out. If it happens,
  the instance's **Console connection** gets you back in to run `ufw disable`.
- Oracle may reclaim an Always Free instance it finds idle for 7 days (CPU, network and, on Ampere,
  memory all under its threshold), and a quiet server can look idle. Upgrading the account to
  **Pay As You Go** stops that, and the Always Free resources stay free on it. Set a budget alert
  (**Billing**, then **Budgets**) at a small amount, to be told if anything ever costs.

Log in as `ubuntu`, Oracle's user on its Ubuntu images, and become root with `sudo -i`.

### Then, on Ubuntu 24.04

As root:

```bash
curl -fsSL https://get.docker.com | sh
adduser --disabled-password --gecos "" intelpulse
usermod -aG docker intelpulse          # docker is root on this machine: keep this user's key safe
install -d -o intelpulse -m 700 /home/intelpulse/.ssh
cp /home/ubuntu/.ssh/authorized_keys /home/intelpulse/.ssh/ && chown intelpulse: /home/intelpulse/.ssh/authorized_keys
# bound Docker's logs: five files of 20 MB a container
printf '{"log-driver": "json-file", "log-opts": {"max-size": "20m", "max-file": "5"}}\n' > /etc/docker/daemon.json
systemctl restart docker
```

Copy the key from `ubuntu`, not from root: on cloud images, root's `authorized_keys` only tells you
to log in as `ubuntu`. On a machine where you log in as root, copy `~/.ssh/authorized_keys` instead,
and if it has no firewall of its own (it is not Oracle's), add one:
`ufw allow OpenSSH && ufw --force enable`.

Keep automatic security updates on (`unattended-upgrades` is on by default on Ubuntu) and log in
with SSH keys only.

## 2. A Cloudflare Tunnel

The domain's DNS must be on Cloudflare (the free plan is enough). In the Cloudflare dashboard, open
**Zero Trust**, then **Networks**, then **Tunnels**, and create a tunnel of type **Cloudflared**.
Name it (for example `intelpulse`) and copy its token: the long value after `--token` in the install
command it shows. Skip that command; the kit runs `cloudflared` itself.

Then add a **public hostname** to the tunnel:

| Field | Value |
| --- | --- |
| Subdomain and domain | the address people will use, for example `intel.example.org` |
| Service type | `HTTP` |
| URL | `app:8000` |

`app` is the app's name on the kit's Docker network. Cloudflare creates the DNS record and the
certificate, serves the address over HTTPS and names the real client in `CF-Connecting-IP`, which
the app is told to trust (nothing but the tunnel can reach the app to forge it), so the sign-in and
sign-up throttles slow down each visitor, not the tunnel. Then, under the domain's **SSL/TLS**, then
**Edge Certificates**, turn on **Always Use HTTPS**.

Keep that DNS record **Proxied** (the orange cloud), also when you change other records in bulk.
Set to DNS only, the name points at an address that answers nothing: the tunnel stays healthy, yet
every visitor and uptime check gets a connection timeout.

Cloudflare's own guide:
[create a remotely managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-remote-tunnel/).
If the server is for one team only, you can also put
[Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/) in front of the
hostname, so only your team's email addresses reach the sign-in page at all. The dashboard settings
that change pages are under [Cloudflare settings](#cloudflare-settings-and-search-engines).

## 3. Mail

For password reset links and email confirmation, IntelPulse sends mail through an SMTP provider
(Brevo, Resend, Amazon SES, Zoho ZeptoMail; Cloudflare Email Routing receives mail but does not send
it). Add the sender domain at the provider and the SPF and DKIM records it gives you in Cloudflare's
DNS. After the first start, put its server, login and key in `deploy/.env` (`SMTP_HOST`,
`SMTP_PORT`, `SMTP_TLS`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`; see
[SERVER.md](SERVER.md#email-optional)) and apply them with
`docker compose -f deploy/compose.yml up -d`. Without mail, everything else works, and an admin sets
passwords.

## 4. First start

As the `intelpulse` user on the server (`sudo -iu intelpulse`, or SSH in as it):

```bash
git clone https://github.com/vinitrami-Soc/intelpulse.git ~/intelpulse
cd ~/intelpulse
git checkout "$(git describe --tags --abbrev=0)"   # the newest release; or stay on main
./deploy/setup.sh
```

`setup.sh` asks for the address (`https://intel.example.org`) and the tunnel token (press Enter for
none). It writes `deploy/.env` with a fresh `ENCRYPTION_KEY` and database password, and the token
to `deploy/tunnel.env`, which only `cloudflared` reads; both are readable by you alone. It builds the
image (a few minutes the first time), starts everything, waits for the server, and prints:

```
IntelPulse is running. To make the owner's account, open
    https://intel.example.org/#/setup
and enter this one-time code:
    XXXX-XXXX-XXXX-XXXX
```

Open that address and enter the code: the account it makes is the server's **owner**. The code
works once. To print it again before anyone has used it:
`docker compose -f deploy/compose.yml exec app python -m app.cli setup-code`.

**Keep a copy of `deploy/.env` (and `deploy/tunnel.env`) in a password manager.** Every case's
input and every stored credential is sealed with its `ENCRYPTION_KEY`; without the key no backup can
be read, by you or anyone else, and nothing can recover it. Running `setup.sh` again is safe: it
never replaces what `deploy/.env` already holds.

Without a terminal (provisioning scripts), it reads `PUBLIC_URL` and `CLOUDFLARE_TUNNEL_TOKEN` from
the environment instead of asking.

## 5. Check it

```bash
read -rs SMOKE_PASSWORD && export SMOKE_PASSWORD        # the owner's password, kept out of the history
python3 deploy/smoke.py https://intel.example.org --owner <owner's username>
```

The smoke test checks `/healthz` (and waits for the worker's first heartbeat on a server that has
just started), signs in as the owner, opens sign-up for a moment, signs a new individual account
up, triages a sample alert as it, checks the verdict and the stored case, and closes sign-up again if
it was closed. It leaves the `smoke-...` account and its one case behind. Every line says `PASS` or
`FAIL`, and the exit status says the same.

For monitoring, point an uptime checker at `https://intel.example.org/healthz`: `200` when the
database, Redis, the worker's heartbeat and the disk are all well, `503` otherwise
([API.md](API.md#get-healthz)).

## 6. Deploys from GitHub

Make a key for GitHub on your own computer:

```bash
ssh-keygen -t ed25519 -N "" -C github-deploy -f intelpulse-deploy
ssh-keyscan -t ed25519 <server address>      # the server's key, for DEPLOY_KNOWN_HOSTS
```

On the server, add one line to `/home/intelpulse/.ssh/authorized_keys`, with the contents of
`intelpulse-deploy.pub` at the end. It lets the key run `update.sh` and nothing else, even if the
key leaks:

```
command="bash ~/intelpulse/deploy/update.sh \"$SSH_ORIGINAL_COMMAND\"",restrict ssh-ed25519 AAAA... github-deploy
```

In the repository on GitHub, **Settings**, then **Secrets and variables**, then **Actions**:

| Kind | Name | Value |
| --- | --- | --- |
| Secret | `DEPLOY_SSH_KEY` | the contents of `intelpulse-deploy` (the private key) |
| Variable | `DEPLOY_HOST` | the server's address |
| Variable | `DEPLOY_USER` | `intelpulse` |
| Variable | `DEPLOY_KNOWN_HOSTS` | the `ssh-keyscan` line |
| Variable | `DEPLOY_URL` | `https://intel.example.org` |

Then delete `intelpulse-deploy` from your computer. From now on:

- **publishing a release** deploys its tag;
- **Actions**, then **Deploy**, then **Run workflow** deploys any branch, tag or commit: an older
  tag rolls the code back.

Each deploy backs up first, rebuilds, waits for the server and verifies the audit log, then asks
`DEPLOY_URL/healthz` through Cloudflare, as a visitor would. Under **Settings**, then
**Environments**, then **production**, you can require your own approval before each deploy runs.
Until `DEPLOY_HOST` is set, the workflow does nothing.

## 7. Backups and restore

Back up every night, as the `intelpulse` user (`crontab -e`):

```
17 3 * * *  ~/intelpulse/deploy/backup.sh >> ~/backup.log 2>&1
```

Each run writes `deploy/backups/intelpulse-<UTC time>.dump` and keeps the newest 14
(`BACKUP_KEEP` sets another number, `BACKUP_DIR` another folder). Copy the folder off the server
too (`rclone` to Oracle Object Storage or Cloudflare R2, or `scp` to your computer): a backup on the
same disk does not survive the server.

**Keep `ENCRYPTION_KEY` apart from the dumps.** Every case's input and every stored credential in a
dump is sealed with it: a dump without the key cannot be read, by you or by anyone who takes it. The
rest of a dump is not sealed: accounts and their password hashes, verdicts, indicators and the
audit log. Guard the dumps as you would the database.

To restore one:

```bash
deploy/restore.sh deploy/backups/intelpulse-20261103T031700Z.dump
```

It asks before replacing the database (set `RESTORE_YES=yes` to skip the question), stops the app,
worker and beat, restores the dump in one transaction, and starts them again. `deploy/.env` must
hold the `ENCRYPTION_KEY` the dump was made with. To move to a new machine: run `setup.sh` there,
put the old `deploy/.env` in place of the new one (before the first start, or followed by
`docker compose -f deploy/compose.yml up -d`), and restore the newest dump.

## 8. Updates by hand

```bash
deploy/update.sh             # the newest commit of the branch you are on
deploy/update.sh v2.1.0      # a release tag, or a branch (main), or a commit
```

It refuses to run over local changes, backs up, fetches the code, pulls the database's, Redis's and
the tunnel's images, rebuilds on a fresh base image (their security fixes), restarts, waits for the
server and verifies the audit log. New migrations run when the app starts. A checkout on a release
has no branch to follow, so name the next version. To go back, run it with the previous tag and
restore the dump the update made, since a migration may have changed the schema. The
[changelog](../CHANGELOG.md) says what each release changes.

Dependabot opens monthly pull requests for the Python, Docker (the tunnel, and Postgres and Redis
within their major versions) and Actions dependencies; once one is merged, a release (or
**Run workflow**) puts it on the server.

## Cloudflare settings and search engines

IntelPulse's content security policy lets the page run its own scripts only. For this hostname, keep
**Rocket Loader**, **Email Address Obfuscation** and the **Web Analytics** script (its automatic
setup) turned off: they add scripts to the page, and the policy blocks them. Leave **Bot Fight Mode**
off if scripts push alerts or read cases with an API token: it challenges clients that are not
browsers, and on the free plan no rule can exempt `/api/`.

Search engines may read the product, about, help, privacy and terms pages once
`INTELPULSE_INDEX_PUBLIC_PAGES=true` and `PUBLIC_URL` are in `deploy/.env` (then
`docker compose -f deploy/compose.yml up -d`). Check:

```bash
curl -s https://intel.example.org/robots.txt      # ends with the Sitemap line
curl -s https://intel.example.org/sitemap.xml     # the public pages
```

Then add the site to Google Search Console (a Domain property, verified with a TXT record in
Cloudflare's DNS) and Bing Webmaster Tools, submit `/sitemap.xml` to both, and leave verified bots
(Googlebot, Bingbot) unchallenged.

To keep AI training crawlers out, open **Security**, then **Settings**, then **Configure AI bot
policies**, keep **Search** on Allow and set **Training** to **Disallow**, not Block. Block (and
Block on pages with ads) also stops crawlers that index for search and training alike, Googlebot,
Bingbot and Applebot among them: Search Console then reports the sitemap as a 403.

## Rotating `ENCRYPTION_KEY`

Back up first. Then, with the database running and everything else stopped:

```bash
c="docker compose -f deploy/compose.yml"
$c stop app worker beat
new="$($c run --rm --no-deps app python -m app.cli new-key)"
$c run --rm --no-deps -e NEW_ENCRYPTION_KEY="$new" app python -m app.cli rotate-key
```

`rotate-key` re-seals every value under the new key, all or nothing. When it says it is done, put
the new key in `ENCRYPTION_KEY` in `deploy/.env`, run `$c up -d`, and keep the old key as long as
you keep dumps made with it ([SECURITY.md](SECURITY.md#rotating-encryption_key)).

## Day to day

```bash
cd ~/intelpulse
docker compose -f deploy/compose.yml ps                 # what runs, and its health
docker compose -f deploy/compose.yml logs -f app        # the app (worker and beat by their names)
deploy/update.sh v2.1.0                                 # deploy by hand
```

## Troubleshooting

| What you see | What to do |
| --- | --- |
| `setup: Docker is installed but not running` | `sudo systemctl start docker`, or add your user to the `docker` group and log in again |
| The address answers `502` or Cloudflare's error page | `docker compose -f deploy/compose.yml logs tunnel`: the token is wrong, or the public hostname's URL is not `app:8000` |
| Visitors and uptime checks time out, yet the tunnel is healthy | the DNS record is set to DNS only: make it **Proxied** |
| The page loads without its styles or scripts on the public address only | Rocket Loader, Email Address Obfuscation or the Web Analytics script is on for the hostname ([Cloudflare settings](#cloudflare-settings-and-search-engines)) |
| `/healthz` is `503` with `beat` failing | `docker compose -f deploy/compose.yml logs worker beat`: both must be running for the retention sweep and the feed refreshes |
| Signing in works on `127.0.0.1` but not on the public address | `PUBLIC_URL` in `deploy/.env` must be exactly the address in the browser, with `https://` |
| Oracle says the Ampere shape is out of capacity | another availability domain, or again later |
| SSH stopped answering on Oracle after `ufw` was turned on | the instance's **Console connection**, then `ufw disable` |
| The Deploy workflow says `Permission denied (publickey)` or `Host key verification failed` | the `authorized_keys` line must be one line with the public key at its end; `DEPLOY_KNOWN_HOSTS` must be this server's `ssh-keyscan` line |
| Everything | `docker compose -f deploy/compose.yml ps` shows each container's state; `logs <name>` shows why |

The kit's containers run read-only, with every Linux capability dropped and no way to gain
privileges; the app writes only to its data volume and `/tmp`. The development compose file at the
repository root (`docker-compose.yml`) is the quick local trial; this kit is the one for a server.
