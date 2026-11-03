# Deploying IntelPulse

This guide takes a clean Linux machine to a running IntelPulse server, reachable at your own address
through a Cloudflare Tunnel, with nightly backups and one-command updates. Everything it uses is in
[`deploy/`](../deploy). For running a server once it is up (accounts, email, settings), see
[SERVER.md](SERVER.md).

| File | What it does |
| --- | --- |
| `deploy/compose.yml` | Postgres 16, Redis 7, the app, its Celery worker and beat, and `cloudflared` |
| `deploy/setup.sh` | the first start: writes `deploy/.env`, builds, starts, prints the setup code |
| `deploy/smoke.py` | signs a new account up, triages a sample alert and checks the verdict, against any address |
| `deploy/backup.sh` | a Postgres dump into `deploy/backups/`, keeping the newest 14 |
| `deploy/restore.sh` | a dump back into the database |
| `deploy/update.sh` | backs up, fetches the code, rebuilds and restarts |

CI runs this kit on every pull request: `setup.sh` on a fresh runner, the smoke test, then a backup
and a restore.

## What you need

- A Linux machine with 2 GB of memory and 10 GB of disk (a small VPS or a spare box).
- Docker Engine with the Compose plugin: `docker compose version` prints a version.
- `git`, `curl` and `python3` (the smoke test uses only the standard library).
- For a public address: a domain on Cloudflare (the free plan is enough). Without one, the server
  answers on the machine itself only (`http://127.0.0.1:8000`).

The machine needs no open inbound port. The tunnel makes an outbound connection to Cloudflare,
and the app listens on `127.0.0.1` only.

## 1. Make the tunnel

In the Cloudflare dashboard, open **Zero Trust**, then **Networks**, then **Tunnels**, and create a
tunnel of type **Cloudflared**. Name it (for example `intelpulse`) and copy its token: the long
value after `--token` in the install command it shows. You do not need to run that command; the
kit runs `cloudflared` itself.

Then add a **public hostname** to the tunnel:

| Field | Value |
| --- | --- |
| Subdomain and domain | the address people will use, for example `intel.example.org` |
| Service type | `HTTP` |
| URL | `app:8000` |

`app` is the app's name on the kit's Docker network. Cloudflare serves the address over HTTPS and
names the real client in `CF-Connecting-IP`, which the app is told to trust (and nothing but the
tunnel can reach the app to forge it). Cloudflare's own guide:
[create a remotely managed tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-remote-tunnel/).

If the server is for one team only, you can also put
[Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/) in front of the
hostname, so only your team's email addresses reach the sign-in page at all.

## 2. Set it up

```bash
sudo mkdir -p /srv && cd /srv
git clone https://github.com/vinitrami-Soc/intelpulse
cd intelpulse
git checkout v2.0.0            # or stay on main
./deploy/setup.sh
```

`setup.sh` asks for the address (`https://intel.example.org`) and the tunnel token (press Enter for
none). It writes `deploy/.env` with a fresh `ENCRYPTION_KEY` and database password, readable by you
alone; builds the image; starts everything; waits for the server; and prints:

```
IntelPulse is running. To make the owner's account, open
    https://intel.example.org/#/setup
and enter this one-time code:
    XXXX-XXXX-XXXX-XXXX
```

Open that address and enter the code: the account it makes is the server's **owner**. The code
works once. To print it again before anyone has used it:
`docker compose -f deploy/compose.yml exec app python -m app.cli setup-code`.

Running `setup.sh` again is safe: it never replaces what `deploy/.env` already holds. A new
`ENCRYPTION_KEY` would make every sealed value unreadable, so the script will not write one over
another.

Without a terminal (provisioning scripts), it reads `PUBLIC_URL` and `CLOUDFLARE_TUNNEL_TOKEN` from
the environment instead of asking.

## 3. Check it

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

## 4. Back up

```bash
crontab -e
# a dump at 03:17 every night
17 3 * * *  /srv/intelpulse/deploy/backup.sh >> /var/log/intelpulse-backup.log 2>&1
```

Each run writes `deploy/backups/intelpulse-<UTC time>.dump` and keeps the newest 14
(`BACKUP_KEEP` sets another number, `BACKUP_DIR` another folder). Copy the folder off the machine
too, with whatever you already use (restic, rclone, a provider's snapshots).

**Keep `ENCRYPTION_KEY` apart from the dumps.** Every case's input and every stored credential in a
dump is sealed with it: a dump without the key cannot be read, by you or by anyone who takes it, and
the key cannot be recovered. Keep a copy of `deploy/.env` in a password manager, not beside the
backups.

## 5. Restore

```bash
deploy/restore.sh deploy/backups/intelpulse-20261103T031700Z.dump
```

It asks before replacing the database (set `RESTORE_YES=yes` to skip the question), stops the app,
worker and beat, restores the dump in one transaction, and starts them again. `deploy/.env` must
hold the `ENCRYPTION_KEY` the dump was made with. To move to a new machine: run `setup.sh` there,
put the old `deploy/.env` in place of the new one (before the first start, or followed by
`docker compose -f deploy/compose.yml up -d`), and restore the newest dump.

## 6. Update

```bash
deploy/update.sh             # the newest commit of the branch you are on
deploy/update.sh v2.0.1      # a release tag
```

It backs up first, refuses to run over local changes, fetches the code, rebuilds the image and
restarts. New migrations run when the app starts. To go back, check out the previous tag, run
`update.sh` again, and restore the dump the update made, since a migration may have changed the
schema. The [changelog](../CHANGELOG.md) says what each release changes.

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

## Troubleshooting

| What you see | What to do |
| --- | --- |
| `setup: Docker is installed but not running` | `sudo systemctl start docker`, or add your user to the `docker` group and log in again |
| The address answers `502` or Cloudflare's error page | `docker compose -f deploy/compose.yml logs tunnel`: the token is wrong, or the public hostname's URL is not `app:8000` |
| `/healthz` is `503` with `beat` failing | `docker compose -f deploy/compose.yml logs worker beat`: both must be running for the retention sweep and the feed refreshes |
| Signing in works on `127.0.0.1` but not on the public address | `PUBLIC_URL` in `deploy/.env` must be exactly the address in the browser, with `https://` |
| Everything | `docker compose -f deploy/compose.yml ps` shows each container's state; `logs <name>` shows why |

The kit's containers run read-only, with every Linux capability dropped and no way to gain
privileges; the app writes only to its data volume and `/tmp`. The development compose file at the
repository root (`docker-compose.yml`) is the quick local trial; this kit is the one for a server.
