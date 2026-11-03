#!/usr/bin/env bash
# The first start of an IntelPulse server (docs/DEPLOY.md).
#
#   deploy/setup.sh
#
# Asks for the address people will use and, optionally, a Cloudflare Tunnel token, then writes
# deploy/.env with fresh secrets, builds the image, starts everything and prints the one-time code
# that makes the first account, the owner's. Run it again at any time: it never replaces a secret
# that deploy/.env already holds (a new ENCRYPTION_KEY would make every sealed value unreadable).
#
# Without a terminal (a script, CI), it reads PUBLIC_URL and CLOUDFLARE_TUNNEL_TOKEN from the
# environment instead of asking.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
env_file="$here/.env"
compose=(docker compose -f "$here/compose.yml")

say() { printf '%s\n' "$*"; }
fail() { printf 'setup: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || fail "Docker is not installed: https://docs.docker.com/engine/install/"
docker compose version >/dev/null 2>&1 || fail "the Docker Compose plugin is missing (docker compose version)"
docker info >/dev/null 2>&1 || fail "Docker is installed but not running, or this user may not use it"

random_b64() {   # 32 random bytes, base64: what ENCRYPTION_KEY expects
  if command -v openssl >/dev/null; then openssl rand -base64 32
  else head -c 32 /dev/urandom | base64 | tr -d '\n'; echo; fi
}
random_hex() {   # for the database password, which sits inside a URL: no character needs escaping
  if command -v openssl >/dev/null; then openssl rand -hex 24
  else head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; echo; fi
}
ask() {   # ask "question" default: the answer, or the default without a terminal
  local answer=""
  if [ -t 0 ]; then read -r -p "$1 [$2]: " answer || true; fi
  printf '%s' "${answer:-$2}"
}

if [ -f "$env_file" ]; then
  say "deploy/.env exists: keeping its secrets and settings."
else
  public_url="${PUBLIC_URL:-$(ask "Address people will open (https://intel.example.org)" "http://localhost:8000")}"
  public_url="${public_url%/}"
  case "$public_url" in http://*|https://*) ;; *) fail "the address must start with https:// (or http:// for localhost)";; esac
  token="${CLOUDFLARE_TUNNEL_TOKEN-}"
  if [ -z "$token" ] && [ -t 0 ]; then
    read -r -s -p "Cloudflare Tunnel token (Enter for none: the server is then reachable on this machine only): " token || true
    echo
  fi
  umask 077
  {
    echo "# Written by deploy/setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ). Keep a copy of ENCRYPTION_KEY"
    echo "# apart from your backups: a backup cannot be read without it, and nothing can recover it."
    echo "ENCRYPTION_KEY=$(random_b64)"
    echo "POSTGRES_PASSWORD=$(random_hex)"
    echo "PUBLIC_URL=$public_url"
    echo "# no shared 1.x token: scripts use API tokens made in the console"
    echo "API_TOKEN="
    if [ -n "$token" ]; then
      echo "CLOUDFLARE_TUNNEL_TOKEN=$token"
      echo "COMPOSE_PROFILES=tunnel"
      echo "# Cloudflare names the client in CF-Connecting-IP; the app is published on 127.0.0.1 only"
      echo "TRUST_FORWARDED_FOR=true"
      echo "CLIENT_IP_HEADER=CF-Connecting-IP"
    else
      echo "TRUST_FORWARDED_FOR=false"
    fi
    echo "INTELPULSE_INDEX_PUBLIC_PAGES=false"
  } > "$env_file"
  chmod 600 "$env_file"
  say "Wrote deploy/.env (readable by you alone)."
fi

port="$(sed -n 's/^APP_PORT=//p' "$env_file" | tail -1)"
port="${port:-8000}"
public_url="$(sed -n 's/^PUBLIC_URL=//p' "$env_file" | tail -1)"

say "Building and starting IntelPulse (the first build takes a few minutes)..."
(cd "$root" && "${compose[@]}" up -d --build)

say "Waiting for the server to answer on 127.0.0.1:$port ..."
for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$port/api/health" 2>/dev/null; then break; fi
  sleep 2
done
curl -fsS -o /dev/null "http://127.0.0.1:$port/api/health" ||
  fail "the server did not come up: ${compose[*]} logs app"
health="$(curl -sS "http://127.0.0.1:$port/healthz" || true)"
say "Health: $health"

code="$("${compose[@]}" exec -T app python -m app.cli setup-code 2>/dev/null | tail -1 || true)"
say ""
if [ -n "$code" ]; then
  say "IntelPulse is running. To make the owner's account, open"
  say "    $public_url/#/setup"
  say "and enter this one-time code:"
  say "    $code"
else
  say "IntelPulse is running and set up already: the owner signs in at $public_url/#/signin"
fi
say ""
say "Next: put deploy/backup.sh in cron (docs/DEPLOY.md), and keep ENCRYPTION_KEY from deploy/.env"
say "somewhere safe that is not where the backups go."
