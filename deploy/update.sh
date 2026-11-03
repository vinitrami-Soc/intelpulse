#!/usr/bin/env bash
# Move an IntelPulse server to the newest code (docs/DEPLOY.md):
#
#   deploy/update.sh            the branch this checkout follows
#   deploy/update.sh v2.0.1     a release tag
#
# Backs the database up first, fetches the code, rebuilds the image and restarts. The app applies
# any new migration when it starts. To go back: check out the previous tag, run this again, and
# restore the dump this run made (deploy/restore.sh), since a migration may have changed the schema.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
compose=(docker compose -f "$here/compose.yml")
target="${1:-}"

[ -f "$here/.env" ] || { echo "update: no deploy/.env here; run deploy/setup.sh first" >&2; exit 1; }

echo "update: backing up first"
"$here/backup.sh"

if git -C "$root" rev-parse --git-dir >/dev/null 2>&1; then
  if [ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]; then
    echo "update: this checkout has local changes; commit or stash them first" >&2
    exit 1
  fi
  before="$(git -C "$root" rev-parse --short HEAD)"
  if [ -n "$target" ]; then
    git -C "$root" fetch --tags --quiet origin
    git -C "$root" -c advice.detachedHead=false checkout --quiet "$target"
  else
    git -C "$root" pull --ff-only --quiet
  fi
  echo "update: code $before -> $(git -C "$root" rev-parse --short HEAD)"
else
  echo "update: not a git checkout; rebuilding the code as it is"
fi

(cd "$root" && "${compose[@]}" up -d --build)

port="$(sed -n 's/^APP_PORT=//p' "$here/.env" | tail -1)"
port="${port:-8000}"
for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$port/api/health" 2>/dev/null; then
    echo "update: running. Health: $(curl -sS "http://127.0.0.1:$port/healthz" || true)"
    exit 0
  fi
  sleep 2
done
echo "update: the server did not come back; see: ${compose[*]} logs app" >&2
exit 1
