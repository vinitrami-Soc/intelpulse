#!/usr/bin/env bash
# A dump from backup.sh back into the database (docs/DEPLOY.md):
#
#   deploy/restore.sh deploy/backups/intelpulse-20261103T031700Z.dump
#
# Replaces everything in the database with the dump. The app, worker and beat are stopped while
# it runs and started again after. The dump's sealed values open only with the ENCRYPTION_KEY
# they were sealed with: deploy/.env must hold that key (the one in use when the dump was made).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose -f "$here/compose.yml")
dump="${1:-}"
[ -n "$dump" ] && [ -s "$dump" ] || { echo "usage: deploy/restore.sh <file.dump from backup.sh>" >&2; exit 1; }

if [ -t 0 ] && [ "${RESTORE_YES:-}" != "yes" ]; then
  read -r -p "Replace everything in the database with $dump? Type yes: " answer
  [ "$answer" = "yes" ] || { echo "restore: nothing changed"; exit 1; }
fi

"${compose[@]}" stop app worker beat
# --clean drops what the dump recreates; --single-transaction makes it all or nothing.
"${compose[@]}" exec -T db pg_restore -U intelpulse -d intelpulse --clean --if-exists --no-owner \
  --single-transaction < "$dump"
"${compose[@]}" start app worker beat
echo "restore: $dump is back; the app starts on it now"
