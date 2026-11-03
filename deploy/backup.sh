#!/usr/bin/env bash
# A dump of the IntelPulse database (docs/DEPLOY.md), for cron:
#
#   17 3 * * *  /srv/intelpulse/deploy/backup.sh >> /var/log/intelpulse-backup.log 2>&1
#
# Writes deploy/backups/intelpulse-<UTC time>.dump (pg_dump's custom format, which restore.sh
# reads) and keeps the newest BACKUP_KEEP of them (14 unless set). The dump holds every case's
# input sealed: it cannot be read without the ENCRYPTION_KEY in deploy/.env, so keep that key
# somewhere else, and never only beside the dumps.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
compose=(docker compose -f "$here/compose.yml")
dir="${BACKUP_DIR:-$here/backups}"
keep="${BACKUP_KEEP:-14}"
case "$keep" in ''|*[!0-9]*) echo "backup: BACKUP_KEEP must be a whole number" >&2; exit 1;; esac

umask 077
mkdir -p "$dir"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
file="$dir/intelpulse-$stamp.dump"
partial="$file.partial"

# Written under another name first, so a dump cut short never looks like a good one.
"${compose[@]}" exec -T db pg_dump -U intelpulse -d intelpulse --format=custom --no-owner > "$partial"
[ -s "$partial" ] || { rm -f "$partial"; echo "backup: pg_dump wrote nothing" >&2; exit 1; }
mv "$partial" "$file"
echo "backup: $file ($(wc -c < "$file") bytes)"

# The newest $keep stay; older dumps go.
ls -1t "$dir"/intelpulse-*.dump 2>/dev/null | tail -n +"$((keep + 1))" | while read -r old; do
  rm -f -- "$old" && echo "backup: removed $old"
done
