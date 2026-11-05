#!/usr/bin/env bash
# Move an IntelPulse server to a version of the code (docs/DEPLOY.md):
#
#   deploy/update.sh            the branch this checkout follows, at its newest commit
#   deploy/update.sh v2.1.0     a release tag, or any branch (main) or commit
#
# Backs the database up first, fetches the code, pulls the database's, Redis's and the tunnel's
# images and rebuilds on a fresh base image (their security fixes), restarts, waits for the server
# and verifies the audit log. The app applies any new migration when it starts. The GitHub "Deploy"
# workflow runs this over SSH with the version it was given. To go back: run it with the previous
# tag, and restore the dump this run made (deploy/restore.sh), since a migration may have changed
# the schema.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(dirname "$here")"
compose=(docker compose -f "$here/compose.yml")
target="${1:-}"

# what arrives over SSH is the caller's to choose: a ref name, never an option or a command
case "$target" in
  "") ;;
  -* | *[!A-Za-z0-9._/-]*) echo "update: not a branch, tag or commit: $target" >&2; exit 2 ;;
esac

[ -f "$here/.env" ] || { echo "update: no deploy/.env here; run deploy/setup.sh first" >&2; exit 1; }

git=(git -C "$root" -c advice.detachedHead=false)
in_git=""
if "${git[@]}" rev-parse --git-dir >/dev/null 2>&1; then
  in_git=yes
  if [ -n "$("${git[@]}" status --porcelain --untracked-files=no)" ]; then
    echo "update: this checkout has local changes; commit or stash them first" >&2
    exit 1
  fi
  if [ -z "$target" ] && ! "${git[@]}" symbolic-ref --quiet HEAD >/dev/null; then
    echo "update: this checkout is on a release, not a branch: name the version (deploy/update.sh v2.1.0, or main)" >&2
    exit 1
  fi
fi

echo "update: backing up first"
"$here/backup.sh"

if [ -n "$in_git" ]; then
  before="$("${git[@]}" rev-parse --short HEAD)"
  if [ -n "$target" ]; then
    "${git[@]}" fetch --tags --quiet origin
    # a branch moves to its newest commit on GitHub; a tag or a commit is taken as it is
    if "${git[@]}" rev-parse --verify --quiet "origin/$target^{commit}" >/dev/null; then
      "${git[@]}" checkout --quiet --detach "origin/$target"
    else
      "${git[@]}" checkout --quiet --detach "$target^{commit}"
    fi
  else
    "${git[@]}" pull --ff-only --quiet
  fi
  echo "update: code $before -> $("${git[@]}" log -1 --format='%h %s')"
else
  echo "update: not a git checkout; rebuilding the code as it is"
fi

(cd "$root" && "${compose[@]}" pull --quiet --ignore-buildable)
(cd "$root" && "${compose[@]}" build --pull)
(cd "$root" && "${compose[@]}" up -d)

port="$(sed -n 's/^APP_PORT=//p' "$here/.env" | tail -1)"
port="${port:-8000}"
up=""
for _ in $(seq 1 90); do
  if curl -fsS -o /dev/null "http://127.0.0.1:$port/api/health" 2>/dev/null; then up=yes; break; fi
  sleep 2
done
[ -n "$up" ] || { echo "update: the server did not come back; see: ${compose[*]} logs app" >&2; exit 1; }

"${compose[@]}" exec -T app python -m app.cli audit verify
echo "update: running. Health: $(curl -sS "http://127.0.0.1:$port/healthz" || true)"
