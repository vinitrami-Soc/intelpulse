"""Command line entry points: feed imports, one-shot triage, seeding.

    python -m app.cli feeds --all
    python -m app.cli triage 185.220.101.34 --report
    python -m app.cli seed          # demo rows so the UI is not empty
    python -m app.cli refresh-tlds  # update the hostname allowlist from IANA
    python -m app.cli audit verify  # exit 1 if any audit record was changed
    python -m app.cli new-key       # a fresh ENCRYPTION_KEY
    python -m app.cli setup-code    # the one-time code that makes the first account (the owner)
    python -m app.cli rotate-key    # re-seal everything under NEW_ENCRYPTION_KEY
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .db import init_db, session_scope
from .ioc import extract
from .models import DEFAULT_WORKSPACE_ID
from .platform import accounts, audit
from .platform.box import server_box
from .platform.crypto import new_key
from .reporting import to_markdown
from .services import feeds
from .services.triage import persist_case, triage
from .tlds import CACHE_PATH, IANA_URL, SNAPSHOT, parse_iana


async def _feeds(args: argparse.Namespace) -> None:
    await init_db()
    jobs = []
    if args.all or args.feodo:
        jobs.append(("feodo-tracker", feeds.refresh_feodo()))
    if args.all or args.threatfox:
        jobs.append(("threatfox-dump", feeds.refresh_threatfox_dump()))
    if args.all or args.firehol:
        jobs.append(("firehol-level1", feeds.refresh_firehol()))
    if args.all or args.kev:
        jobs.append(("cisa-kev", feeds.refresh_kev()))
    if args.all or args.nvd:
        jobs.append(("nvd", feeds.refresh_nvd(days=args.days)))
    if not jobs:
        print("nothing to do — pass --all or a specific feed flag")
        return
    for name, coro in jobs:
        rows = await coro
        print(f"{name}: {rows} rows")


async def _triage(args: argparse.Namespace) -> None:
    await init_db()
    text = " ".join(args.indicators)
    indicators = extract(text)
    if not indicators:
        print("no indicators found", file=sys.stderr)
        raise SystemExit(2)
    outcome = await triage(indicators, workspace_id=DEFAULT_WORKSPACE_ID, title=args.title)
    if args.persist:
        async with session_scope() as session:
            await persist_case(session, outcome, workspace_id=DEFAULT_WORKSPACE_ID, raw_input=text, source="cli")
    if args.report:
        print(
            to_markdown(
                outcome.case_id,
                outcome.title,
                outcome.verdicts,
                outcome.verdict,
                outcome.score,
                duration_ms=outcome.duration_ms,
            )
        )
    else:
        print(json.dumps(outcome.as_dict(), indent=2, default=str))


async def _seed(_: argparse.Namespace) -> None:
    """Load the bundled sample feed rows so an offline demo has real hits."""
    from pathlib import Path

    await init_db()
    sample = Path(__file__).resolve().parent.parent / "data" / "sample_feed.csv"
    if not sample.exists():
        print(f"sample feed missing at {sample}", file=sys.stderr)
        raise SystemExit(1)
    rows = await feeds.import_local_csv(str(sample), feed="sample-offline", ioc_type="ip")
    print(f"seeded {rows} offline feed rows from {sample.name}")


async def _refresh_tlds(_: argparse.Namespace) -> None:
    """Replace data/tlds.txt with the authoritative IANA list.

    The file is only written once it has parsed, so a captive portal or a 500
    from IANA leaves the previous allowlist in place rather than emptying it.
    """
    from .net import build_client

    async with build_client(timeout=30.0) as client:
        response = await client.get(IANA_URL)
        response.raise_for_status()
        text = response.text

    labels = parse_iana(text)
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text("\n".join(sorted(labels)) + "\n", encoding="utf-8")
    added = labels - SNAPSHOT
    print(f"{len(labels)} TLDs written to {CACHE_PATH}")
    print(f"  {len(added)} not in the compiled snapshot"
          + (f" (e.g. {', '.join(sorted(added)[:6])})" if added else ""))


async def _audit(_args: argparse.Namespace) -> None:
    await init_db()
    async with session_scope() as session:
        problems = await audit.verify(session)
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        raise SystemExit(1)
    print("the audit log is intact")


async def _new_key(_args: argparse.Namespace) -> None:
    # Printed, never written anywhere: where it is kept is the operator's choice.
    print(new_key())


async def _setup_code(_args: argparse.Namespace) -> None:
    # Printed here only, never logged: whoever enters it first owns the server.
    await init_db()
    async with session_scope() as session:
        code = await accounts.setup_code(session, server_box())
    if code is None:
        print("this server is set up already: an admin adds people, and the owner signs in", file=sys.stderr)
        raise SystemExit(1)
    print("Open the console in a browser, choose Set up this server, and enter this code (it works once):")
    print(code)


async def _sweep(_args: argparse.Namespace) -> None:
    """What the hourly Celery job does, once, from the terminal (or a cron line without Celery)."""
    from .services import retention

    await init_db()
    async with session_scope() as session:
        swept = await retention.sweep(session)
    print(f"{sum(swept.values())} case input(s) past retention deleted, in {len(swept)} workspace(s)")


async def _rotate_key(args: argparse.Namespace) -> None:
    """Re-seal every sealed value under a new key, read from NEW_ENCRYPTION_KEY or a file: never
    from the command line, where it would stay in the shell's history. Stop the API and the worker
    first, so nothing is sealed with the old key while this runs."""
    import os
    from pathlib import Path

    from .platform import rotation
    from .platform.crypto import Box

    value = os.environ.get("NEW_ENCRYPTION_KEY", "").strip()
    if not value and args.new_key_file:
        try:
            value = Path(args.new_key_file).read_text(encoding="ascii").strip()
        except OSError as exc:
            print(f"--new-key-file could not be read: {exc.strerror}", file=sys.stderr)
            raise SystemExit(2) from exc
    if not value:
        print("set NEW_ENCRYPTION_KEY or pass --new-key-file (new-key prints a fresh key)", file=sys.stderr)
        raise SystemExit(2)
    try:
        new = Box.from_b64(value)
    except ValueError as exc:
        print(f"the new key is not usable: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    old = server_box()
    await init_db()
    try:
        async with session_scope() as session:
            counts = await rotation.rotate(session, old, new)
    except rotation.RotationError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
    print(f"{counts['settings']} setting(s) and {counts['case_inputs']} case input(s) are sealed with the new key.")
    print("Set ENCRYPTION_KEY to the new key, then start the server and the worker again.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="intelpulse")
    sub = parser.add_subparsers(dest="command", required=True)

    feeds_parser = sub.add_parser("feeds", help="import offline datasets")
    feeds_parser.add_argument("--all", action="store_true")
    feeds_parser.add_argument("--feodo", action="store_true")
    feeds_parser.add_argument("--threatfox", action="store_true")
    feeds_parser.add_argument("--firehol", action="store_true")
    feeds_parser.add_argument("--kev", action="store_true")
    feeds_parser.add_argument("--nvd", action="store_true")
    feeds_parser.add_argument("--days", type=int, default=30)
    feeds_parser.set_defaults(func=_feeds)

    triage_parser = sub.add_parser("triage", help="triage indicators from the terminal")
    triage_parser.add_argument("indicators", nargs="+")
    triage_parser.add_argument("--title", default="CLI triage")
    triage_parser.add_argument("--report", action="store_true", help="print a Markdown ticket")
    triage_parser.add_argument("--persist", action="store_true")
    triage_parser.set_defaults(func=_triage)

    seed_parser = sub.add_parser("seed", help="load bundled sample feed rows")
    seed_parser.set_defaults(func=_seed)

    tlds_parser = sub.add_parser(
        "refresh-tlds", help="update the hostname allowlist from the IANA list"
    )
    tlds_parser.set_defaults(func=_refresh_tlds)

    audit_parser = sub.add_parser("audit", help="check that the audit log has not been changed")
    audit_parser.add_argument("action", choices=["verify"])
    audit_parser.set_defaults(func=_audit)

    key_parser = sub.add_parser(
        "new-key", help="print a fresh ENCRYPTION_KEY (32 random bytes, base64)"
    )
    key_parser.set_defaults(func=_new_key)

    setup_parser = sub.add_parser(
        "setup-code", help="print the one-time code that creates the owner's account on a new server"
    )
    setup_parser.set_defaults(func=_setup_code)

    rotate_parser = sub.add_parser(
        "rotate-key", help="re-seal everything under a new key (from NEW_ENCRYPTION_KEY or --new-key-file)"
    )
    rotate_parser.add_argument("--new-key-file", default=None, help="a file holding the new key")
    rotate_parser.set_defaults(func=_rotate_key)

    sweep_parser = sub.add_parser(
        "sweep", help="delete case inputs older than each workspace's retention days (held cases stay)"
    )
    sweep_parser.set_defaults(func=_sweep)

    args = parser.parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
