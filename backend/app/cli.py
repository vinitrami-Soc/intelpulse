"""Command line entry points: feed imports, one-shot triage, seeding.

    python -m app.cli feeds --all
    python -m app.cli triage 185.220.101.34 --report
    python -m app.cli seed          # demo rows so the UI is not empty
    python -m app.cli refresh-tlds  # update the hostname allowlist from IANA
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .db import init_db, session_scope
from .ioc import extract
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
    outcome = await triage(indicators, title=args.title)
    if args.persist:
        async with session_scope() as session:
            await persist_case(session, outcome, raw_input=text, source="cli")
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

    args = parser.parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
