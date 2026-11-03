"""What the console's views read (spec 9.2), worked out from one workspace's rows.

Every function takes a workspace id and reads nothing outside it. The shared
feeds are the exception, and they are the server's, not anyone's cases.

Each read is bounded: a view that would have to scan a year of history scans a
window and says it was cut (`truncated`), rather than taking the database down
with it. The arithmetic that joins, groups and orders the rows is kept in plain
functions over plain values, so it is tested without a database.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, date, datetime, time, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import Case, CaseTicket, IndicatorResult, PushedAlert, User, utcnow
from ..scoring import VERDICTS, describe_techniques
from . import workflow

# Most severe first: the order every view lists bands in.
BANDS = tuple(reversed(VERDICTS))
RANK = {verdict: index for index, verdict in enumerate(VERDICTS)}

# A provider "flagged" an indicator when it answered and one of its signals leans
# malicious. A hosting or geography hint is context, not a flag.
FLAG_AT = 0.5

# ATT&CK's enterprise tactics in the order an intrusion runs through them.
TACTICS = (
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Command and Control", "Exfiltration", "Impact",
)

# What a pushed alert may call a host or a person. Anything else keeps its own kind.
HOST_KINDS = frozenset({"host", "hostname", "device", "computer", "endpoint", "server", "workstation", "machine"})
USER_KINDS = frozenset({"user", "username", "account", "user_account", "principal", "identity"})

# Relation targets that make two cases one campaign. A country or an OTX pulse is
# shared by too much to mean anything; a CVE is a weakness, not an actor.
CAMPAIGN_RELATIONS = frozenset({"asn", "ip", "domain", "url", "hash"})

# The windows each view scans, newest first.
CAMPAIGN_CASES = 500
NARRATIVE_CASES = 200
ASSET_ALERTS = 2000
SOURCE_RESULTS = 5000


def aware(at: datetime | None) -> datetime | None:
    """SQLite hands datetimes back without their offset; every one stored is UTC."""
    if at is None:
        return None
    return at if at.tzinfo is not None else at.replace(tzinfo=UTC)


def higher(a: str | None, b: str | None) -> str | None:
    """The more severe of two verdicts; an unknown one never wins over a known one."""
    if a is None:
        return b
    if b is None:
        return a
    return a if RANK.get(a, -1) >= RANK.get(b, -1) else b


def case_brief(case: Case) -> dict[str, Any]:
    return {"id": case.id, "title": case.title, "verdict": case.verdict, "score": case.max_score,
            "status": case.status, "created_at": workflow.iso(case.created_at)}


def by_severity(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Most severe first, then the highest score, then the most recently seen."""
    items = sorted(items, key=lambda item: item["last_seen"] or "", reverse=True)
    return sorted(items, key=lambda item: (-RANK.get(item["verdict"], -1), -item["score"]))


def flagged_by(payload: dict[str, Any]) -> list[str]:
    """The providers whose answer leaned malicious, by their label."""
    names = []
    for source in payload.get("sources") or []:
        if not isinstance(source, dict) or source.get("status") != "ok":
            continue
        signals = [s.get("value") for s in source.get("signals") or [] if isinstance(s, dict)]
        if any(isinstance(v, int | float) and v >= FLAG_AT for v in signals):
            names.append(str(source.get("label") or source.get("provider") or ""))
    return sorted(n for n in set(names) if n)


# -- the overview --------------------------------------------------------------------
def trend(created: Iterable[datetime], closed: Iterable[datetime], *, days: int, today: date) -> list[dict]:
    """Cases opened and closed on each of the last `days` days, oldest first."""
    start = today - timedelta(days=days - 1)
    opened_on: dict[date, int] = defaultdict(int)
    closed_on: dict[date, int] = defaultdict(int)
    for at in created:
        opened_on[aware(at).astimezone(UTC).date()] += 1
    for at in closed:
        closed_on[aware(at).astimezone(UTC).date()] += 1
    return [
        {"date": day.isoformat(), "opened": opened_on.get(day, 0), "closed": closed_on.get(day, 0)}
        for day in (start + timedelta(days=n) for n in range(days))
    ]


def time_to_close(pairs: Iterable[tuple[datetime, datetime]]) -> dict[str, Any]:
    """Mean and median seconds from opening to closing, over the cases given."""
    seconds = [max(0.0, (aware(closed) - aware(opened)).total_seconds()) for opened, closed in pairs]
    if not seconds:
        return {"cases": 0, "mean_seconds": None, "median_seconds": None}
    return {"cases": len(seconds), "mean_seconds": round(statistics.fmean(seconds)),
            "median_seconds": round(statistics.median(seconds))}


async def overview(db: AsyncSession, workspace_id: int, *, user_id: int | None, days: int) -> dict[str, Any]:
    """The workflow's numbers: each band by status, the trend, and how long closing takes."""
    ws = workspace_id
    grid = {(verdict, status): n for verdict, status, n in (await db.execute(
        select(Case.verdict, Case.status, func.count(Case.id)).where(Case.workspace_id == ws)
        .group_by(Case.verdict, Case.status)
    )).all()}
    bands = [{"verdict": band, **{status: grid.get((band, status), 0) for status in workflow.STATUSES}}
             for band in BANDS]
    by_status = {status: sum(n for (_, s), n in grid.items() if s == status) for status in workflow.STATUSES}

    async def count(query) -> int:
        return (await db.execute(query)).scalar_one()

    open_cases = Case.workspace_id == ws, Case.status != "closed"
    today = utcnow().date()
    # from midnight UTC of the trend's first day, so every case counted is on a day it shows
    since = datetime.combine(today - timedelta(days=days - 1), time.min, tzinfo=UTC)
    created = (await db.execute(
        select(Case.created_at).where(Case.workspace_id == ws, Case.created_at >= since)
    )).scalars().all()
    closed = (await db.execute(
        select(Case.created_at, Case.closed_at)
        .where(Case.workspace_id == ws, Case.status == "closed", Case.closed_at >= since)
    )).all()
    return {
        "bands": bands,
        "by_status": by_status,
        "open": by_status["new"] + by_status["in_progress"],
        "unassigned_open": await count(select(func.count(Case.id)).where(*open_cases, Case.assignee_id.is_(None))),
        "assigned_to_me_open": await count(
            select(func.count(Case.id)).where(*open_cases, Case.assignee_id == user_id)) if user_id else None,
        "distinct_indicators": await count(
            select(func.count(func.distinct(IndicatorResult.value))).where(IndicatorResult.workspace_id == ws)),
        "pushed_alerts": await count(select(func.count(PushedAlert.id)).where(PushedAlert.workspace_id == ws)),
        "tickets": await count(select(func.count(CaseTicket.id)).where(CaseTicket.workspace_id == ws)),
        "trend_days": days,
        "trend": trend(created, (at for _, at in closed), days=days, today=today),
        "time_to_close": time_to_close(closed),
    }


# -- every indicator once ------------------------------------------------------------
INDICATOR_SORTS = ("last_seen", "score", "cases")


async def indicators(db: AsyncSession, workspace_id: int, *, q: str = "", ioc_type: str | None = None,
                     verdict: str | None = None, sort: str = "last_seen", limit: int = 50,
                     offset: int = 0) -> list[dict[str, Any]]:
    """Each indicator the workspace has triaged, once: its latest verdict, when it was
    first and last seen, in how many cases, and which providers flagged it."""
    ir = IndicatorResult
    grouped = (
        select(ir.value.label("value"), ir.ioc_type.label("ioc_type"),
               func.count(func.distinct(ir.case_id)).label("cases"),
               func.min(ir.created_at).label("first_seen"), func.max(ir.created_at).label("last_seen"),
               func.max(ir.id).label("latest_id"))
        .where(ir.workspace_id == workspace_id)
        .group_by(ir.value, ir.ioc_type)
    )
    text = q.strip().lower()
    if text:
        grouped = grouped.where(func.lower(ir.value).contains(text, autoescape=True))
    if ioc_type:
        grouped = grouped.where(ir.ioc_type == ioc_type)
    each = grouped.subquery()
    query = select(each, ir).join(ir, ir.id == each.c.latest_id)
    if verdict:
        query = query.where(ir.verdict == verdict)
    order = {
        "score": (ir.score.desc(), each.c.last_seen.desc()),
        "cases": (each.c.cases.desc(), each.c.last_seen.desc()),
    }.get(sort, (each.c.last_seen.desc(),))
    rows = (await db.execute(query.order_by(*order, each.c.latest_id.desc()).limit(limit).offset(offset))).all()
    return [_indicator(row, row[-1]) for row in rows]


def _indicator(row, latest: IndicatorResult) -> dict[str, Any]:
    return {
        "value": row.value,
        "type": row.ioc_type,
        "verdict": latest.verdict,
        "score": latest.score,
        "confidence": latest.confidence,
        "first_seen": workflow.iso(row.first_seen),
        "last_seen": workflow.iso(row.last_seen),
        "cases": row.cases,
        "latest_case_id": latest.case_id,
        "malware_families": sorted({str(m) for m in latest.malware_families or []}),
        "flagged_by": flagged_by(latest.payload or {}),
    }


# -- campaigns -----------------------------------------------------------------------
def link_keys(row: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """What one scored indicator lets its case share with another: (kind, type, key, shown)."""
    keys = [("indicator", row["type"], f"{row['type']}:{row['value'].lower()}", row["value"])]
    for family in row.get("malware_families") or []:
        keys.append(("malware", "malware", f"malware:{str(family).lower()}", str(family)))
    for source in (row.get("payload") or {}).get("sources") or []:
        if not isinstance(source, dict) or source.get("status") != "ok":
            continue
        for relation in source.get("relations") or []:
            if not isinstance(relation, dict) or not relation.get("target"):
                continue
            target, kind = str(relation["target"]), str(relation.get("target_type") or "")
            if kind == "malware":
                keys.append(("malware", "malware", f"malware:{target.lower()}", target))
            elif kind in CAMPAIGN_RELATIONS:
                keys.append(("infrastructure", kind, f"{kind}:{target.lower()}", target))
    return keys


def join_campaigns(cases: list[dict[str, Any]], rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Cases joined into campaigns when they share a malware family or infrastructure.

    `cases` are briefs (`case_brief`), `rows` the cases' scored indicators. Only an
    indicator scored low or above joins anything: two emails that both name a big
    mail provider are not one campaign. A campaign has two cases or more.
    """
    by_id = {case["id"]: case for case in cases}
    parent = {case_id: case_id for case_id in by_id}

    def root(case_id: str) -> str:
        while parent[case_id] != case_id:
            parent[case_id] = parent[parent[case_id]]
            case_id = parent[case_id]
        return case_id

    links: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row["case_id"] not in by_id or RANK.get(row["verdict"], 0) < RANK["low"]:
            continue
        for kind, link_type, key, shown in link_keys(row):
            link = links.setdefault(key, {"kind": kind, "type": link_type, "value": shown,
                                          "cases": set(), "verdict": None})
            link["cases"].add(row["case_id"])
            link["verdict"] = higher(link["verdict"], row["verdict"])
    for link in links.values():
        first, *rest = sorted(link["cases"])
        for other in rest:
            a, b = root(first), root(other)
            if a != b:
                parent[b] = a

    groups: dict[str, list[str]] = defaultdict(list)
    for case_id in by_id:
        groups[root(case_id)].append(case_id)
    campaigns = []
    for members in groups.values():
        if len(members) < 2:
            continue
        inside = set(members)
        shared = [link for link in links.values() if len(link["cases"]) > 1 and link["cases"] <= inside]
        shared.sort(key=lambda link: (-len(link["cases"]), link["kind"] != "malware", link["value"].lower()))
        briefs = sorted((by_id[c] for c in members), key=lambda c: (c["created_at"] or "", c["id"]))
        top = max(briefs, key=lambda c: (RANK.get(c["verdict"], -1), c["score"]))
        families = [link for link in shared if link["kind"] == "malware"]
        label = (families or shared)[0]["value"] if shared else "Shared infrastructure"
        campaigns.append({
            "id": briefs[0]["id"],
            "label": label,
            "verdict": top["verdict"],
            "score": top["score"],
            "first_seen": briefs[0]["created_at"],
            "last_seen": briefs[-1]["created_at"],
            "case_count": len(briefs),
            "cases": briefs[:100],
            "links": [
                {"kind": link["kind"], "type": link["type"], "value": link["value"], "verdict": link["verdict"],
                 "cases": sorted(link["cases"], key=lambda c: (by_id[c]["created_at"] or "", c)),
                 "first_seen": min(by_id[c]["created_at"] or "" for c in link["cases"]) or None}
                for link in shared[:50]
            ],
        })
    return by_severity(campaigns)


async def campaigns(db: AsyncSession, workspace_id: int, *, days: int) -> dict[str, Any]:
    since = utcnow() - timedelta(days=days)
    found = (await db.execute(
        select(Case).where(Case.workspace_id == workspace_id, Case.created_at >= since)
        .order_by(Case.created_at.desc()).limit(CAMPAIGN_CASES + 1)
    )).scalars().all()
    window = found[:CAMPAIGN_CASES]
    ids = [case.id for case in window]
    rows = []
    if ids:
        rows = [
            {"case_id": r.case_id, "value": r.value, "type": r.ioc_type, "verdict": r.verdict,
             "malware_families": r.malware_families, "payload": r.payload}
            for r in (await db.execute(
                select(IndicatorResult).where(IndicatorResult.workspace_id == workspace_id,
                                              IndicatorResult.case_id.in_(ids),
                                              IndicatorResult.verdict != "informational")
            )).scalars()
        ]
    return {"days": days, "cases_considered": len(window), "truncated": len(found) > CAMPAIGN_CASES,
            "campaigns": join_campaigns([case_brief(case) for case in window], rows)}


# -- the attack surface ---------------------------------------------------------------
def asset_kind(kind: str) -> str:
    kind = kind.strip().lower()
    if kind in HOST_KINDS:
        return "host"
    if kind in USER_KINDS:
        return "user"
    return kind


def gather_assets(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The hosts, people and other things pushed alerts named, each with its cases.

    `alerts` are newest first: {entities, case (a brief), received_at}. The name is
    kept as the newest alert spelled it; two spellings that differ only in case are
    one asset.
    """
    assets: dict[tuple[str, str], dict[str, Any]] = {}
    for alert in alerts:
        case = alert["case"]
        seen = set()
        for entity in alert.get("entities") or []:
            if not isinstance(entity, dict) or not str(entity.get("name") or "").strip():
                continue
            kind, name = asset_kind(str(entity.get("kind") or "")), str(entity["name"]).strip()
            key = (kind, name.lower())
            if key in seen:
                continue
            seen.add(key)
            asset = assets.setdefault(key, {"kind": kind, "name": name, "alerts": 0, "case_ids": [],
                                            "open_cases": 0, "verdict": None, "score": 0,
                                            "first_seen": None, "last_seen": alert["received_at"]})
            asset["alerts"] += 1
            asset["first_seen"] = alert["received_at"]
            if case["id"] not in asset["case_ids"]:
                asset["case_ids"].append(case["id"])
                asset["open_cases"] += int(case["status"] != "closed")
                if (RANK.get(case["verdict"], -1), case["score"]) > (RANK.get(asset["verdict"], -1), asset["score"]):
                    asset["verdict"], asset["score"] = case["verdict"], case["score"]
    return by_severity([{**asset, "cases": len(asset["case_ids"]), "case_ids": asset["case_ids"][:20]}
                        for asset in assets.values()])


async def attack_surface(db: AsyncSession, workspace_id: int, *, kind: str | None = None, q: str = "",
                         limit: int = 100) -> dict[str, Any]:
    found = (await db.execute(
        select(PushedAlert, Case).join(Case, Case.id == PushedAlert.case_id)
        .where(PushedAlert.workspace_id == workspace_id)
        .order_by(PushedAlert.received_at.desc(), PushedAlert.id.desc()).limit(ASSET_ALERTS + 1)
    )).all()
    window = found[:ASSET_ALERTS]
    assets = gather_assets([
        {"entities": (alert.payload or {}).get("entities"), "case": case_brief(case),
         "received_at": workflow.iso(alert.received_at)}
        for alert, case in window
    ])
    if kind:
        assets = [a for a in assets if a["kind"] == asset_kind(kind)]
    text = q.strip().lower()
    if text:
        assets = [a for a in assets if text in a["name"].lower()]
    return {"alerts_considered": len(window), "truncated": len(found) > ASSET_ALERTS,
            "assets": assets[:limit]}


# -- intelligence sources ------------------------------------------------------------
def source_health(payloads: Iterable[tuple[dict[str, Any], datetime, str]]) -> dict[str, dict[str, Any]]:
    """Per provider, over the results given (newest first): how often it was asked,
    answered, failed and was rate limited, its median latency, and its last error."""
    stats: dict[str, dict[str, Any]] = {}
    latencies: dict[str, list[int]] = defaultdict(list)
    for payload, at, case_id in payloads:
        for source in payload.get("sources") or []:
            if not isinstance(source, dict) or not source.get("provider"):
                continue
            name, status = str(source["provider"]), str(source.get("status") or "")
            row = stats.setdefault(name, {"queries": 0, "answered": 0, "errors": 0, "rate_limited": 0,
                                          "skipped": 0, "last_error": None})
            if status == "skipped":
                row["skipped"] += 1
                continue
            row["queries"] += 1
            if status in ("ok", "clean"):
                row["answered"] += 1
            elif status == "error":
                row["errors"] += 1
            elif status == "rate_limited":
                row["rate_limited"] += 1
            if status in ("error", "rate_limited") and row["last_error"] is None:
                row["last_error"] = {"status": status, "message": str(source.get("error") or "")[:300],
                                     "at": workflow.iso(at), "case_id": case_id}
            latency = source.get("latency_ms")
            if not source.get("cached") and isinstance(latency, int) and latency > 0:
                latencies[name].append(latency)
    for name, row in stats.items():
        row["median_latency_ms"] = round(statistics.median(latencies[name])) if latencies[name] else None
    return stats


async def sources(db: AsyncSession, workspace_id: int, providers: list[dict[str, Any]], *,
                  days: int) -> dict[str, Any]:
    """The workspace's providers, each with how it has behaved over the last `days` days."""
    since = utcnow() - timedelta(days=days)
    found = (await db.execute(
        select(IndicatorResult.payload, IndicatorResult.created_at, IndicatorResult.case_id)
        .where(IndicatorResult.workspace_id == workspace_id, IndicatorResult.created_at >= since)
        .order_by(IndicatorResult.created_at.desc(), IndicatorResult.id.desc()).limit(SOURCE_RESULTS + 1)
    )).all()
    window = found[:SOURCE_RESULTS]
    health = source_health((payload or {}, at, case_id) for payload, at, case_id in window)
    empty = {"queries": 0, "answered": 0, "errors": 0, "rate_limited": 0, "skipped": 0,
             "median_latency_ms": None, "last_error": None}
    return {"days": days, "results_considered": len(window), "truncated": len(found) > SOURCE_RESULTS,
            "providers": [{**provider, **health.get(provider["name"], empty)} for provider in providers]}


# -- SOC tickets ---------------------------------------------------------------------
async def tickets(db: AsyncSession, workspace_id: int, *, sink: str | None = None, limit: int = 50,
                  offset: int = 0) -> list[dict[str, Any]]:
    """Every ticket raised for one of the workspace's cases, newest first."""
    query = (
        select(CaseTicket, Case, User)
        .join(Case, Case.id == CaseTicket.case_id)
        .outerjoin(User, User.id == CaseTicket.created_by)
        .where(CaseTicket.workspace_id == workspace_id, Case.workspace_id == workspace_id)
    )
    if sink:
        query = query.where(CaseTicket.sink == sink)
    rows = (await db.execute(
        query.order_by(CaseTicket.created_at.desc(), CaseTicket.id.desc()).limit(limit).offset(offset)
    )).all()
    return [
        {"id": ticket.id, "sink": ticket.sink, "key": ticket.key, "url": ticket.url,
         "created_at": workflow.iso(ticket.created_at), "created_by": workflow.person(user),
         "case": case_brief(case),
         "report": {"markdown": f"/api/cases/{case.id}/report?fmt=markdown",
                    "json": f"/api/cases/{case.id}/report?fmt=json"}}
        for ticket, case, user in rows
    ]


# -- attack narratives ---------------------------------------------------------------
def narrative(rows: list[dict[str, Any]], alert_techniques: Iterable[str] = ()) -> list[dict[str, Any]]:
    """A case's techniques, grouped by tactic in the order an intrusion runs, each with
    the indicators that evidence it and the providers that named it."""
    evidence: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in sorted(rows, key=lambda r: (-r["score"], r["value"])):
        payload = row.get("payload") or {}
        for tid in row.get("attack_ids") or []:
            named = sorted({
                str(s.get("label") or s.get("provider"))
                for s in payload.get("sources") or []
                if isinstance(s, dict) and tid in (s.get("attack_ids") or [])
            })
            evidence[tid].append({"indicator": row["value"], "type": row["type"], "verdict": row["verdict"],
                                  "score": row["score"], "named_by": named, "inferred": not named})
    from_alert = [tid for tid in dict.fromkeys(alert_techniques) if tid]
    order = {tactic: n for n, tactic in enumerate(TACTICS)}
    steps: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for technique in describe_techniques(list(dict.fromkeys([*evidence, *from_alert]))):
        tid = technique["id"]
        steps[technique["tactic"]].append({**technique, "from_alert": tid in from_alert,
                                           "evidence": evidence.get(tid, [])[:20]})
    return [
        {"tactic": tactic, "techniques": sorted(items, key=lambda t: t["id"])}
        for tactic, items in sorted(steps.items(), key=lambda kv: (order.get(kv[0], len(TACTICS)), kv[0]))
    ]


async def narratives(db: AsyncSession, workspace_id: int, *, days: int, limit: int) -> dict[str, Any]:
    since = utcnow() - timedelta(days=days)
    found = (await db.execute(
        select(Case).where(Case.workspace_id == workspace_id, Case.created_at >= since)
        .order_by(Case.created_at.desc()).limit(NARRATIVE_CASES + 1)
    )).scalars().all()
    window = found[:NARRATIVE_CASES]
    ids = [case.id for case in window]
    rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    alerts: dict[str, list[str]] = {}
    if ids:
        for r in (await db.execute(
            select(IndicatorResult).where(IndicatorResult.workspace_id == workspace_id,
                                          IndicatorResult.case_id.in_(ids))
        )).scalars():
            if r.attack_ids:
                rows[r.case_id].append({"value": r.value, "type": r.ioc_type, "verdict": r.verdict,
                                        "score": r.score, "attack_ids": r.attack_ids, "payload": r.payload})
        for case_id, payload in (await db.execute(
            select(PushedAlert.case_id, PushedAlert.payload)
            .where(PushedAlert.workspace_id == workspace_id, PushedAlert.case_id.in_(ids))
        )).all():
            alerts[case_id] = [str(t) for t in (payload or {}).get("attack_techniques") or []]
    stories = []
    for case in window:
        steps = narrative(rows.get(case.id, []), alerts.get(case.id, []))
        if steps:
            stories.append({"case": case_brief(case), "steps": steps})
        if len(stories) == limit:
            break
    return {"days": days, "cases_considered": len(window), "truncated": len(found) > NARRATIVE_CASES,
            "narratives": stories}
