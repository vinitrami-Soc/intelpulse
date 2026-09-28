"""SOC ticket generation — the output an analyst actually pastes into Jira.

Containment advice is derived from indicator type plus verdict, and is written
as the action a defender takes on their own estate (block, hunt, revoke), never
as an offensive step.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from .ioc import defang
from .scoring import IndicatorVerdict
from .text import clean_label, md_text


def _code(value: str) -> str:
    """An indicator as an inline code span. A URL may carry a backtick, which
    would close the span early, so it is written the way a URL writes it."""
    return "`" + defang(value).replace("`", "%60") + "`"

SEVERITY_SLA = {
    "critical": "P1: contain within 1 hour",
    "high": "P2: contain within 4 hours",
    "medium": "P3: investigate within 1 business day",
    "low": "P4: monitor",
    "informational": "P5: no action, record only",
    "allowlisted": "closed: allowlisted by the SOC",
}

_CONTAINMENT: dict[str, list[str]] = {
    "ip": [
        "Block the address at the perimeter firewall and on egress proxies.",
        "Search SIEM/NetFlow for the last 30 days of traffic to this address and list every internal host that talked to it.",
        "If any internal host communicated with it, isolate the host and capture volatile memory before reimaging.",
    ],
    "domain": [
        "Sinkhole or block the domain on the DNS resolver and secure web gateway.",
        "Query DNS logs for the last 30 days for resolution attempts and identify the requesting hosts.",
        "Add the domain and its known subdomains to the email gateway blocklist.",
    ],
    "url": [
        "Block the full URL and its parent domain on the web proxy.",
        "Pull proxy logs for anyone who fetched it; treat a 200 response as a suspected download.",
        "If a user clicked it, reset their credentials and revoke active sessions and OAuth tokens.",
    ],
    "hash": [
        "Add the hash to the EDR blocklist and trigger an estate-wide hash sweep.",
        "Quarantine any endpoint where the file is present and preserve the sample for analysis.",
        "Identify the delivery vector (email attachment, USB, download) before closing the ticket.",
    ],
    "email": [
        "Block the sender address and its domain at the mail gateway.",
        "Run a mailbox search-and-purge for messages from this sender.",
        "Notify recipients and force password resets where credentials may have been entered.",
    ],
    "cve": [
        "Confirm exposure with an authenticated vulnerability scan of the affected estate.",
        "Apply the vendor patch or documented mitigation within the SLA for its CVSS band.",
        "Add detection for known exploitation attempts against the affected service.",
    ],
}

_NO_ACTION = [
    "No containment action required. Record the triage result against the ticket and close.",
    "If this indicator recurs with a higher score, re-open and re-triage.",
]


def containment_actions(verdict: IndicatorVerdict) -> list[str]:
    if verdict.verdict in ("informational", "allowlisted", "low"):
        return _NO_ACTION
    actions = list(_CONTAINMENT.get(verdict.indicator.type, _NO_ACTION))
    if verdict.malware_families:
        actions.append(
            f"Hunt for the known TTPs of {', '.join(verdict.malware_families[:3])} "
            "across endpoints and identity logs."
        )
    if verdict.verdict == "critical":
        actions.append("Raise a major-incident bridge and notify the on-call incident manager.")
    return actions


# Low to high, for the one place a sender's severity meets a verdict: the ticket's priority.
_LEVELS = ("allowlisted", "informational", "low", "medium", "high", "critical")


def ticket_level(case_level: str, alert: dict[str, Any] | None) -> str:
    """The level a ticket is filed at: the case's verdict, or a pushed alert's
    severity when that is higher. Threat intelligence judges the indicators;
    the sender judged the behaviour, and a detection whose indicators no source
    has seen before is no less urgent for it."""
    sent = str((alert or {}).get("severity", ""))
    if sent not in _LEVELS:
        return case_level
    rank = {level: i for i, level in enumerate(_LEVELS)}
    return sent if rank[sent] > rank.get(case_level, -1) else case_level


def _when(value: object) -> str:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return md_text(value, 40)


def _alert_lines(alert: dict[str, Any]) -> list[str]:
    """What the sender saw, before what threat intelligence says about it.

    Everything here came from the sender, so every field goes through md_text:
    one line, escaped, schemes defanged.
    """
    lines = [f"## Alert from {md_text(alert.get('source'), 40)}", ""]
    if alert.get("description"):
        lines += [md_text(alert["description"], 2000), ""]
    lines += [
        "| Field | Value |",
        "| --- | --- |",
        f"| Alert ID | {md_text(alert.get('alert_id'), 200)} |",
        f"| Severity (sender) | **{md_text(alert.get('severity'), 20).upper()}** |",
    ]
    entities = alert.get("entities") or []
    if entities:
        named = ", ".join(f"{md_text(e.get('kind'), 20)} {md_text(e.get('name'), 200)}" for e in entities[:20])
        lines.append(f"| Entities | {named} |")
    techniques = alert.get("attack_techniques") or []
    if techniques:
        lines.append(f"| MITRE ATT&CK | {', '.join(md_text(t, 20) for t in techniques[:20])} |")
    for key, name in (("first_seen", "First seen"), ("last_seen", "Last seen")):
        if alert.get(key):
            lines.append(f"| {name} | {_when(alert[key])} UTC |")
    lines.append("")
    evidence = alert.get("evidence") or []
    if evidence:
        lines += ["| Time (UTC) | What | Detail |", "| --- | --- | --- |"]
        for item in evidence[:_EVIDENCE_ROWS]:
            when = _when(item["time"]) if item.get("time") else ""
            lines.append(f"| {when} | {md_text(item.get('label'), 200)} | {md_text(item.get('text'), 400)} |")
        lines.append("")
        if len(evidence) > _EVIDENCE_ROWS:
            lines += [f"{len(evidence) - _EVIDENCE_ROWS} more evidence item(s) are stored with the case.", ""]
    return lines


_EVIDENCE_ROWS = 50


def _score_bar(score: int) -> str:
    filled = round(score / 10)
    return "█" * filled + "░" * (10 - filled)


def executive_summary(
    case_title: str,
    verdicts: list[IndicatorVerdict],
    verdict: str,
    score: int,
    *,
    markdown: bool = False,
) -> str:
    actionable = [v for v in verdicts if v.is_actionable]
    families = sorted({f for v in verdicts for f in v.malware_families})
    # Family names are the vendors' words: one clean line each, and escaped
    # when the summary is going into Markdown.
    label = md_text if markdown else clean_label
    if not verdicts:
        return "No indicators were extracted from the supplied input."
    lead = (
        f"{len(verdicts)} indicator(s) were triaged across the configured intelligence sources. "
        f"The highest composite score is {score}/100 ({verdict.upper()})."
    )
    if actionable:
        worst = max(actionable, key=lambda v: v.score)
        lead += (
            f" {len(actionable)} indicator(s) are actionable, led by "
            f"{_code(worst.indicator.value)} ({worst.verdict.upper()}, {worst.score}/100, "
            f"confidence {worst.confidence:.0%})."
        )
    else:
        lead += " No indicator reached the actionable threshold; treat this as informational."
    if families:
        lead += f" Associated malware/activity: {', '.join(label(f, 80) for f in families[:4])}."
    return lead


def to_markdown(
    case_id: str,
    case_title: str,
    verdicts: list[IndicatorVerdict],
    case_level: str,
    case_score: int,
    *,
    analyst: str | None = None,
    duration_ms: int = 0,
    alert: dict[str, Any] | None = None,
) -> str:
    """The ticket. `alert` is what a SIEM pushed, for a case that came in through
    /api/alerts: it opens the report, and its severity can raise the priority."""
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    lines: list[str] = [
        f"# SOC Triage Report: {md_text(case_title, 200)}",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Case ID | `{case_id}` |",
        f"| Generated | {now} |",
        f"| Analyst | {md_text(analyst, 120) if analyst else 'IntelPulse (automated)'} |",
        f"| Severity | **{case_level.upper()}** ({case_score}/100) |",
        f"| Priority | {SEVERITY_SLA.get(ticket_level(case_level, alert), 'P4')} |",
        f"| Indicators | {len(verdicts)} |",
        f"| Enrichment time | {duration_ms} ms |",
        "",
    ]
    if alert:
        # After the table, so a report's first lines read the same for every case.
        lines[-1:-1] = [f"| Alert | {md_text(alert.get('source'), 40)}, {md_text(alert.get('severity'), 20).upper()} |"]
        lines += _alert_lines(alert)
    lines += [
        "## 1. Executive summary",
        "",
        executive_summary(case_title, verdicts, case_level, case_score, markdown=True),
        "",
        "## 2. Indicators observed",
        "",
        "| Indicator | Type | Score | Verdict | Confidence | Sources agreeing |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for v in sorted(verdicts, key=lambda x: x.score, reverse=True):
        agreeing = sum(1 for c in v.contributions if c.signal >= 0.5)
        lines.append(
            f"| {_code(v.indicator.value)} | {v.indicator.type} | {v.score}/100 "
            f"`{_score_bar(v.score)}` | **{v.verdict.upper()}** | {v.confidence:.0%} | "
            f"{agreeing}/{v.providers_answered} |"
        )

    lines += ["", "## 3. Evidence and attribution", ""]
    for v in sorted(verdicts, key=lambda x: x.score, reverse=True):
        lines.append(f"### {_code(v.indicator.value)}: {v.verdict.upper()} ({v.score}/100)")
        lines.append("")
        if v.malware_families:
            lines.append(f"- **Malware / campaign:** {', '.join(md_text(f, 80) for f in v.malware_families)}")
        if v.attack_techniques:
            techniques = ", ".join(
                f"{md_text(t.get('id', ''), 20)} ({md_text(t.get('name', ''), 80)})" for t in v.attack_techniques[:6]
            )
            lines.append(f"- **MITRE ATT&CK:** {techniques}")
        if v.tags:
            lines.append(f"- **Tags:** {', '.join(md_text(t, 60) for t in v.tags[:10])}")
        for contribution in v.contributions:
            if contribution.signal <= 0 and not contribution.rationale:
                continue
            lines.append(
                f"- **{md_text(contribution.provider, 40)}** (signal {contribution.signal:.2f}, "
                f"weight {contribution.weight:g}): {md_text(contribution.rationale, 400)}"
            )
        for modifier in v.modifiers:
            lines.append(f"- **Modifier:** {md_text(modifier, 300)}")
        lines.append("")

    lines += ["## 4. Recommended containment actions", ""]
    seen: set[str] = set()
    for v in sorted(verdicts, key=lambda x: x.score, reverse=True):
        if v.verdict in ("informational", "allowlisted"):
            continue
        header = f"**{_code(v.indicator.value)} ({v.verdict.upper()})**"
        lines.append(header)
        for action in containment_actions(v):
            if action in seen:
                continue
            seen.add(action)
            lines.append(f"- [ ] {action}")
        lines.append("")
    if not seen:
        lines += [f"- [x] {action}" for action in _NO_ACTION] + [""]

    queried = sum(v.providers_queried for v in verdicts)
    answered = sum(v.providers_answered for v in verdicts)
    lines += [
        "## 5. Notes",
        "",
        f"- **Source coverage:** {answered}/{queried} provider lookups returned data. "
        "Unconfigured or failing sources are listed as skipped/error in the platform UI; "
        "a low-coverage verdict should be treated as provisional.",
        "- Indicators are defanged in this report; refang before use in tooling.",
        "- Scores are a weighted composite of the sources listed above, not a single vendor verdict.",
        "- Confidence reflects source coverage and agreement, not certainty of maliciousness.",
        "",
        f"_Generated by IntelPulse · case `{case_id}`_",
    ]
    return "\n".join(lines)


def to_ticket_json(
    case_id: str,
    case_title: str,
    verdicts: list[IndicatorVerdict],
    case_level: str,
    case_score: int,
    *,
    analyst: str | None = None,
    alert: dict[str, Any] | None = None,
) -> dict:
    ticket = {
        "case_id": case_id,
        "title": case_title,
        "generated_at": datetime.now(UTC).isoformat(),
        "analyst": analyst or "IntelPulse (automated)",
        "severity": case_level,
        "priority": SEVERITY_SLA.get(ticket_level(case_level, alert), "P4"),
        "score": case_score,
        "summary": executive_summary(case_title, verdicts, case_level, case_score),
        "indicators": [
            {
                "value": v.indicator.value,
                "defanged": defang(v.indicator.value),
                "type": v.indicator.type,
                "score": v.score,
                "verdict": v.verdict,
                "confidence": v.confidence,
                "malware_families": v.malware_families,
                "attack_techniques": v.attack_techniques,
                "tags": v.tags,
                "evidence": [
                    {
                        "provider": c.provider,
                        "signal": c.signal,
                        "weight": c.weight,
                        "rationale": c.rationale,
                    }
                    for c in v.contributions
                ],
                "modifiers": v.modifiers,
                "containment": containment_actions(v),
            }
            for v in sorted(verdicts, key=lambda x: x.score, reverse=True)
        ],
    }
    if alert:
        ticket["alert"] = alert
    return ticket
