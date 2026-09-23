"""Push a case to the tracker the SOC actually works in.

Downloading Markdown and pasting it into Jira is the step that gets skipped at
2am, and a triage nobody raised a ticket for may as well not have happened. A
sink turns the generated report into an issue in one request.

Design notes worth keeping:

* A sink is configured by an operator through the environment, never by a
  request. `net.ticket_sink_hosts()` widens the egress allowlist with exactly
  those hosts, so this does not become a way for an attacker-controlled
  indicator to make the server talk to somewhere new.
* Credentials never appear in a response or a log line. On failure the caller
  is told the status code and the vendor's message, not the request.
* One sink failing is a 502 with the reason, not a crash: the case is already
  stored, and the analyst can retry or fall back to Markdown.
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Any

import httpx

from ..config import settings
from ..net import build_client

logger = logging.getLogger(__name__)

JIRA = "jira"
SERVICENOW = "servicenow"


class TicketError(RuntimeError):
    """The sink refused the issue. Carries what the vendor said, not the request."""

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class Ticket:
    sink: str
    key: str
    url: str

    def as_dict(self) -> dict[str, Any]:
        return {"sink": self.sink, "key": self.key, "url": self.url}



def _summary(case: dict[str, Any]) -> str:
    verdict = str(case.get("verdict", "informational")).upper()
    title = str(case.get("title") or "Ad-hoc triage")
    count = len(case.get("indicators") or [])
    return f"[{verdict}] {title}: {count} indicator(s), score {case.get('score', 0)}/100"[:250]


def configured_sinks() -> list[str]:
    """Which sinks this deployment can actually deliver to."""
    sinks = []
    if settings.jira_base_url and settings.jira_api_token and settings.jira_project_key:
        sinks.append(JIRA)
    if settings.servicenow_base_url and settings.servicenow_password:
        sinks.append(SERVICENOW)
    return sinks


def _auth_header(user: str | None, secret: str | None) -> str:
    raw = f"{user or ''}:{secret or ''}".encode()
    return "Basic " + base64.b64encode(raw).decode()


async def _post(url: str, *, headers: dict[str, str], json: dict) -> httpx.Response:
    async with build_client(timeout=settings.ticket_timeout_seconds) as client:
        return await client.post(url, headers=headers, json=json)


async def _create_jira(case: dict[str, Any], body: str) -> Ticket:
    base = str(settings.jira_base_url).rstrip("/")
    payload = {
        "fields": {
            "project": {"key": settings.jira_project_key},
            "summary": _summary(case),
            # Jira Cloud's v3 API takes Atlassian Document Format, not Markdown.
            # One code block keeps the report readable without a converter that
            # would have to be maintained against their schema.
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "codeBlock", "content": [{"type": "text", "text": body[:30_000]}]}
                ],
            },
            "issuetype": {"name": settings.jira_issue_type},
            "labels": ["intelpulse", f"verdict-{case.get('verdict', 'informational')}"],
        }
    }
    response = await _post(
        f"{base}/rest/api/3/issue",
        headers={
            "Authorization": _auth_header(settings.jira_email, settings.jira_api_token),
            "Accept": "application/json",
        },
        json=payload,
    )
    if response.status_code >= 400:
        raise TicketError(_vendor_message(response), status=response.status_code)
    data = response.json()
    key = str(data.get("key") or data.get("id") or "")
    return Ticket(sink=JIRA, key=key, url=f"{base}/browse/{key}" if key else base)


async def _create_servicenow(case: dict[str, Any], body: str) -> Ticket:
    base = str(settings.servicenow_base_url).rstrip("/")
    table = settings.servicenow_table
    # ServiceNow urgency/impact run 1 (high) to 3 (low) — the inverse of how a
    # verdict reads, so the mapping is explicit rather than arithmetic.
    urgency = {"critical": "1", "high": "1", "medium": "2"}.get(
        str(case.get("verdict")), "3"
    )
    payload = {
        "short_description": _summary(case),
        "description": body[:30_000],
        "urgency": urgency,
        "impact": urgency,
        "category": "security",
        "correlation_id": str(case.get("case_id") or ""),
    }
    response = await _post(
        f"{base}/api/now/table/{table}",
        headers={
            "Authorization": _auth_header(
                settings.servicenow_user, settings.servicenow_password
            ),
            "Accept": "application/json",
        },
        json=payload,
    )
    if response.status_code >= 400:
        raise TicketError(_vendor_message(response), status=response.status_code)
    result = (response.json() or {}).get("result") or {}
    number = str(result.get("number") or "")
    sys_id = str(result.get("sys_id") or "")
    url = f"{base}/nav_to.do?uri={table}.do%3Fsys_id%3D{sys_id}" if sys_id else base
    return Ticket(sink=SERVICENOW, key=number or sys_id, url=url)


def _vendor_message(response: httpx.Response) -> str:
    """What the vendor said, trimmed. Never the request, which holds the token."""
    try:
        data = response.json()
    except ValueError:
        return f"{response.status_code} {response.reason_phrase}".strip()
    for key in ("errorMessages", "error", "message", "detail"):
        value = data.get(key) if isinstance(data, dict) else None
        if isinstance(value, list) and value:
            return str(value[0])[:300]
        if isinstance(value, str) and value:
            return str(value)[:300]
    if isinstance(data, dict) and isinstance(data.get("errors"), dict) and data["errors"]:
        first = next(iter(data["errors"].items()))
        return f"{first[0]}: {first[1]}"[:300]
    return f"{response.status_code} {response.reason_phrase}".strip()


async def create_ticket(case: dict[str, Any], body: str, sink: str) -> Ticket:
    """Raise `case` in `sink`.

    `case` is metadata only — case_id, title, verdict, score, indicators — and
    `body` is the rendered report. The caller owns rendering, because it already
    does for the download route and the two must not drift.
    """
    available = configured_sinks()
    if sink not in available:
        raise TicketError(
            f"{sink} is not configured on this deployment"
            + (f" (available: {', '.join(available)})" if available else ""),
            status=409,
        )
    try:
        if sink == JIRA:
            ticket = await _create_jira(case, body)
        else:
            ticket = await _create_servicenow(case, body)
    except TicketError:
        raise
    except httpx.HTTPError as exc:
        # Includes EgressBlocked, which is a TransportError.
        raise TicketError(f"could not reach {sink}: {exc}", status=502) from exc
    logger.info(
        "ticket created", extra={"sink": sink, "key": ticket.key, "case": case.get("case_id")}
    )
    return ticket
