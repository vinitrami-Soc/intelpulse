"""Push a case to the tracker the SOC actually works in.

Downloading Markdown and pasting it into Jira is the step that gets skipped at
2am, and a triage nobody raised a ticket for may as well not have happened. A
sink turns the generated report into an issue in one request.

Design notes worth keeping:

* A sink is configured per workspace by its admin (sealed, in its settings;
  `SinkConfig`), never by a request that carries a case. The client that
  delivers a ticket is allowed exactly that workspace's sink host and no
  other; private address space stays closed to it unless the operator named
  the host (`net.ticket_sink_hosts()`).
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


@dataclass(frozen=True)
class SinkConfig:
    """One workspace's trackers. Built from its settings (workspace_settings.sink_config)."""

    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None
    jira_issue_type: str = "Task"
    servicenow_base_url: str | None = None
    servicenow_user: str | None = None
    servicenow_password: str | None = None
    servicenow_table: str = "incident"

    @classmethod
    def from_env(cls) -> SinkConfig:
        """What IntelPulse 1.x read from the environment (moved into the first organization once)."""
        return cls(
            jira_base_url=settings.jira_base_url, jira_email=settings.jira_email,
            jira_api_token=settings.jira_api_token, jira_project_key=settings.jira_project_key,
            jira_issue_type=settings.jira_issue_type or "Task",
            servicenow_base_url=settings.servicenow_base_url, servicenow_user=settings.servicenow_user,
            servicenow_password=settings.servicenow_password, servicenow_table=settings.servicenow_table or "incident",
        )

    def sinks(self) -> list[str]:
        """Which sinks can actually deliver: a URL alone is not enough, the credential is needed too."""
        found = []
        if self.jira_base_url and self.jira_api_token and self.jira_project_key:
            found.append(JIRA)
        if self.servicenow_base_url and self.servicenow_password:
            found.append(SERVICENOW)
        return found

    def host(self, sink: str) -> str:
        raw = self.jira_base_url if sink == JIRA else self.servicenow_base_url
        return (httpx.URL(raw).host or "").lower() if raw else ""


def configured_sinks(config: SinkConfig) -> list[str]:
    return config.sinks()


def _auth_header(user: str | None, secret: str | None) -> str:
    raw = f"{user or ''}:{secret or ''}".encode()
    return "Basic " + base64.b64encode(raw).decode()


async def _post(url: str, *, headers: dict[str, str], json: dict, host: str = "") -> httpx.Response:
    # This client, and only this one, may reach the workspace's own sink host.
    async with build_client(timeout=settings.ticket_timeout_seconds,
                            extra_hosts=frozenset({host}) if host else frozenset()) as client:
        return await client.post(url, headers=headers, json=json)


async def _create_jira(case: dict[str, Any], body: str, config: SinkConfig) -> Ticket:
    base = str(config.jira_base_url).rstrip("/")
    payload = {
        "fields": {
            "project": {"key": config.jira_project_key},
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
            "issuetype": {"name": config.jira_issue_type},
            "labels": ["intelpulse", f"verdict-{case.get('verdict', 'informational')}"],
        }
    }
    response = await _post(
        f"{base}/rest/api/3/issue",
        headers={
            "Authorization": _auth_header(config.jira_email, config.jira_api_token),
            "Accept": "application/json",
        },
        json=payload,
        host=config.host(JIRA),
    )
    if response.status_code >= 400:
        raise TicketError(_vendor_message(response), status=response.status_code)
    data = response.json()
    key = str(data.get("key") or data.get("id") or "")
    return Ticket(sink=JIRA, key=key, url=f"{base}/browse/{key}" if key else base)


async def _create_servicenow(case: dict[str, Any], body: str, config: SinkConfig) -> Ticket:
    base = str(config.servicenow_base_url).rstrip("/")
    table = config.servicenow_table
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
                config.servicenow_user, config.servicenow_password
            ),
            "Accept": "application/json",
        },
        json=payload,
        host=config.host(SERVICENOW),
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


async def create_ticket(case: dict[str, Any], body: str, sink: str, config: SinkConfig) -> Ticket:
    """Raise `case` in `sink`.

    `case` is metadata only — case_id, title, verdict, score, indicators — and
    `body` is the rendered report. The caller owns rendering, because it already
    does for the download route and the two must not drift.
    """
    available = config.sinks()
    if sink not in available:
        raise TicketError(
            f"{sink} is not configured for this workspace"
            + (f" (available: {', '.join(available)})" if available else ""),
            status=409,
        )
    try:
        if sink == JIRA:
            ticket = await _create_jira(case, body, config)
        else:
            ticket = await _create_servicenow(case, body, config)
    except TicketError:
        raise
    except httpx.HTTPError as exc:
        # Includes EgressBlocked, which is a TransportError.
        raise TicketError(f"could not reach {sink}: {exc}", status=502) from exc
    logger.info(
        "ticket created", extra={"sink": sink, "key": ticket.key, "case": case.get("case_id")}
    )
    return ticket
