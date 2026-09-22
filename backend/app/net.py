"""Outbound request guard.

IntelPulse never fetches a URL an analyst supplies — indicators are passed to
fixed vendor endpoints as path or body parameters, so there is no classic SSRF
sink here. This module exists anyway, because "there is no sink today" is not a
control:

  * every outbound host must be on an explicit allowlist (vendor APIs + the
    offline feed sources), so a future provider, a typo in a URL template or a
    manipulated path can only ever reach a known intelligence service;
  * the resolved addresses are checked against private, loopback, link-local,
    CGNAT and cloud-metadata space, so an allowlisted host whose DNS answer
    points inward (rebinding, a poisoned resolver, a hijacked domain) is
    refused before a socket is opened;
  * plain HTTP is refused outright.

The DNS check is defence in depth, not a complete rebinding defence: there is a
window between resolution and connection that only IP-pinned connections close.
The host allowlist is the control that actually holds.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time

import httpx

logger = logging.getLogger(__name__)

# Every host this service is ever allowed to talk to.
ALLOWED_HOSTS: frozenset[str] = frozenset({
    # live provider APIs
    "api.abuseipdb.com",
    "otx.alienvault.com",
    "api.greynoise.io",
    "threatfox-api.abuse.ch",
    "urlhaus-api.abuse.ch",
    "www.virustotal.com",
    # offline dataset sources
    "feodotracker.abuse.ch",
    "threatfox.abuse.ch",
    "urlhaus.abuse.ch",
    "raw.githubusercontent.com",
    "www.cisa.gov",
    "services.nvd.nist.gov",
})


def ticket_sink_hosts() -> frozenset[str]:
    """Hosts the operator configured for ticket delivery, from env only.

    These come from JIRA_BASE_URL / SERVICENOW_BASE_URL, which an operator sets
    when they deploy. They are never taken from a request, so widening the
    allowlist with them does not widen what an attacker-controlled indicator
    can reach — the rest of the policy (HTTPS only, no reserved space unless
    explicitly permitted) still applies to them.
    """
    from .config import settings

    hosts = set()
    for raw in (settings.jira_base_url, settings.servicenow_base_url):
        if not raw:
            continue
        host = (httpx.URL(raw).host or "").lower()
        if host:
            hosts.add(host)
    return frozenset(hosts)

# Ranges that an external intelligence API must never resolve to.
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16",          # link-local, incl. 169.254.169.254 metadata
        "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
        "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4",
        "240.0.0.0/4", "255.255.255.255/32",
        "::1/128", "fc00::/7", "fe80::/10", "::/128", "2001:db8::/32",
    )
)

_RESOLUTION_TTL = 60.0
_resolution_cache: dict[str, tuple[float, tuple[str, ...]]] = {}


class EgressBlocked(httpx.TransportError):
    """Raised instead of connecting when a request fails the egress policy."""


def is_blocked_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True  # un-parseable is not provably safe
    return any(address in network for network in _BLOCKED_NETWORKS)


async def resolve(host: str) -> tuple[str, ...]:
    cached = _resolution_cache.get(host)
    now = time.monotonic()
    if cached and cached[0] > now:
        return cached[1]

    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    addresses = tuple(dict.fromkeys(info[4][0] for info in infos))
    _resolution_cache[host] = (now + _RESOLUTION_TTL, addresses)
    return addresses


async def assert_allowed(url: httpx.URL) -> None:
    from .config import settings

    host = (url.host or "").lower()
    if url.scheme != "https":
        raise EgressBlocked(f"refused non-HTTPS outbound request to {host or url}")

    sinks = ticket_sink_hosts()
    if host not in ALLOWED_HOSTS and host not in sinks:
        raise EgressBlocked(f"refused outbound request to non-allowlisted host {host!r}")

    try:
        addresses = await resolve(host)
    except OSError as exc:
        raise EgressBlocked(f"could not resolve {host}: {exc}") from exc
    if not addresses:
        raise EgressBlocked(f"no addresses returned for {host}")

    # A self-hosted Jira or ServiceNow legitimately lives on an internal
    # network, so an operator can permit reserved space for the sinks they
    # configured — and only those. Intelligence providers never get it.
    if host in sinks and settings.ticket_allow_private_host:
        return

    blocked = [address for address in addresses if is_blocked_address(address)]
    if blocked:
        logger.warning("egress: %s resolved into reserved space %s — refused", host, blocked)
        raise EgressBlocked(f"{host} resolved to non-routable address {blocked[0]}")


class GuardedTransport(httpx.AsyncHTTPTransport):
    """httpx transport that applies the egress policy before every connection."""

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        await assert_allowed(request.url)
        return await super().handle_async_request(request)


def build_client(**kwargs) -> httpx.AsyncClient:
    """The only way this codebase is allowed to construct an outbound client.

    Redirects are followed, because httpx re-enters the transport for every
    hop — so a vendor redirecting to an internal host is refused at the hop
    that tries it, not silently followed.
    """
    kwargs.setdefault("follow_redirects", True)
    kwargs.setdefault("max_redirects", 5)
    return httpx.AsyncClient(transport=GuardedTransport(), **kwargs)
