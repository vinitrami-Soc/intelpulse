"""IOC extraction: turn whatever an analyst pastes into typed indicators.

Handles the three shapes of input a SOC actually produces:
  * a list of indicators pasted from a ticket,
  * a raw syslog / firewall / EDR line,
  * exported JSON (Windows event log, SIEM alert, evtx -> JSON conversion).

Defanged notation (1.2.3[.]4, hxxp://) is refanged before matching, RFC1918 and
other non-routable space is dropped, and hostnames are TLD-checked so that
`svchost.exe` or a version string never reaches an external API.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

from .config import settings

IOCType = str  # "ip" | "domain" | "url" | "hash" | "email" | "cve"

# --- defang / refang --------------------------------------------------------
_REFANG_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\[\s*\.\s*\]"), "."),
    (re.compile(r"\(\s*\.\s*\)"), "."),
    (re.compile(r"\{\s*\.\s*\}"), "."),
    (re.compile(r"\s+dot\s+", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*@\s*\]"), "@"),
    (re.compile(r"\(\s*@\s*\)"), "@"),
    (re.compile(r"\bh(?:xx|X X|\[t\]t)p", re.I), "http"),
    (re.compile(r"\bhxxps", re.I), "https"),
    (re.compile(r"\[\s*(https?)\s*\]", re.I), r"\1"),
)

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\)\]\},]{4,2048}", re.I)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.I)
_HASH_RE = re.compile(r"\b[A-F0-9]{32}\b|\b[A-F0-9]{40}\b|\b[A-F0-9]{64}\b", re.I)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,24}\b", re.I)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?:(?!-)[A-Z0-9-]{1,63}(?<!-)\.)+[A-Z]{2,24}\b", re.I
)

# Extensions and suffixes that look like domains in logs but are not.
_FILE_SUFFIXES = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "lnk", "scr",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "zip", "rar", "7z",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "css", "log", "txt", "tmp",
    "dat", "bin", "iso", "msi", "conf", "cfg", "ini", "xml", "yml", "yaml",
    "json", "py", "sh", "db", "sqlite", "local", "localdomain", "internal",
    "corp", "lan", "home", "arpa", "invalid", "example", "test",
}

# Keys that carry indicators in SIEM/EVTX JSON exports.
_JSON_IOC_KEYS = {
    "ip", "ipaddress", "ip_address", "src_ip", "dst_ip", "sourceip",
    "destinationip", "src", "dst", "remoteaddress", "remoteip", "clientip",
    "host", "hostname", "domain", "url", "uri", "request_url", "referer",
    "hash", "sha256", "sha1", "md5", "filehash", "hashes", "process_hash",
    "sender", "from", "recipient", "to", "email", "cve",
}


@dataclass(frozen=True)
class Indicator:
    value: str
    type: IOCType
    original: str = ""
    context: str = ""
    sources: tuple[str, ...] = field(default=())

    def as_dict(self) -> dict:
        return {
            "value": self.value,
            "type": self.type,
            "original": self.original or self.value,
            "context": self.context,
        }


def refang(text: str) -> str:
    out = text
    for pattern, repl in _REFANG_PATTERNS:
        out = pattern.sub(repl, out)
    return out


def defang(value: str) -> str:
    """Render an indicator safe to paste into a ticket or chat."""
    return value.replace("http", "hxxp").replace(".", "[.]")


_DOC_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def is_documentation_ip(addr: ipaddress._BaseAddress) -> bool:
    return any(addr in network for network in _DOC_NETWORKS)


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if settings.allow_documentation_ranges and is_documentation_ip(addr):
        return True
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_link_local
        or addr.is_unspecified
    )


def is_plausible_domain(value: str) -> bool:
    value = value.strip(".").lower()
    if "." not in value or len(value) > 253:
        return False
    tld = value.rsplit(".", 1)[-1]
    if tld in _FILE_SUFFIXES or tld.isdigit():
        return False
    # A bare "1.2.3.4" is an IP, never a domain.
    return not _IPV4_RE.fullmatch(value)


def classify(value: str) -> IOCType | None:
    """Classify a single already-refanged indicator string."""
    value = value.strip().strip(",;")
    if not value:
        return None
    if _CVE_RE.fullmatch(value):
        return "cve"
    if _URL_RE.fullmatch(value):
        return "url"
    if _HASH_RE.fullmatch(value):
        return "hash"
    if _EMAIL_RE.fullmatch(value):
        return "email"
    if is_public_ip(value):
        return "ip"
    try:
        ipaddress.ip_address(value)
        return None  # a valid but non-routable address: deliberately dropped
    except ValueError:
        pass
    if is_plausible_domain(value):
        return "domain"
    return None


def hash_algorithm(value: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(value), "unknown")


def url_host(url: str) -> str | None:
    match = re.match(r"https?://(?:[^/@\s]+@)?([^/:\s]+)", url, re.I)
    return match.group(1).lower() if match else None


def _walk_json(node: object, out: list[str]) -> None:
    if isinstance(node, dict):
        for key, val in node.items():
            if isinstance(val, str) and key.lower().replace("-", "_") in _JSON_IOC_KEYS:
                out.append(val)
            _walk_json(val, out)
    elif isinstance(node, list):
        for item in node:
            _walk_json(item, out)
    elif isinstance(node, str):
        out.append(node)


def _context_for(text: str, token: str) -> str:
    idx = text.find(token)
    if idx < 0:
        return ""
    line_start = text.rfind("\n", 0, idx) + 1
    line_end = text.find("\n", idx)
    line = text[line_start: line_end if line_end != -1 else len(text)]
    line = " ".join(line.split())
    return line[:220]


def extract(text: str, *, limit: int | None = None) -> list[Indicator]:
    """Extract de-duplicated, typed indicators from arbitrary analyst input."""
    if not text:
        return []

    candidates: list[str] = []
    stripped = text.strip()
    if stripped.startswith(("{", "[")):
        try:
            _walk_json(json.loads(stripped), candidates)
        except (ValueError, RecursionError):
            candidates.append(text)
    else:
        candidates.append(text)

    haystack = refang("\n".join(candidates))
    found: dict[str, Indicator] = {}

    def add(raw: str, ioc_type: IOCType, normalised: str | None = None) -> None:
        value = (normalised or raw).strip().rstrip(".,;)")
        key = value if ioc_type == "url" else value.lower()
        if key in found:
            return
        found[key] = Indicator(
            value=value if ioc_type in ("url", "cve") else value.lower(),
            type=ioc_type,
            original=raw,
            context=_context_for(haystack, raw),
        )

    urls = _URL_RE.findall(haystack)
    for url in urls:
        add(url, "url")
        host = url_host(url)
        if host and is_public_ip(host):
            add(host, "ip")
        elif host and is_plausible_domain(host):
            add(host, "domain")

    # Blank URLs out so their hosts/paths are not re-extracted as loose IOCs.
    masked = haystack
    for url in urls:
        masked = masked.replace(url, " " * len(url))

    for match in _CVE_RE.findall(masked):
        add(match, "cve", match.upper())
    for match in _HASH_RE.findall(masked):
        add(match, "hash", match.lower())
    for match in _EMAIL_RE.findall(masked):
        add(match, "email", match.lower())
        domain = match.split("@", 1)[1]
        if is_plausible_domain(domain):
            add(domain, "domain")
    for match in _IPV4_RE.findall(masked):
        if is_public_ip(match):
            add(match, "ip")
    for match in _IPV6_RE.findall(masked):
        if is_public_ip(match):
            add(match, "ip", match.lower())
    for match in _DOMAIN_RE.findall(masked):
        if is_plausible_domain(match):
            add(match, "domain")

    indicators = list(found.values())
    order = {"ip": 0, "domain": 1, "url": 2, "hash": 3, "email": 4, "cve": 5}
    indicators.sort(key=lambda i: (order.get(i.type, 9), i.value))
    return indicators[:limit] if limit else indicators


def summarise(indicators: Iterable[Indicator]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for indicator in indicators:
        counts[indicator.type] = counts.get(indicator.type, 0) + 1
    return counts
