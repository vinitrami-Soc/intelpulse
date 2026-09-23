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
from .tlds import is_tld

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
# Both of the next two were quadratic on input like "a.a.a.a…" or "1.1.1.1…":
# an unbounded repeat ran to the end of the text from every start position, then
# backtracked all the way. 8,000 characters took a second; the 200,000-character
# paste limit would have held a worker for about ten minutes. Bounding each
# repeat to what the standards allow (a 64-character local part, RFC 5321; a
# 253-character host) makes the work per start position constant.
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,24}\b", re.I)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_DOMAIN_RE = re.compile(
    # at most 20 labels before the TLD: far past any real indicator, and finite
    r"\b(?:(?!-)[A-Z0-9-]{1,63}(?<!-)\.){1,20}[A-Z]{2,24}\b", re.I
)

# Extensions and suffixes that look like domains in logs but are not.
_FILE_SUFFIXES = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar", "lnk", "scr",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "zip", "rar", "7z",
    "png", "jpg", "jpeg", "gif", "svg", "ico", "css", "log", "txt", "tmp",
    "dat", "bin", "iso", "msi", "conf", "cfg", "ini", "xml", "yml", "yaml",
    "json", "py", "sh", "db", "sqlite", "local", "localdomain", "internal",
    "corp", "lan", "home", "arpa", "invalid", "example", "test",
    # Web, archive and media extensions a proxy log is full of. Five entries
    # here also pass the TLD check and so depend on this list: `md` (Moldova),
    # `pub`, `zip` and `mov` are real delegations, and `gz` passes the
    # two-letter ccTLD shape rule without being one. In a log line a filename is
    # overwhelmingly the likelier reading of all five, so the denylist wins
    # there — but only there. See `declared` in is_plausible_domain below.
    "html", "htm", "php", "asp", "aspx", "jsp", "cgi", "tar", "gz", "bz2",
    "dmp", "pub", "config", "sql", "apk", "pem", "key", "crt", "md", "woff",
    "woff2", "ttf", "eot", "map", "lock", "bak", "old", "swp", "pid", "sock",
    "mov", "mp3", "mp4", "avi", "wav", "webm", "webp",
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

# Ranges Python's `ipaddress` does not flag but which must never be queried.
# 100.64.0.0/10 is RFC 6598 carrier-grade NAT: it looks routable to `ipaddress`
# and is not. Sending one costs quota and tells a vendor nothing, because the
# address belongs to an ISP's NAT pool and not to any host.
_NON_ROUTABLE = (
    ipaddress.ip_network("100.64.0.0/10"),
)


def is_non_routable(addr: ipaddress._BaseAddress) -> bool:
    return any(addr in network for network in _NON_ROUTABLE)


def is_documentation_ip(addr: ipaddress._BaseAddress) -> bool:
    return any(addr in network for network in _DOC_NETWORKS)


def is_public_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if is_non_routable(addr):
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


def is_plausible_domain(value: str, *, declared: bool = False) -> bool:
    """Is `value` a hostname worth querying?

    `declared` says the string's position already asserts it is a hostname: a
    URL host, the part after an `@`, or an entry the analyst typed into the
    lookup box. Nothing in those positions can be a filename, so the file-suffix
    denylist is skipped there — which is what keeps the host of
    `https://invoice-2026.zip/setup.exe`. `.zip`, `.mov`, `.sh`, `.md` and
    `.pub` are live TLDs as well as file extensions, and are registered by
    attackers precisely because of the collision. A bare token scraped out of a
    log line is not declared, so there `payload.zip` stays a file.

    The TLD allowlist applies either way: `svchost.exe` is not a host in any
    position.
    """
    value = value.strip(".").lower()
    if "." not in value or len(value) > 253:
        return False
    tld = value.rsplit(".", 1)[-1]
    if tld.isdigit():
        return False
    if not declared and tld in _FILE_SUFFIXES:
        return False
    # The last label must be a real TLD. Checking membership of the published
    # list, rather than absence from a list of things that are not TLDs, is
    # what stops `j.doe` and `core.dmp` being sent to a threat-intel vendor:
    # a denylist of non-TLDs can never be complete.
    if not is_tld(tld):
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
    if is_plausible_domain(value, declared=True):
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


def _context_for(text: str, at: int) -> str:
    """The log line surrounding offset `at`.

    Takes an offset rather than the matched token because every caller already
    has one from `finditer`. Searching for the token again cost a scan of the
    whole input per indicator, which on a 5 MB upload was 28% of total runtime.
    Both scans below stop at the nearest newline, so this is O(line), not
    O(input).
    """
    if at < 0:
        return ""
    line_start = text.rfind("\n", 0, at) + 1
    line_end = text.find("\n", at)
    line = text[line_start: line_end if line_end != -1 else len(text)]
    return " ".join(line.split())[:220]


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

    def add(
        raw: str, ioc_type: IOCType, normalised: str | None = None, *, at: int = -1
    ) -> None:
        value = (normalised or raw).strip().rstrip(".,;)")
        key = value if ioc_type == "url" else value.lower()
        if key in found:
            return
        found[key] = Indicator(
            value=value if ioc_type in ("url", "cve") else value.lower(),
            type=ioc_type,
            original=raw,
            context=_context_for(haystack, at),
        )

    url_spans: list[tuple[int, int]] = []
    for match in _URL_RE.finditer(haystack):
        url, at = match.group(0), match.start()
        url_spans.append((at, match.end()))
        add(url, "url", at=at)
        host = url_host(url)
        if host and is_public_ip(host):
            add(host, "ip", at=at)
        elif host and is_plausible_domain(host, declared=True):
            add(host, "domain", at=at)

    # Blank URLs out so their hosts and paths are not re-extracted as loose
    # IOCs, reusing the spans the loop above already found.
    #
    # This used to be one `str.replace` per URL, which rescanned the whole input
    # for every URL and made a 5 MB upload quadratic: 46% of its 14 s runtime.
    # Rebuilding from the spans is a single linear pass, and a second regex pass
    # (`_URL_RE.sub`) would have cost the common case — most calls are one log
    # line with no URL in it at all, and those now skip the work entirely.
    # Spaces keep the length identical, so offsets into `masked` remain valid
    # offsets into `haystack`.
    if url_spans:
        parts: list[str] = []
        prev = 0
        for start, end in url_spans:
            parts.append(haystack[prev:start])
            parts.append(" " * (end - start))
            prev = end
        parts.append(haystack[prev:])
        masked = "".join(parts)
    else:
        masked = haystack

    for match in _CVE_RE.finditer(masked):
        add(match.group(0), "cve", match.group(0).upper(), at=match.start())
    for match in _HASH_RE.finditer(masked):
        add(match.group(0), "hash", match.group(0).lower(), at=match.start())
    for match in _EMAIL_RE.finditer(masked):
        email, at = match.group(0), match.start()
        add(email, "email", email.lower(), at=at)
        domain = email.split("@", 1)[1]
        if is_plausible_domain(domain, declared=True):
            add(domain, "domain", at=at)
    for match in _IPV4_RE.finditer(masked):
        if is_public_ip(match.group(0)):
            add(match.group(0), "ip", at=match.start())
    for match in _IPV6_RE.finditer(masked):
        if is_public_ip(match.group(0)):
            add(match.group(0), "ip", match.group(0).lower(), at=match.start())
    for match in _DOMAIN_RE.finditer(masked):
        if is_plausible_domain(match.group(0)):
            add(match.group(0), "domain", at=match.start())

    indicators = list(found.values())
    order = {"ip": 0, "domain": 1, "url": 2, "hash": 3, "email": 4, "cve": 5}
    indicators.sort(key=lambda i: (order.get(i.type, 9), i.value))
    return indicators[:limit] if limit else indicators


def summarise(indicators: Iterable[Indicator]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for indicator in indicators:
        counts[indicator.type] = counts.get(indicator.type, 0) + 1
    return counts
