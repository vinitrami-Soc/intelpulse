"""Deterministic generator for the multi-format extraction corpus.

Each format function returns (text, expected) where `expected` is the set of
(value, type) pairs the extractor is contracted to produce for that text.
Read the package docstring for why the content is synthetic and the framing is
not.
"""
from __future__ import annotations

import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# ── the pools ───────────────────────────────────────────────────────────────
# Documentation space (RFC 5737). Extracted when allow_documentation_ranges is
# on, which is how the corpus test runs — see the package docstring.
DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")

# Never extracted, whatever the settings: RFC 1918, loopback, link-local, CGNAT,
# multicast. These are the precision traps.
PRIVATE = [
    "10.0.0.5", "10.14.22.199", "172.16.4.9", "172.31.255.1", "192.168.1.1",
    "192.168.50.240", "127.0.0.1", "169.254.169.254", "100.64.0.1", "224.0.0.251",
    "0.0.0.0", "255.255.255.255",
]

# RFC 2606 reserved. Subdomains give the parser depth to chew on.
SUBS = [
    "cdn", "static", "api", "mail", "vpn", "secure-login", "update-07", "ns1",
    "portal", "auth", "files", "img-cache", "edge-03", "mx1", "autodiscover",
]
APEX = ["example.com", "example.net", "example.org"]

# Things that look like domains in a log and are not. _FILE_SUFFIXES in
# app/ioc.py is what should reject these.
FILENAMES = [
    "svchost.exe", "rundll32.exe", "powershell.exe", "config.ini", "app.log",
    "update.dll", "payload.zip", "report.pdf", "index.html", "styles.css",
    "notes.txt", "backup.tar", "core.dmp", "web.config", "id_rsa.pub",
    # Extensions that are also live TLDs. A bare one in a log line is a file;
    # the same label in a URL host is a domain. The split is pinned by name in
    # tests/test_extraction_findings.py, section 5.
    "clip.mov", "build.sh", "notes.md", "archive.gz", "dump.sql", "app.apk",
]
VERSIONS = ["1.2.3", "10.0.19041", "4.14.0", "2.31.1", "8.0.302", "7.9.5"]

HEX = "0123456789abcdef"
USERS = ["j.doe", "payroll", "admin", "svc_backup", "k.patel", "noreply", "hr"]
PORTS = [80, 443, 8080, 8443, 53, 25, 587, 3389, 445, 22, 4444, 8888]
CVES = [
    "CVE-2021-44228", "CVE-2014-0160", "CVE-2017-0144", "CVE-2023-23397",
    "CVE-2019-0708", "CVE-2020-1472", "CVE-2022-30190",
]
PATHS = [
    "/owa/session", "/wp-content/uploads/x.php", "/api/v2/token", "/beacon.bin",
    "/download/setup", "/cgi-bin/status", "/assets/loader", "/j_spring_security_check",
]
MALWARE = ["SampleLoader", "SampleBot", "SamplePhishKit", "SampleStealer", "SampleRAT"]

BASE_TIME = datetime(2026, 3, 14, 9, 0, 0)


def contract_expand(pairs: set[tuple[str, str]]) -> set[tuple[str, str]]:
    """Apply the extractor's documented contract to a hand-written expectation.

    A URL yields its host as a domain too, and an email yields its domain — a
    SOC wants the sending domain, not only the address. Writing that out by hand
    at every call site invites the expectation to drift from the contract, so it
    is derived here once.
    """
    out = set(pairs)
    for value, kind in pairs:
        if kind == "url":
            host = value.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
            if host:
                out.add((host.lower(), "domain"))
        elif kind == "email":
            domain = value.rsplit("@", 1)[-1]
            if domain:
                out.add((domain.lower(), "domain"))
    return out


@dataclass
class CorpusLine:
    """One log line plus the indicators the extractor is contracted to find."""

    fmt: str
    text: str
    expect: set[tuple[str, str]] = field(default_factory=set)
    # Values present in the text that must NOT be extracted. Kept for the
    # report, so a false positive can be named as "the trap it fell for".
    traps: set[str] = field(default_factory=set)

    def __post_init__(self) -> None:
        self.expect = contract_expand(self.expect)


class Gen:
    """Seeded source of every value the formats need."""

    def __init__(self, seed: int) -> None:
        self.r = random.Random(seed)
        self.n = 0

    # -- primitives ------------------------------------------------------
    def doc_ip(self) -> str:
        return self.r.choice(DOC_NETS) + str(self.r.randint(1, 254))

    def private_ip(self) -> str:
        return self.r.choice(PRIVATE)

    def domain(self) -> str:
        return f"{self.r.choice(SUBS)}.{self.r.choice(APEX)}"

    def url(self) -> str:
        scheme = self.r.choice(["http", "https"])
        return f"{scheme}://{self.domain()}{self.r.choice(PATHS)}"

    def hash_(self, length: int | None = None) -> str:
        length = length or self.r.choice([32, 40, 64])
        return "".join(self.r.choice(HEX) for _ in range(length))

    def email(self) -> str:
        return f"{self.r.choice(USERS)}@{self.r.choice(APEX)}"

    def port(self) -> int:
        return self.r.choice(PORTS)

    def when(self) -> datetime:
        self.n += 1
        return BASE_TIME + timedelta(seconds=self.n * 7)

    def maybe_trap(self) -> tuple[str, str]:
        """A value that looks extractable and is not. Returns (kind, value)."""
        kind = self.r.choice(["private", "filename", "version"])
        if kind == "private":
            return kind, self.private_ip()
        if kind == "filename":
            return kind, self.r.choice(FILENAMES)
        return kind, self.r.choice(VERSIONS)


# ── the formats ─────────────────────────────────────────────────────────────
# Each takes the generator and returns a CorpusLine. The framing is what these
# products actually emit; only the values inside it are synthetic.

def cisco_asa(g: Gen) -> CorpusLine:
    src, dst = g.private_ip(), g.doc_ip()
    sport, dport = g.r.randint(1024, 65535), g.port()
    t = g.when().strftime("%b %d %Y %H:%M:%S")
    text = (
        f"{t}: %ASA-6-302013: Built outbound TCP connection {g.r.randint(10000, 99999)} "
        f"for outside:{dst}/{dport} ({dst}/{dport}) to inside:{src}/{sport} ({src}/{sport})"
    )
    return CorpusLine("cisco_asa", text, {(dst, "ip")}, {src})


def cisco_asa_deny(g: Gen) -> CorpusLine:
    src = g.doc_ip()
    dst = g.private_ip()
    t = g.when().strftime("%b %d %Y %H:%M:%S")
    text = (
        f"{t}: %ASA-4-106023: Deny tcp src outside:{src}/{g.r.randint(1024, 65535)} "
        f"dst inside:{dst}/{g.port()} by access-group \"outside_access_in\""
    )
    return CorpusLine("cisco_asa", text, {(src, "ip")}, {dst})


def panos_traffic(g: Gen) -> CorpusLine:
    """PAN-OS writes CSV. Commas inside the line are the parser hazard."""
    src, dst = g.private_ip(), g.doc_ip()
    t = g.when().strftime("%Y/%m/%d %H:%M:%S")
    text = (
        f"1,{t},001801000001,TRAFFIC,end,2049,{t},{src},{dst},0.0.0.0,0.0.0.0,"
        f"rule-allow-web,,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,"
        f"log-forward,{t},{g.r.randint(1000, 9999)},1,{g.r.randint(1024, 65535)},{g.port()},"
        f"0,0,0x19,tcp,allow,{g.r.randint(500, 90000)},1234,5678,12,{t},0,any,0"
    )
    return CorpusLine("panos", text, {(dst, "ip")}, {src, "0.0.0.0"})


def panos_threat(g: Gen) -> CorpusLine:
    src, dst = g.doc_ip(), g.private_ip()
    url = g.url()
    t = g.when().strftime("%Y/%m/%d %H:%M:%S")
    text = (
        f"1,{t},001801000001,THREAT,url,2049,{t},{src},{dst},0.0.0.0,0.0.0.0,"
        f"rule-block-c2,,,web-browsing,vsys1,untrust,trust,ethernet1/1,ethernet1/2,"
        f"log-forward,{t},0,1,{g.port()},{g.port()},0,0,0x0,tcp,block-url,\"{url}\","
        f"(9999),malware,critical,client-to-server"
    )
    return CorpusLine("panos", text, {(src, "ip"), (url, "url")}, {dst, "0.0.0.0"})


def fortigate(g: Gen) -> CorpusLine:
    """FortiGate writes key=value, some values quoted."""
    src, dst = g.private_ip(), g.doc_ip()
    host = g.domain()
    t = g.when()
    text = (
        f'date={t:%Y-%m-%d} time={t:%H:%M:%S} devname="FG100E" devid="FG100E0000000000" '
        f'logid="0000000013" type="traffic" subtype="forward" level="notice" '
        f'srcip={src} srcport={g.r.randint(1024, 65535)} srcintf="port1" '
        f'dstip={dst} dstport={g.port()} dstintf="wan1" '
        f'hostname="{host}" action="blocked" policyid=12 service="HTTPS" '
        f'appcat="unscanned" sentbyte={g.r.randint(100, 9000)}'
    )
    return CorpusLine("fortigate", text, {(dst, "ip"), (host, "domain")}, {src})


def suricata_eve(g: Gen) -> CorpusLine:
    src, dst = g.doc_ip(), g.private_ip()
    host = g.domain()
    payload = {
        "timestamp": g.when().isoformat() + "+0000",
        "flow_id": g.r.randint(10**14, 10**15),
        "event_type": "alert",
        "src_ip": src,
        "src_port": g.r.randint(1024, 65535),
        "dest_ip": dst,
        "dest_port": g.port(),
        "proto": "TCP",
        "alert": {
            "action": "blocked",
            "signature": f"ET MALWARE {g.r.choice(MALWARE)} CnC Activity",
            "category": "A Network Trojan was detected",
            "severity": 1,
        },
        "http": {"hostname": host, "url": g.r.choice(PATHS), "http_user_agent": "curl/7.68.0"},
    }
    return CorpusLine(
        "suricata_eve", json.dumps(payload), {(src, "ip"), (host, "domain")}, {dst}
    )


def zeek_conn(g: Gen) -> CorpusLine:
    """Zeek conn.log is tab-separated. Column boundaries are the hazard."""
    src, dst = g.private_ip(), g.doc_ip()
    t = g.when().timestamp()
    cols = [
        f"{t:.6f}", "C" + "".join(g.r.choice(HEX) for _ in range(12)),
        src, str(g.r.randint(1024, 65535)), dst, str(g.port()),
        "tcp", "http", f"{g.r.random() * 10:.6f}",
        str(g.r.randint(100, 9000)), str(g.r.randint(100, 9000)),
        "SF", "-", "-", "0", "ShADadFf",
        str(g.r.randint(2, 40)), str(g.r.randint(200, 4000)),
        str(g.r.randint(2, 40)), str(g.r.randint(200, 4000)), "-",
    ]
    return CorpusLine("zeek_conn", "\t".join(cols), {(dst, "ip")}, {src})


def windows_event_json(g: Gen) -> CorpusLine:
    """EVTX exported to JSON. Windows writes '-' for an absent value."""
    ip = g.doc_ip()
    sha = g.hash_(64)
    payload = {
        "EventID": g.r.choice([4624, 4625, 4688]),
        "Computer": f"WKSTN-{g.r.randint(100, 999)}.{g.r.choice(APEX)}",
        "TimeCreated": g.when().isoformat(),
        "EventData": {
            "TargetUserName": g.r.choice(USERS),
            "IpAddress": ip,
            "IpPort": str(g.port()),
            "LogonType": "3",
            "ProcessName": "C:\\\\Windows\\\\System32\\\\" + g.r.choice(FILENAMES),
            "WorkstationName": "-",
            "Hashes": f"SHA256={sha}",
        },
    }
    computer = payload["Computer"]
    return CorpusLine(
        "windows_event_json",
        json.dumps(payload),
        {(ip, "ip"), (sha, "hash"), (computer.lower(), "domain")},
        {payload["EventData"]["ProcessName"].rsplit("\\\\", 1)[-1]},
    )


def sysmon_json(g: Gen) -> CorpusLine:
    md5, sha = g.hash_(32), g.hash_(256 // 4)
    dst = g.doc_ip()
    payload = {
        "EventID": 3,
        "UtcTime": g.when().isoformat(),
        "Image": "C:\\\\Users\\\\Public\\\\" + g.r.choice(FILENAMES),
        "Hashes": f"MD5={md5},SHA256={sha}",
        "DestinationIp": dst,
        "DestinationPort": g.port(),
        "DestinationHostname": g.domain(),
        "Initiated": "true",
    }
    host = payload["DestinationHostname"]
    return CorpusLine(
        "sysmon_json",
        json.dumps(payload),
        {(dst, "ip"), (md5, "hash"), (sha, "hash"), (host, "domain")},
        {payload["Image"].rsplit("\\\\", 1)[-1]},
    )


def cloudtrail(g: Gen) -> CorpusLine:
    ip = g.doc_ip()
    payload = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "arn": f"arn:aws:iam::123456789012:user/{g.r.choice(USERS)}",
            "userName": g.r.choice(USERS),
        },
        "eventTime": g.when().isoformat() + "Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "awsRegion": "ap-south-1",
        "sourceIPAddress": ip,
        "userAgent": "Mozilla/5.0",
        "responseElements": {"ConsoleLogin": "Failure"},
    }
    return CorpusLine(
        "cloudtrail", json.dumps(payload),
        {(ip, "ip"), ("signin.amazonaws.com", "domain")}, set(),
    )


def squid(g: Gen) -> CorpusLine:
    src = g.private_ip()
    url = g.url()
    t = g.when().timestamp()
    text = (
        f"{t:.3f} {g.r.randint(50, 900)} {src} TCP_DENIED/403 {g.r.randint(200, 9000)} "
        f"GET {url} - HIER_NONE/- text/html"
    )
    return CorpusLine("squid", text, {(url, "url")}, {src})


def nginx_combined(g: Gen) -> CorpusLine:
    ip = g.doc_ip()
    ref = g.url()
    t = g.when().strftime("%d/%b/%Y:%H:%M:%S +0530")
    text = (
        f'{ip} - - [{t}] "GET {g.r.choice(PATHS)} HTTP/1.1" '
        f'{g.r.choice([200, 301, 403, 404, 500])} {g.r.randint(200, 9000)} '
        f'"{ref}" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
    )
    return CorpusLine("nginx", text, {(ip, "ip"), (ref, "url")}, set())


def mail_header(g: Gen) -> CorpusLine:
    sender, rcpt = g.email(), g.email()
    ip = g.doc_ip()
    host = g.domain()
    relay = f"mx.{g.r.choice(APEX)}"
    text = (
        f"Received: from {host} ({host} [{ip}]) by {relay} with ESMTPS "
        f"id {g.hash_(16)} for <{rcpt}>; {g.when():%a, %d %b %Y %H:%M:%S} +0530\n"
        f"From: {sender}\nSubject: Payroll update required\n"
        f"X-Spam-Status: Yes, score={g.r.uniform(5, 15):.1f}"
    )
    return CorpusLine(
        "mail_header", text,
        {(sender, "email"), (rcpt, "email"), (ip, "ip"),
         (host, "domain"), (relay, "domain")},
        set(),
    )


def ufw_kernel(g: Gen) -> CorpusLine:
    src, dst = g.doc_ip(), g.private_ip()
    t = g.when().strftime("%b %d %H:%M:%S")
    text = (
        f"{t} fw-edge-01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e "
        f"SRC={src} DST={dst} LEN={g.r.randint(40, 1500)} TOS=0x00 PREC=0x00 "
        f"TTL={g.r.randint(40, 128)} ID={g.r.randint(1, 65535)} PROTO=TCP "
        f"SPT={g.r.randint(1024, 65535)} DPT={g.port()} WINDOW=1024 RES=0x00 SYN URGP=0"
    )
    return CorpusLine("ufw_kernel", text, {(src, "ip")}, {dst})


def defanged_report(g: Gen) -> CorpusLine:
    """Threat-report prose. Defanging is the whole point of this format."""
    ip, host = g.doc_ip(), g.domain()
    sha = g.hash_(64)
    cve = g.r.choice(CVES)
    path = g.r.choice(PATHS)
    # Written defanged, expected refanged — that round trip is what is tested.
    defanged_url = f"hxxps://{host.replace('.', '[.]')}{path}"
    text = (
        f"The loader beacons to {ip.replace('.', '[.]')} over port {g.port()} and "
        f"retrieves a second stage from {defanged_url}. The dropper "
        f"(SHA256 {sha}) exploits {cve}. Infrastructure overlaps with "
        f"{g.r.choice(MALWARE)} reporting from earlier this year."
    )
    return CorpusLine(
        "defanged_report",
        text,
        {(ip, "ip"), (sha, "hash"), (cve.upper(), "cve"),
         (f"https://{host}{path}", "url")},
        set(),
    )


def ioc_list(g: Gen) -> CorpusLine:
    """The simplest shape: a list pasted out of a ticket."""
    ip, host, sha, mail = g.doc_ip(), g.domain(), g.hash_(64), g.email()
    trap_kind, trap = g.maybe_trap()
    text = "\n".join([ip, host, sha, mail, trap])
    return CorpusLine(
        "ioc_list", text,
        {(ip, "ip"), (host, "domain"), (sha, "hash"), (mail, "email")},
        {trap},
    )


def mixed_paste(g: Gen) -> CorpusLine:
    """Half a ticket and half a log, which is what people actually paste."""
    ip, url, sha = g.doc_ip(), g.url(), g.hash_(40)
    trap_kind, trap = g.maybe_trap()
    text = (
        f"Ticket SOC-{g.r.randint(1000, 9999)}: blocked outbound to {ip}\n"
        f"Proxy line: GET {url} 403\n"
        f"Hash from EDR: {sha}\n"
        f"Process: {trap}\n"
        f"Analyst: please confirm"
    )
    return CorpusLine("mixed_paste", text, {(ip, "ip"), (url, "url"), (sha, "hash")}, {trap})


FORMATS = [
    cisco_asa, cisco_asa_deny, panos_traffic, panos_threat, fortigate,
    suricata_eve, zeek_conn, windows_event_json, sysmon_json, cloudtrail,
    squid, nginx_combined, mail_header, ufw_kernel, defanged_report,
    ioc_list, mixed_paste,
]


def build_corpus(lines: int = 3400, seed: int = 20260314) -> list[CorpusLine]:
    """`lines` log lines spread evenly across every format, deterministically."""
    g = Gen(seed)
    out: list[CorpusLine] = []
    while len(out) < lines:
        for fmt in FORMATS:
            if len(out) >= lines:
                break
            out.append(fmt(g))
    return out
