"""The four extraction bugs the multi-format corpus found.

Each of these shipped. None was caught by the eight hand-written extractor tests
that existed before, because each needs a log shape those eight did not contain.
They are pinned individually here so a regression names the bug rather than a
percentage; `test_extraction_corpus.py` holds the aggregate.
"""
from __future__ import annotations

import pytest

from app.ioc import extract, is_public_ip


def values(text: str, kind: str | None = None) -> set[str]:
    return {i.value for i in extract(text) if kind is None or i.type == kind}


# ── 1. CGNAT ───────────────────────────────────────────────────────────────
# The README promises "RFC1918, loopback and CGNAT space are dropped before
# anything leaves the building". Python's ipaddress does not flag 100.64.0.0/10
# as private, so it was reaching the providers: a customer's carrier-grade NAT
# address, spending quota and telling a vendor nothing.

@pytest.mark.parametrize("addr", ["100.64.0.1", "100.100.50.20", "100.127.255.254"])
def test_carrier_grade_nat_is_not_a_public_address(addr):
    assert is_public_ip(addr) is False, f"{addr} is CGNAT and must not be queried"


@pytest.mark.parametrize("addr", ["100.63.255.255", "100.128.0.1"])
def test_the_addresses_either_side_of_cgnat_are_still_public(addr):
    """100.64.0.0/10, not 100.0.0.0/8 — the boundary is the whole point."""
    assert is_public_ip(addr) is True


def test_cgnat_is_dropped_out_of_a_real_log_line():
    line = "Jun 04 11:02:55 fw kernel: [UFW BLOCK] SRC=100.64.9.14 DST=192.0.2.7 PROTO=TCP"
    assert "100.64.9.14" not in values(line)


# ── 2. A username with a dot became a domain ───────────────────────────────
# `j.doe` matches the domain pattern and `doe` was not on the file-suffix
# denylist, so it was extracted as a domain and queried. That wastes quota and
# hands a third party an employee's username.

@pytest.mark.parametrize("name", ["j.doe", "k.patel", "a.kumar", "m.o.brien"])
def test_a_username_is_not_a_domain(name):
    assert name not in values(f"user {name} logged on", "domain")


def test_the_domain_in_an_address_is_still_extracted():
    """The fix must not cost the sending domain, which a SOC does want."""
    found = values("From: j.doe@example.com", "domain")
    assert {"example.com"} <= found
    assert "j.doe" not in found


# ── 3. File extensions read as a TLD ───────────────────────────────────────
# The denylist held exe/dll/log/txt but not the extensions a proxy log is full
# of, so `x.php`, `index.html`, `core.dmp` and `web.config` became domains.

@pytest.mark.parametrize("name", [
    "x.php", "index.html", "login.asp", "handler.aspx", "view.jsp",
    "core.dmp", "web.config", "backup.tar", "id_rsa.pub", "dump.sql",
    "archive.gz", "app.apk", "style.woff2", "cert.pem", "notes.md",
])
def test_a_filename_is_not_a_domain(name):
    assert name not in values(f"wrote {name} to disk", "domain")


def test_a_path_full_of_filenames_yields_only_the_host():
    line = 'GET /wp-content/uploads/x.php HTTP/1.1" 200 - "https://cdn.example.com/index.html"'
    found = values(line, "domain")
    assert found == {"cdn.example.com"}, f"unexpected domains: {found - {'cdn.example.com'}}"


# ── 4. An unknown TLD is not a domain ──────────────────────────────────────
# Underneath 2 and 3 is one cause: any dotted string whose last label was not on
# a denylist counted as a domain. A denylist of things that are not TLDs can
# never be complete; the list of things that ARE TLDs is finite and published.

def test_a_real_two_letter_country_code_is_accepted():
    for host in ["example.in", "example.uk", "example.ru", "example.io", "example.co"]:
        assert host in values(f"contacted {host}", "domain"), host


def test_a_common_generic_tld_is_accepted():
    for host in ["example.com", "example.org", "site.xyz", "cdn.top", "api.dev", "x.app"]:
        assert host in values(f"contacted {host}", "domain"), host


def test_a_label_that_is_not_a_tld_is_rejected():
    for junk in ["thing.doe", "file.dmp", "script.php", "name.patel", "build.tmp"]:
        assert junk not in values(f"saw {junk}", "domain"), junk


def test_a_version_string_is_still_not_a_domain():
    assert values("kernel 4.14.0 build 10.0.19041", "domain") == set()


# ── 5. The filename denylist swallowed real TLDs (introduced by fix 3) ─────
# `.zip`, `.mov` and `.sh` are live TLDs *and* common file extensions, and
# attackers register them precisely because of that collision. Rejecting them
# everywhere cost the host of `https://invoice-2026.zip/setup.exe` — the one
# reading where a filename is impossible.
#
# Position resolves it. A label in a URL host, after an `@`, or in an entry the
# analyst submitted as an indicator, is declared to be a hostname; nothing in
# those positions is a file. A bare token scraped out of a log line is not, so
# there the denylist still applies.

@pytest.mark.parametrize("url,host", [
    ("https://invoice-2026.zip/setup.exe", "invoice-2026.zip"),
    ("https://transfer.sh/get/abc123", "transfer.sh"),
    ("https://update.mov/payload", "update.mov"),
    ("https://cdn.example.com/index.html", "cdn.example.com"),
])
def test_a_url_host_is_a_domain_even_when_it_reads_as_a_filename(url, host):
    assert host in values(f"user clicked {url}", "domain")


@pytest.mark.parametrize("name", ["payload.zip", "build.sh", "clip.mov", "notes.md"])
def test_a_bare_filename_in_a_log_line_is_still_not_a_domain(name):
    assert name not in values(f"wrote {name} to disk", "domain")


def test_an_email_domain_is_read_as_declared():
    assert "example.sh" in values("From: hr@example.sh", "domain")


def test_an_explicitly_submitted_indicator_is_read_as_declared():
    """`classify` sees one value the analyst typed into the lookup box."""
    from app.ioc import classify
    assert classify("invoice-2026.zip") == "domain"
    assert classify("transfer.sh") == "domain"
    # The allowlist still rejects it: `exe` is not a TLD in any position.
    assert classify("svchost.exe") is None
