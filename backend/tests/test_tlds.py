"""The hostname allowlist and its refresh path."""
from __future__ import annotations

import pytest

from app import tlds
from app.tlds import SNAPSHOT, is_tld, parse_iana


def test_every_two_letter_label_is_a_country_code():
    for label in ["in", "uk", "ru", "io", "co", "de", "jp", "br"]:
        assert is_tld(label), label


def test_a_longer_label_must_be_on_the_list():
    assert is_tld("com") and is_tld("xyz") and is_tld("dev")
    assert not is_tld("doe")
    assert not is_tld("patel")
    assert not is_tld("config")


def test_punycode_is_accepted_and_bare_unicode_is_not():
    """IDNs reach a log punycoded; raw unicode is not a hostname we can query."""
    assert is_tld("xn--p1ai")
    assert not is_tld("xn--")
    assert not is_tld("москва")


def test_a_label_that_is_not_alphabetic_is_rejected():
    assert not is_tld("123")
    assert not is_tld("woff2")
    assert not is_tld("")
    assert not is_tld("   ")


def test_parse_iana_reads_the_published_format():
    text = "# Version 2026032100\n" + "\n".join(
        [f"T{n:03d}" for n in range(600)] + ["COM", "NET"]
    )
    parsed = parse_iana(text)
    assert "com" in parsed and "net" in parsed
    assert "# version 2026032100" not in parsed


def test_a_truncated_download_is_refused_rather_than_written():
    """An error page parses to a few 'TLDs'. Writing it would drop every domain."""
    with pytest.raises(ValueError, match="expected >=500"):
        parse_iana("<html><body>503 Service Unavailable</body></html>")
    with pytest.raises(ValueError):
        parse_iana("# Version 1\nCOM\nNET\nORG\n")


def test_the_snapshot_alone_is_enough_without_a_refresh(tmp_path, monkeypatch):
    """A fresh checkout with no network still rejects a username."""
    monkeypatch.setattr(tlds, "CACHE_PATH", tmp_path / "absent.txt")
    assert tlds._load() == SNAPSHOT
    assert "doe" not in tlds._load()
    assert "com" in tlds._load()


def test_a_refresh_adds_to_the_snapshot_rather_than_replacing_it(tmp_path, monkeypatch):
    """Union, so a partial list can never drop a TLD the parser relies on."""
    cache = tmp_path / "tlds.txt"
    cache.write_text("\n".join(f"t{n:03d}" for n in range(600)) + "\nquux\n")
    monkeypatch.setattr(tlds, "CACHE_PATH", cache)
    loaded = tlds._load()
    assert "quux" in loaded          # new delegation picked up
    assert loaded >= SNAPSHOT        # nothing from the snapshot lost
