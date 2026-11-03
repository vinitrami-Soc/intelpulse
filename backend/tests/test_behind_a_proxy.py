"""Behind the deploy kit's Cloudflare Tunnel (docs/DEPLOY.md): the browser is on https://PUBLIC_URL
while the app sees http://, and the client's address arrives in a header only Cloudflare sets."""
from __future__ import annotations

import pytest
from starlette.datastructures import Headers

from app.config import settings
from app.security import client_ip, public_origin

BLOCK = {"value": "8.8.4.4", "list_type": "block"}


async def test_a_write_from_the_public_address_is_the_server_s_own(client, monkeypatch):
    # without PUBLIC_URL an https:// page writing to an app that sees http:// is a foreign origin
    assert (await client.post("/api/lists", headers={"Origin": "https://intel.example.org"}, json=BLOCK)).status_code == 403
    monkeypatch.setattr(settings, "public_url", "https://intel.example.org/")
    answer = await client.post("/api/lists", headers={"Origin": "https://intel.example.org"}, json=BLOCK)
    assert answer.status_code in (200, 201), answer.text


@pytest.mark.parametrize("origin", ["http://intel.example.org", "https://intel.example.org.evil.example",
                                    "https://evil.example", "null"])
async def test_only_that_exact_origin_counts(client, monkeypatch, origin):
    monkeypatch.setattr(settings, "public_url", "https://intel.example.org")
    assert (await client.post("/api/lists", headers={"Origin": origin}, json=BLOCK)).status_code == 403


@pytest.mark.parametrize(("url", "origin"), [
    ("https://intel.example.org/", {"https://intel.example.org"}),
    ("https://intel.example.org:8443/soc", {"https://intel.example.org:8443"}),
    ("", set()), ("intel.example.org", set()), ("javascript:alert(1)", set()),
])
def test_the_public_origin_is_scheme_and_host_or_nothing(monkeypatch, url, origin):
    monkeypatch.setattr(settings, "public_url", url)
    assert public_origin() == origin


class _Request:
    def __init__(self, headers: dict[str, str], host: str = "172.18.0.7") -> None:
        self.headers = Headers(headers)   # case-insensitive, as a real request's are
        self.client = type("Peer", (), {"host": host})()


def test_the_named_header_is_the_client_and_x_forwarded_for_is_not(monkeypatch):
    monkeypatch.setattr(settings, "trust_forwarded_for", True)
    monkeypatch.setattr(settings, "client_ip_header", "CF-Connecting-IP")
    spoofed = _Request({"X-Forwarded-For": "203.0.113.66, 198.51.100.9", "CF-Connecting-IP": "198.51.100.9"})
    assert client_ip(spoofed) == "198.51.100.9"
    # a request that did not come through Cloudflare (the container's own healthcheck) is its socket
    assert client_ip(_Request({"X-Forwarded-For": "203.0.113.66"})) == "172.18.0.7"


def test_the_header_means_nothing_unless_forwarding_is_trusted(monkeypatch):
    monkeypatch.setattr(settings, "trust_forwarded_for", False)
    monkeypatch.setattr(settings, "client_ip_header", "CF-Connecting-IP")
    assert client_ip(_Request({"CF-Connecting-IP": "198.51.100.9"})) == "172.18.0.7"


async def test_each_address_cloudflare_names_has_its_own_bucket(client, monkeypatch):
    monkeypatch.setattr(settings, "trust_forwarded_for", True)
    monkeypatch.setattr(settings, "client_ip_header", "CF-Connecting-IP")
    monkeypatch.setattr(settings, "rate_limit_write", 1)
    one = {"CF-Connecting-IP": "198.51.100.1"}
    assert (await client.post("/api/extract", json={"text": "8.8.8.8"}, headers=one)).status_code == 200
    assert (await client.post("/api/extract", json={"text": "8.8.8.8"}, headers=one)).status_code == 429
    # a forged X-Forwarded-For mints no new identity
    forged = {**one, "X-Forwarded-For": "203.0.113.200"}
    assert (await client.post("/api/extract", json={"text": "8.8.8.8"}, headers=forged)).status_code == 429
    other = {"CF-Connecting-IP": "198.51.100.2"}
    assert (await client.post("/api/extract", json={"text": "8.8.8.8"}, headers=other)).status_code == 200
