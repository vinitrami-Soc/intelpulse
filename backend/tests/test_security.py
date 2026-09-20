"""Security-path tests: egress policy, rate limits, body bounds, log masking.

These assert the controls actually fire. A control nobody tested is a comment.
"""
from __future__ import annotations

import httpx
import pytest

from app.config import settings
from app.logging_config import mask
from app.net import EgressBlocked, assert_allowed, is_blocked_address
from app.security import SlidingWindowLimiter, limiter


@pytest.fixture(autouse=True)
def reset_limiter():
    """The limiter is process-global; tests must not inherit each other's budget."""
    limiter._hits.clear()
    yield
    limiter._hits.clear()


# --------------------------------------------------------------- egress ---
@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1", "10.1.2.3", "192.168.1.10", "172.16.5.4",
        "169.254.169.254",          # cloud metadata — the one that matters
        "100.64.0.1", "0.0.0.0", "::1", "fd00::1",
    ],
)
def test_reserved_space_is_blocked(address):
    assert is_blocked_address(address) is True


@pytest.mark.parametrize("address", ["1.1.1.1", "8.8.8.8", "185.220.101.34", "2606:4700::1111"])
def test_public_space_is_allowed(address):
    assert is_blocked_address(address) is False


@pytest.mark.asyncio
async def test_non_allowlisted_host_is_refused():
    with pytest.raises(EgressBlocked, match="non-allowlisted"):
        await assert_allowed(httpx.URL("https://evil.example.com/steal"))


@pytest.mark.asyncio
async def test_plain_http_is_refused():
    with pytest.raises(EgressBlocked, match="non-HTTPS"):
        await assert_allowed(httpx.URL("http://api.abuseipdb.com/api/v2/check"))


@pytest.mark.asyncio
async def test_metadata_service_is_refused_even_by_ip():
    with pytest.raises(EgressBlocked):
        await assert_allowed(httpx.URL("https://169.254.169.254/latest/meta-data/"))


@pytest.mark.asyncio
async def test_allowlisted_host_resolving_inward_is_refused(monkeypatch):
    """DNS rebinding: the name is fine, the answer is not."""
    async def fake_resolve(host: str):
        return ("127.0.0.1",)

    monkeypatch.setattr("app.net.resolve", fake_resolve)
    with pytest.raises(EgressBlocked, match="non-routable"):
        await assert_allowed(httpx.URL("https://api.abuseipdb.com/api/v2/check"))


@pytest.mark.asyncio
async def test_allowlisted_host_resolving_publicly_is_allowed(monkeypatch):
    async def fake_resolve(host: str):
        return ("104.26.1.1",)

    monkeypatch.setattr("app.net.resolve", fake_resolve)
    await assert_allowed(httpx.URL("https://api.abuseipdb.com/api/v2/check"))


def test_every_feed_and_provider_host_is_allowlisted():
    """A new source must be added to the allowlist deliberately, not by accident."""
    import re

    from app.net import ALLOWED_HOSTS
    from app.services import feeds

    sources = [getattr(feeds, name) for name in dir(feeds) if name.isupper()]
    urls = [value for value in sources if isinstance(value, str) and value.startswith("http")]
    assert urls, "expected feed URLs to inspect"
    for url in urls:
        host = re.sub(r"^https?://", "", url).split("/")[0]
        assert host in ALLOWED_HOSTS, f"{host} is used but not allowlisted"


# ----------------------------------------------------------- rate limits ---
def test_sliding_window_blocks_then_recovers():
    limiter = SlidingWindowLimiter()
    for _ in range(3):
        allowed, _, _ = limiter.check("k", limit=3, window=60)
        assert allowed
    allowed, remaining, retry_after = limiter.check("k", limit=3, window=60)
    assert allowed is False and remaining == 0 and retry_after >= 1

    # A tiny window expires immediately, proving the window slides.
    limiter2 = SlidingWindowLimiter()
    assert limiter2.check("k", limit=1, window=0.001)[0] is True
    import time

    time.sleep(0.01)
    assert limiter2.check("k", limit=1, window=0.001)[0] is True


def test_rate_limit_keys_are_per_client():
    limiter = SlidingWindowLimiter()
    assert limiter.check("triage:1.1.1.1", 1, 60)[0] is True
    assert limiter.check("triage:1.1.1.1", 1, 60)[0] is False
    assert limiter.check("triage:2.2.2.2", 1, 60)[0] is True


def test_buckets_match_what_each_endpoint_actually_costs():
    """Enrichment spends vendor quota; parsing and health checks do not."""
    from starlette.datastructures import Headers
    from starlette.requests import Request

    from app.security import RateLimitMiddleware

    middleware = RateLimitMiddleware(app=None)

    def fake(method: str, path: str) -> Request:
        return Request(
            {
                "type": "http", "method": method, "path": path, "query_string": b"",
                "headers": Headers({}).raw, "client": ("1.1.1.1", 1234),
            }
        )

    assert middleware._limit_for(fake("POST", "/api/triage"))[0] == "triage"
    assert middleware._limit_for(fake("POST", "/api/triage/report"))[0] == "triage"
    assert middleware._limit_for(fake("POST", "/api/intel/feeds/nvd/refresh"))[0] == "triage"
    assert middleware._limit_for(fake("POST", "/api/extract"))[0] == "write"
    assert middleware._limit_for(fake("GET", "/api/health"))[0] == "read"
    assert settings.rate_limit_triage < settings.rate_limit_write < settings.rate_limit_read


@pytest.mark.asyncio
async def test_endpoint_returns_429_with_retry_after(client, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_write", 2)
    responses = [await client.post("/api/extract", json={"text": "8.8.8.8"}) for _ in range(4)]
    assert [r.status_code for r in responses[:2]] == [200, 200]
    limited = responses[-1]
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1
    assert limited.headers["X-RateLimit-Remaining"] == "0"
    assert "rate limit exceeded" in limited.json()["detail"]


@pytest.mark.asyncio
async def test_read_endpoints_keep_their_own_budget(client, monkeypatch):
    """A burst of writes must not starve the dashboard's health polling."""
    monkeypatch.setattr(settings, "rate_limit_write", 1)
    await client.post("/api/extract", json={"text": "8.8.8.8"})
    assert (await client.post("/api/extract", json={"text": "8.8.8.8"})).status_code == 429
    assert (await client.get("/api/health")).status_code == 200


@pytest.mark.asyncio
async def test_forwarded_for_is_ignored_unless_trusted(client, monkeypatch):
    """Otherwise every attacker mints a new identity per request."""
    monkeypatch.setattr(settings, "rate_limit_write", 1)
    monkeypatch.setattr(settings, "trust_forwarded_for", False)
    await client.post("/api/extract", json={"text": "8.8.8.8"})
    spoofed = await client.post(
        "/api/extract", json={"text": "8.8.8.8"}, headers={"X-Forwarded-For": "9.9.9.9"}
    )
    assert spoofed.status_code == 429


# ------------------------------------------------------------- payloads ---
@pytest.mark.asyncio
async def test_oversized_body_is_rejected_before_parsing(client):
    payload = {"text": "8.8.8.8 " * 200_000}
    response = await client.post("/api/triage", json=payload)
    assert response.status_code in (413, 422)


@pytest.mark.asyncio
async def test_input_length_is_bounded(client):
    response = await client.post("/api/extract", json={"text": "a" * 250_000})
    assert response.status_code in (413, 422)


@pytest.mark.asyncio
async def test_malformed_json_returns_422_not_500(client):
    response = await client.post(
        "/api/triage", content=b'{"text": "8.8.8.8", ', headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_binary_garbage_does_not_crash_extraction(client):
    response = await client.post(
        "/api/extract", json={"text": "\x00�\x1b[31m" + "‮" * 100 + "8.8.8.8"}
    )
    assert response.status_code == 200
    assert response.json()["count"] == 1


@pytest.mark.asyncio
async def test_ten_thousand_indicators_are_capped_not_crashed(client):
    text = " ".join(f"185.220.{i // 256 % 256}.{i % 256}" for i in range(10_000))
    response = await client.post("/api/extract", json={"text": text[: settings.max_input_chars]})
    assert response.status_code == 200
    assert response.json()["count"] <= settings.max_iocs_per_request


# --------------------------------------------------------------- headers ---
@pytest.mark.asyncio
async def test_security_headers_are_present(client):
    response = await client.get("/api/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Request-ID"]


# --------------------------------------------------------- log redaction ---
def test_configured_secret_values_are_masked(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abcd1234secretkey")
    assert "abcd1234secretkey" not in mask("calling vendor with key abcd1234secretkey")


@pytest.mark.parametrize(
    "line",
    [
        "GET https://api.greynoise.io/v3/community/1.1.1.1?key=SUPERSECRETVALUE",
        "headers={'Key': 'SUPERSECRETVALUE'}",
        "Authorization: Bearer SUPERSECRETVALUE",
        "postgresql+asyncpg://intelpulse:SUPERSECRETVALUE@db:5432/intelpulse",
        'api_key="SUPERSECRETVALUE"',
    ],
)
def test_credential_shaped_text_is_masked(line):
    assert "SUPERSECRETVALUE" not in mask(line)


def test_masking_leaves_ordinary_log_lines_intact():
    line = "triage completed for 185.220.101.34 in 612ms (verdict=critical)"
    assert mask(line) == line
