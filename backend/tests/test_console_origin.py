"""One origin: the app serves the console's pages beside the API (spec 4)."""
from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import settings
from app.main import create_app
from app.security import SecurityHeadersMiddleware
from app.web import servable


async def test_the_console_is_served_at_the_root(browser):
    page = await browser.get("/")
    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert "<title>IntelPulse" in page.text
    assert (await browser.get("/index.html")).text == page.text


async def test_a_page_gets_the_page_policy_and_the_api_keeps_its_own(browser):
    page = await browser.get("/")
    assert page.headers["content-security-policy"] == SecurityHeadersMiddleware.PAGE_CSP
    for header, value in (("x-frame-options", "DENY"), ("x-content-type-options", "nosniff"),
                          ("referrer-policy", "no-referrer"), ("cache-control", "no-cache")):
        assert page.headers[header] == value
    policy = SecurityHeadersMiddleware.PAGE_CSP
    assert "script-src 'self';" in policy and "frame-ancestors 'none'" in policy
    assert "https:" not in policy and "googleapis" not in policy
    api = await browser.get("/api/health")
    assert api.headers["content-security-policy"] == SecurityHeadersMiddleware.API_CSP


@pytest.mark.parametrize(("path", "kind"), [
    ("/assets/suite.css", "text/css"),
    ("/assets/suite.js", "javascript"),
    ("/assets/fonts.css", "text/css"),
    ("/assets/fonts/outfit-latin-wght-normal.woff2", "font/woff2"),
    ("/assets/fonts/jetbrains-mono-latin-wght-normal.woff2", "font/woff2"),
    ("/workbench.html", "text/html"),
])
async def test_the_pages_assets_are_served(browser, path, kind):
    response = await browser.get(path)
    assert response.status_code == 200, path
    assert kind in response.headers["content-type"]


@pytest.mark.parametrize("path", [
    "/nginx.conf",
    "/tests/engine.test.mjs",
    "/tests/security.spec.mjs",
    "/assets/%2e%2e/nginx.conf",
    "/assets/..%2f..%2fbackend/app/config.py",
    "/%2e%2e/backend/app/config.py",
])
async def test_nothing_else_in_the_folder_or_beside_it_is_served(browser, path):
    response = await browser.get(path)
    assert response.status_code == 404, path


async def test_an_unknown_api_path_is_still_a_json_404(browser):
    response = await browser.get("/api/no-such-thing")
    assert response.status_code == 404
    assert response.json() == {"detail": "Not Found"}


async def test_loading_the_console_does_not_spend_the_api_budget(browser, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_read", 2)
    for _ in range(6):
        assert (await browser.get("/assets/suite.css")).status_code == 200
    answers = [(await browser.get("/api/scoring/model")).status_code for _ in range(3)]
    assert answers[-1] == 429


async def test_without_the_web_folder_the_root_says_what_the_api_is(monkeypatch, tmp_path, clean_db):
    monkeypatch.setattr(settings, "web_dir", tmp_path)  # no index.html there
    api_only = create_app()
    async with AsyncClient(transport=ASGITransport(app=api_only), base_url="http://localhost") as client:
        body = (await client.get("/")).json()
    assert body["docs"] == "/docs" and body["health"] == "/api/health"


@pytest.mark.parametrize(("path", "served"), [
    (".", True), ("index.html", True), ("explorer.html", True), ("assets/suite.css", True),
    ("assets/fonts/outfit-latin-wght-normal.woff2", True),
    ("nginx.conf", False), ("tests/ui.spec.mjs", False), ("../backend/app/config.py", False),
    ("assets", False),
])
def test_what_is_servable(path, served):
    assert servable(path) is served
