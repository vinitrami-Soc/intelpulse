"""The product, privacy, help, about and terms pages (spec 9.5): served to anyone, each with its own title and
description, and offered to search engines only when the owner sets INTELPULSE_INDEX_PUBLIC_PAGES."""
from __future__ import annotations

import re

import pytest

from app.config import settings
from app.web import PUBLIC_PAGES


@pytest.mark.parametrize("page", PUBLIC_PAGES)
async def test_each_page_is_served_to_anyone_with_its_own_title(browser, page):
    answer = await browser.get("/" + page)
    assert answer.status_code == 200 and answer.headers["content-type"].startswith("text/html")
    title = re.search(r"<title>([^<]+)</title>", answer.text).group(1)
    description = re.search(r'<meta name="description" content="([^"]+)"', answer.text).group(1)
    assert title.endswith("· IntelPulse") and len(description) > 80
    assert answer.headers["x-frame-options"] == "DENY"


async def test_the_titles_and_descriptions_differ(browser):
    seen = set()
    for page in PUBLIC_PAGES + ("index.html",):
        text = (await browser.get("/" + page)).text
        seen.add(re.search(r'<meta name="description" content="([^"]+)"', text).group(1))
    assert len(seen) == len(PUBLIC_PAGES) + 1


async def test_by_default_every_crawler_is_turned_away(browser):
    robots = await browser.get("/robots.txt")
    assert robots.status_code == 200 and robots.headers["content-type"].startswith("text/plain")
    assert robots.text == "User-agent: *\nDisallow: /\n"
    assert (await browser.get("/sitemap.xml")).status_code == 404


async def test_with_indexing_on_the_public_pages_are_offered(browser, monkeypatch):
    monkeypatch.setattr(settings, "index_public_pages", True)
    monkeypatch.setattr(settings, "public_url", "https://intel.example.org/")
    robots = (await browser.get("/robots.txt")).text
    assert robots.splitlines() == ["User-agent: *", "Allow: /product.html", "Allow: /privacy.html",
                                   "Allow: /help.html", "Allow: /about.html", "Allow: /terms.html", "Disallow: /",
                                   "Sitemap: https://intel.example.org/sitemap.xml"]
    sitemap = await browser.get("/sitemap.xml")
    assert sitemap.status_code == 200 and sitemap.headers["content-type"].startswith("application/xml")
    locs = re.findall(r"<loc>([^<]+)</loc>", sitemap.text)
    assert locs == [f"https://intel.example.org/{page}" for page in PUBLIC_PAGES]


async def test_without_public_url_the_sitemap_uses_the_request_s_own_address(browser, monkeypatch):
    monkeypatch.setattr(settings, "index_public_pages", True)
    monkeypatch.setattr(settings, "public_url", "")
    sitemap = (await browser.get("/sitemap.xml")).text
    assert "<loc>http://localhost/product.html</loc>" in sitemap


async def test_a_hostile_host_header_is_escaped_in_the_sitemap(browser, monkeypatch):
    monkeypatch.setattr(settings, "index_public_pages", True)
    monkeypatch.setattr(settings, "public_url", "")
    sitemap = (await browser.get("/sitemap.xml", headers={"Host": "evil.example&<x>"})).text
    assert "<x>" not in sitemap


def test_the_switch_reads_the_name_the_spec_gives_it(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("INTELPULSE_INDEX_PUBLIC_PAGES", "true")
    assert Settings().index_public_pages is True
    monkeypatch.delenv("INTELPULSE_INDEX_PUBLIC_PAGES")
    assert Settings(_env_file=None).index_public_pages is False
