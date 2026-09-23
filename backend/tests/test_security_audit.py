"""Regression tests for the 2026 security audit (docs/SECURITY-AUDIT.md).

Each test pins one finding: it was written against the vulnerable behaviour,
seen to fail there, and passes against the fix. The finding it guards is named
in the docstring so a failure here points straight at the write-up.
"""
from __future__ import annotations

import re
import time

import pytest

from app.config import settings
from app.ioc import extract
from app.security import limiter
from app.text import clean_label, md_text

EVIL = "https://evil.example"
DASHBOARD = "http://localhost:8080"


@pytest.fixture(autouse=True)
def reset_limiter():
    limiter._hits.clear()
    yield
    limiter._hits.clear()


# ───────────────────────────── F1 — any page could drive the local API (A01)
@pytest.mark.asyncio
async def test_preflight_from_a_foreign_origin_gets_no_cors_grant(client):
    """F1: CORS was "*", so any site's script could read every response."""
    response = await client.options(
        "/api/lists",
        headers={"Origin": EVIL, "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "content-type"},
    )
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.asyncio
async def test_preflight_from_the_dashboard_is_granted(client):
    response = await client.options(
        "/api/lists",
        headers={"Origin": DASHBOARD, "Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "content-type,authorization"},
    )
    assert response.headers.get("access-control-allow-origin") == DASHBOARD
    assert "authorization" in response.headers.get("access-control-allow-headers", "").lower()


@pytest.mark.asyncio
async def test_a_foreign_page_cannot_allowlist_an_address(client):
    """F1: proven end to end — a write from another origin allowlisted an
    attacker's address, and the next triage called it safe."""
    response = await client.post(
        "/api/lists", headers={"Origin": EVIL},
        json={"value": "185.220.101.34", "list_type": "allow", "reason": "looks internal"},
    )
    assert response.status_code == 403
    assert (await client.get("/api/lists")).json() == []


@pytest.mark.asyncio
async def test_a_simple_request_cannot_slip_past_cors(client):
    """F1: CORS never stopped a form post; a multipart upload needs no preflight."""
    response = await client.post(
        "/api/triage/upload", headers={"Origin": EVIL},
        files={"file": ("x.log", b"SRC=185.220.101.34", "text/plain")},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_fetch_metadata_marks_a_cross_site_write_without_an_origin(client):
    response = await client.post(
        "/api/intel/cache/invalidate", headers={"Sec-Fetch-Site": "cross-site"}, json={}
    )
    assert response.status_code == 403


@pytest.mark.asyncio
@pytest.mark.parametrize("origin", ["null", "https://vinitrami-soc.github.io.evil.example"])
async def test_lookalike_and_null_origins_are_refused(client, origin):
    response = await client.post("/api/lists", headers={"Origin": origin}, json={"value": "8.8.4.4"})
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_the_dashboard_and_non_browser_clients_can_still_write(client):
    from_dashboard = await client.post(
        "/api/lists", headers={"Origin": DASHBOARD}, json={"value": "8.8.4.4", "list_type": "block"}
    )
    from_curl = await client.post("/api/lists", json={"value": "1.0.0.1", "list_type": "block"})
    assert (from_dashboard.status_code, from_curl.status_code) == (201, 201)


@pytest.mark.asyncio
async def test_reads_from_a_foreign_origin_are_answered_but_not_shared(client):
    """A GET changes nothing; CORS alone decides whether the page may read it."""
    response = await client.get("/api/lists", headers={"Origin": EVIL})
    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


# ─────────────────────────────────── F2 — no way to require credentials (A07)
@pytest.mark.asyncio
async def test_with_a_token_configured_every_data_route_requires_it(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "s3cret-token-for-tests")
    missing = await client.get("/api/cases")
    wrong = await client.get("/api/cases", headers={"Authorization": "Bearer s3cret-token-for-test"})
    other_scheme = await client.get("/api/cases", headers={"Authorization": "Basic s3cret-token-for-tests"})
    right = await client.get("/api/cases", headers={"Authorization": "Bearer s3cret-token-for-tests"})
    assert (missing.status_code, wrong.status_code, other_scheme.status_code) == (401, 401, 401)
    assert missing.headers["www-authenticate"].startswith("Bearer")
    assert right.status_code == 200


@pytest.mark.asyncio
async def test_health_and_preflight_stay_open_with_a_token(client, monkeypatch):
    monkeypatch.setattr(settings, "api_token", "s3cret-token-for-tests")
    assert (await client.get("/api/health")).status_code == 200
    preflight = await client.options(
        "/api/triage", headers={"Origin": DASHBOARD, "Access-Control-Request-Method": "POST"}
    )
    assert preflight.status_code == 200


@pytest.mark.asyncio
async def test_a_refusal_is_readable_by_the_dashboard(client, monkeypatch):
    """CORS sits outside the guards, so the dashboard sees "401", not a network error."""
    monkeypatch.setattr(settings, "api_token", "s3cret-token-for-tests")
    response = await client.get("/api/cases", headers={"Origin": DASHBOARD})
    assert response.status_code == 401
    assert response.headers.get("access-control-allow-origin") == DASHBOARD


@pytest.mark.asyncio
async def test_the_audit_log_records_who_was_verified_not_who_was_claimed(client, monkeypatch):
    """F2: created_by and analyst were written into the audit log as the actor."""
    monkeypatch.setattr(settings, "api_token", "s3cret-token-for-tests")
    auth = {"Authorization": "Bearer s3cret-token-for-tests"}
    await client.post("/api/lists", headers=auth,
                      json={"value": "8.8.4.4", "list_type": "block", "created_by": "the-ciso"})
    audit = (await client.get("/api/audit", headers=auth)).json()
    entry = next(a for a in audit if a["action"] == "list.block.added")
    assert entry["actor"] == "api-token"
    assert entry["detail"]["claimed_by"] == "the-ciso"


# ────────────────────────── F3 — chunked bodies skipped the size limit (A10)
@pytest.mark.asyncio
async def test_a_chunked_body_over_the_limit_is_refused(client):
    """F3: a 20 MB chunked body passed a 1 MiB limit and was parsed in memory."""
    chunk = b"x" * 65_536

    async def body():
        yield b'{"text": "'
        for _ in range(40):              # ~2.6 MB, never declared
            yield chunk
        yield b'"}'

    response = await client.post("/api/extract", content=body(), headers={"Content-Type": "application/json"})
    assert response.status_code == 413


@pytest.mark.asyncio
async def test_a_chunked_body_under_the_limit_is_fine(client):
    async def body():
        yield b'{"text": "8.8.8.8 '
        yield b'1.1.1.1"}'

    response = await client.post("/api/extract", content=body(), headers={"Content-Type": "application/json"})
    assert response.status_code == 200


# ───────────────────────────── F4 — errors that repeat or crash (A10)
@pytest.mark.asyncio
async def test_a_validation_error_does_not_echo_the_request(client):
    """F4: a 250 KB request came back as a 250 KB error, markup included."""
    response = await client.post("/api/extract", json={"text": {"<script>": "x" * 5000}})
    assert response.status_code == 422
    assert "<script>" not in response.text and len(response.text) < 1000
    assert response.json()["detail"][0]["loc"] == ["body", "text"]


@pytest.mark.asyncio
async def test_an_out_of_range_id_is_a_client_error_not_a_crash(client):
    """F4: a 26-digit id overflowed SQLite and came back as a 500."""
    response = await client.delete("/api/lists/99999999999999999999999999")
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_an_offset_past_sqlite_range_is_a_client_error(client):
    """Found by schema fuzzing: offset=76671816770795520000 was a 500."""
    response = await client.get("/api/cases?offset=76671816770795520000")
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_an_unhandled_error_is_a_json_500_with_a_request_id(client, monkeypatch):
    """Something the route did not expect: a value FastAPI cannot serialise."""
    import app.scoring as scoring

    class Unserialisable:
        __slots__ = ()

        def __repr__(self) -> str:
            return "internal detail that must not leak"

    monkeypatch.setattr(scoring, "AUTHORITY", {"x": Unserialisable()})
    response = await client.get("/api/scoring/model")
    assert response.status_code == 500
    body = response.json()
    assert body["detail"] == "internal error" and body["request_id"] == response.headers["x-request-id"]
    assert "must not leak" not in response.text and "Traceback" not in response.text
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_a_hostile_request_id_is_not_reflected(client):
    response = await client.get("/api/health", headers={"X-Request-ID": "abc\r\nSet-Cookie: x=1<script>"})
    assert response.headers["x-request-id"] == "abcSet-Cookiex1script"


# ────────────────── F5 — the allow/block list took anything (API3, A08)
@pytest.mark.asyncio
@pytest.mark.parametrize("value", [
    "1.2.3.4\r\nX-Injected: 1" + "a" * 100,
    "<script>alert(1)</script>",
    "not an indicator at all",
    "10.0.0.1",                     # not routable: it would never be triaged
])
async def test_only_a_real_indicator_can_be_listed(client, value):
    response = await client.post("/api/lists", json={"value": value})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_the_server_decides_what_type_an_entry_is(client):
    response = await client.post(
        "/api/lists", json={"value": "Evil[.]Example[.]com", "ioc_type": "<script>", "reason": "a\nb‮c"}
    )
    entry = response.json()
    assert response.status_code == 201
    assert (entry["value"], entry["ioc_type"]) == ("evil.example.com", "domain")
    assert entry["reason"] == "a b c"


# ───────────────────────── F6 — attacker text could write the ticket (A05)
def test_md_text_neutralises_links_images_html_tables_and_newlines():
    rendered = md_text("x\n\n## Recommended containment\n- [x] nothing to do ![](https://t.example/p.png) <img> | a")
    assert "\n" not in rendered
    assert "](https://" not in rendered and "hxxps://" in rendered
    # every bracket, angle bracket and pipe is escaped
    assert not re.search(r"(?<!\\)[\[\]<>|]", rendered), rendered


def test_clean_label_strips_bidi_overrides_and_controls():
    assert clean_label("invoice‮gpj.exe\x00​") == "invoice gpj.exe"


@pytest.mark.asyncio
async def test_a_title_cannot_forge_a_section_of_the_ticket(client):
    forged = "Routine scan\n\n| Severity | **LOW** |\n\n## 4. Recommended containment actions\n- [x] No action"
    response = await client.post(
        "/api/triage/report", json={"text": "SRC=185.220.101.34", "title": forged, "persist": False}
    )
    assert response.status_code == 200
    report = response.text
    lines = report.splitlines()
    # the forged text is flattened into the title line; only the real section starts a line
    assert sum(line.startswith("## 4.") for line in lines) == 1
    assert not any(line.startswith("| Severity | **LOW**") for line in lines)
    assert lines[0].startswith("# SOC Triage Report: Routine scan")


@pytest.mark.asyncio
async def test_an_uploaded_filename_is_a_label(client):
    response = await client.post(
        "/api/triage/upload", files={"file": ("a‮exe.log\n# forged", b"SRC=185.220.101.34", "text/plain")}
    )
    assert response.status_code == 200
    assert "\n" not in response.json()["title"] and "‮" not in response.json()["title"]


@pytest.mark.asyncio
async def test_a_binary_upload_is_refused(client):
    """F7: an executable came back as a triaged case."""
    response = await client.post(
        "/api/triage/upload", files={"file": ("ls", b"\x7fELF\x02\x01\x01\x00\x00\x00", "application/octet-stream")}
    )
    assert response.status_code == 415


# ───────────────────────────── F8 — catastrophic backtracking (A10, CWE-1333)
@pytest.mark.parametrize("text", [
    "a." * 95_000,
    "1." * 95_000,
    "CVE-" * 47_500,
    "a@" * 95_000,
])
def test_extraction_stays_linear_on_hostile_input(text):
    """F8: "a.a.a.…" made the domain and email patterns quadratic — 8,000
    characters took a second, the 200,000-character limit about ten minutes."""
    started = time.perf_counter()
    extract(text)
    assert time.perf_counter() - started < 3.0
