"""Setup, signing in and out, CSRF, the login throttle, and who reaches which route."""
from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app.config import settings
from app.db import session_scope
from app.main import app
from app.models import DEFAULT_WORKSPACE_ID, LoginSession, User, Workspace, utcnow

from .conftest import PASSWORD

TRIAGE = {"indicators": ["185.220.101.34"], "title": "session test"}


# -- setup -----------------------------------------------------------------------
async def test_a_new_server_says_it_needs_setup(browser):
    body = (await browser.get("/api/session")).json()
    assert body["mode"] == "server" and body["setup_needed"] is True
    assert body["user"] is None and body["csrf"] is None


async def test_setup_makes_the_owner_and_renames_the_default_organization(people):
    owner = await people.set_up("ada", "Acme SOC")
    body = (await owner.get("/api/session")).json()
    assert body["user"]["username"] == "ada"
    assert body["user"]["owner"] is True and body["user"]["role"] == "admin"
    assert body["workspace"] == {"id": DEFAULT_WORKSPACE_ID, "name": "Acme SOC", "kind": "organization"}
    assert body["setup_needed"] is False and body["csrf"]


async def test_the_setup_code_works_once(people, browser):
    code = await people.code()
    await people.set_up()
    again = await browser.post("/api/setup", json={
        "code": code, "username": "mallory", "password": PASSWORD, "organization": "Mine now"})
    assert again.status_code == 409 and again.json()["error"] == "set_up"
    assert await people.code() is None
    async with session_scope() as db:
        assert (await db.get(Workspace, DEFAULT_WORKSPACE_ID)).name == "Acme SOC"


async def test_a_wrong_setup_code_is_refused_and_then_slowed_down(people, browser):
    await people.code()
    attempt = {"code": "AAAA-BBBB-CCCC-DDDD", "username": "mallory", "password": PASSWORD,
               "organization": "Mine"}
    answers = [await browser.post("/api/setup", json=attempt) for _ in range(4)]
    assert [a.status_code for a in answers[:3]] == [403, 403, 403]
    assert answers[0].json() == {"error": "wrong_code", "detail": "that setup code is not right"}
    assert answers[3].status_code == 429 and int(answers[3].headers["retry-after"]) >= 1
    async with session_scope() as db:
        assert (await db.execute(select(User))).first() is None


async def test_setup_checks_what_it_is_given(people, browser):
    base = {"code": await people.code(), "username": "ada", "password": PASSWORD, "organization": "Acme"}
    for change, words in [({"organization": "  "}, "needs a name"), ({"email": "not-an-address"}, "email"),
                          ({"password": "short"}, "at least 12"), ({"username": "Ada Lovelace"}, "usernames")]:
        response = await browser.post("/api/setup", json={**base, **change})
        assert response.status_code == 422 and words in response.json()["detail"], change
    assert (await browser.post("/api/setup", json=base)).status_code == 201


async def test_the_setup_code_never_reaches_the_log(people, browser, caplog):
    caplog.set_level(logging.DEBUG)
    for handler in app.router.on_startup:
        await handler()
    code = await people.code()
    await people.set_up()
    assert "setup-code" in caplog.text  # the server says how to get one...
    assert code not in caplog.text      # ...and never prints it


# -- signing in and out ------------------------------------------------------------
async def test_signing_in_sets_a_strict_http_only_cookie(people, browser, monkeypatch):
    await people.set_up("ada")
    monkeypatch.setattr(settings, "cookie_secure", True)
    response = await browser.post("/api/session", json={"username": "ada", "password": PASSWORD})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"].lower()
    assert cookie.startswith("ip_session=")
    for flag in ("httponly", "secure", "samesite=strict", "path=/"):
        assert flag in cookie


async def test_a_wrong_password_is_refused_without_saying_which_part_was_wrong(people, browser):
    await people.set_up("ada")
    wrong = await browser.post("/api/session", json={"username": "ada", "password": PASSWORD + "!"})
    nobody = await browser.post("/api/session", json={"username": "nobody", "password": PASSWORD})
    assert wrong.status_code == nobody.status_code == 401
    assert wrong.json() == nobody.json() == {"error": "unauthorized", "detail": "wrong username or password"}


async def test_repeated_failures_slow_down_sign_in(people, browser):
    await people.set_up("ada")
    for _ in range(3):
        await browser.post("/api/session", json={"username": "ada", "password": "not it at all"})
    throttled = await browser.post("/api/session", json={"username": "ada", "password": PASSWORD})
    assert throttled.status_code == 429 and throttled.json()["error"] == "throttled"


async def test_a_session_reads_and_writes_with_its_csrf_token(people):
    owner = await people.set_up()
    assert (await owner.get("/api/cases")).status_code == 200
    assert (await owner.post("/api/triage", json=TRIAGE)).status_code == 200


async def test_a_write_without_the_csrf_token_is_refused(people):
    owner = await people.set_up()
    csrf = owner.headers.pop("X-CSRF-Token")
    missing = await owner.post("/api/triage", json=TRIAGE)
    wrong = await owner.post("/api/triage", json=TRIAGE, headers={"X-CSRF-Token": csrf[:-1] + "x"})
    assert missing.status_code == wrong.status_code == 403
    assert missing.json()["error"] == "csrf"
    assert (await owner.get("/api/cases")).status_code == 200  # reads need no token


async def test_signing_out_ends_the_session(people):
    owner = await people.set_up()
    stolen = owner.cookies.get("ip_session")
    assert (await owner.delete("/api/session")).status_code == 204
    assert (await owner.get("/api/cases")).status_code == 401
    replay = await owner.get("/api/cases", cookies={"ip_session": stolen})
    assert replay.status_code == 401


async def test_an_idle_session_expires(people):
    owner = await people.set_up()
    async with session_scope() as db:
        await db.execute(update(LoginSession).values(last_seen_at=utcnow() - timedelta(hours=9)))
    assert (await owner.get("/api/cases")).status_code == 401
    assert (await owner.get("/api/session")).json()["user"] is None


async def test_a_disabled_account_is_signed_out(people):
    owner = await people.set_up()
    await people.member("bea")
    bea = await people.signed_in("bea")
    async with session_scope() as db:
        await db.execute(update(User).where(User.username == "bea").values(disabled=True))
    assert (await bea.get("/api/cases")).status_code == 401
    assert (await owner.get("/api/cases")).status_code == 200


async def test_a_wrong_bearer_token_is_not_rescued_by_a_session_cookie(people):
    owner = await people.set_up()
    response = await owner.get("/api/cases", headers={"Authorization": "Bearer ipt_not-a-real-token"})
    assert response.status_code == 401


# -- roles ------------------------------------------------------------------------
async def test_an_analyst_triages_but_does_not_change_lists_or_delete_cases(people):
    await people.set_up()
    await people.member("bea", role="analyst")
    bea = await people.signed_in("bea")
    case_id = (await bea.post("/api/triage", json=TRIAGE)).json()["case_id"]
    assert (await bea.post("/api/lists", json={"value": "8.8.4.4", "list_type": "block"})).status_code == 403
    assert (await bea.delete(f"/api/cases/{case_id}")).status_code == 403
    assert (await bea.get(f"/api/cases/{case_id}")).status_code == 200


async def test_an_analyst_sees_only_their_own_audit_records(people):
    owner = await people.set_up("ada")
    await people.member("bea")
    bea = await people.signed_in("bea")
    await owner.post("/api/lists", json={"value": "8.8.4.4", "list_type": "block"})
    await bea.post("/api/triage", json=TRIAGE)
    actors = {record["actor"] for record in (await bea.get("/api/audit")).json()}
    assert actors == {"bea"}
    everyone = {record["actor"] for record in (await owner.get("/api/audit")).json()}
    assert {"ada", "bea"} <= everyone


async def test_only_the_owner_refreshes_the_shared_feeds(people):
    owner = await people.set_up()
    await people.member("adam", role="admin")
    adam = await people.signed_in("adam")
    # an unknown feed: the role check runs first, and nothing is fetched from the network
    assert (await adam.post("/api/intel/feeds/no-such-feed/refresh")).status_code == 403
    assert (await owner.post("/api/intel/feeds/no-such-feed/refresh")).status_code == 404
    assert (await adam.post("/api/intel/cache/invalidate", params={"ioc": "8.8.8.8"})).status_code == 403


# -- every route --------------------------------------------------------------------
PUBLIC = {("GET", "/api/health"), ("GET", "/api/scoring/model"), ("GET", "/api/session"),
          ("POST", "/api/session"), ("POST", "/api/setup"), ("POST", "/api/signup"),
          ("POST", "/api/join"), ("POST", "/api/join/check"), ("POST", "/api/password/forgot"),
          ("POST", "/api/password/reset"), ("POST", "/api/email/confirm")}
SAMPLE_IDS = {"{case_id}": "00000000-0000-0000-0000-000000000000", "{entry_id}": "1", "{token_id}": "1",
              "{feed}": "cisa-kev", "{cve_id}": "CVE-2024-3400", "{name}": "otx", "{user_id}": "1",
              "{invite_id}": "1"}


def _api_routes() -> list[tuple[str, str]]:
    """Every route of the API, as the OpenAPI document lists it."""
    paths = app.openapi()["paths"]
    return sorted((method.upper(), path) for path, item in paths.items() for method in item
                  if path.startswith("/api/"))


def test_the_public_routes_are_the_ones_meant_to_be():
    assert set(_api_routes()) >= PUBLIC


@pytest.mark.parametrize(("method", "path"), [r for r in _api_routes() if r not in PUBLIC])
async def test_every_other_route_needs_a_signed_in_caller(browser, method, path):
    for placeholder, value in SAMPLE_IDS.items():
        path = path.replace(placeholder, value)
    assert "{" not in path, f"no sample id for {path}"
    response = await browser.request(method, path, params={"sink": "jira", "ioc": "8.8.8.8"})
    assert response.status_code == 401, f"{method} {path} answered {response.status_code}"
