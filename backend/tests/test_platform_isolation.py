"""One workspace never reads, changes or learns of another's data (spec 6.1).

The owner's organization holds a case, a list entry, a token and audit records.
Bob is the admin of a second organization. Everything of the owner's is 404 to
Bob, exactly like an id that does not exist, and nothing of it shapes his answers.
"""
from __future__ import annotations

import pytest

KNOWN = "185.220.101.34"
TRIAGE = {"indicators": [KNOWN], "title": "the owner's case"}


@pytest.fixture
async def two(people):
    """(owner, bob, the owner's case id, the owner's list entry id, the owner's token id)."""
    owner = await people.set_up("ada", "Acme SOC")
    other = await people.workspace("Globex SOC")
    await people.member("bob", role="admin", workspace_id=other)
    bob = await people.signed_in("bob")
    case_id = (await owner.post("/api/triage", json=TRIAGE)).json()["case_id"]
    entry = await owner.post("/api/lists", json={"value": "8.8.4.4", "list_type": "block", "reason": "IR-7"})
    token = await owner.post("/api/tokens", json={"name": "ada-script", "scope": "read"})
    return owner, bob, case_id, entry.json()["id"], token.json()["id"]


async def test_another_workspace_sees_no_cases_and_no_numbers(two):
    _owner, bob, _case, _entry, _token = two
    assert (await bob.get("/api/cases")).json() == []
    stats = (await bob.get("/api/stats")).json()
    assert stats["cases"] == 0 and stats["indicators"] == 0 and stats["cases_by_verdict"] == {}


@pytest.mark.parametrize(("method", "path", "params"), [
    ("GET", "/api/cases/{case}", {}),
    ("GET", "/api/cases/{case}/report", {}),
    ("GET", "/api/cases/{case}/report", {"fmt": "json"}),
    ("POST", "/api/cases/{case}/ticket", {"sink": "jira"}),
    ("DELETE", "/api/cases/{case}", {}),
    ("DELETE", "/api/lists/{entry}", {}),
    ("DELETE", "/api/tokens/{token}", {}),
])
async def test_another_workspaces_ids_are_404_like_ids_that_do_not_exist(two, method, path, params):
    owner, bob, case_id, entry_id, token_id = two
    real = path.format(case=case_id, entry=entry_id, token=token_id)
    made_up = path.format(case="00000000-0000-0000-0000-000000000000", entry=999_999, token=999_999)
    theirs = await bob.request(method, real, params=params)
    nothing = await bob.request(method, made_up, params=params)
    assert theirs.status_code == nothing.status_code == 404
    assert theirs.json() == nothing.json()
    # and it is all still there for its owner
    assert (await owner.get(f"/api/cases/{case_id}")).status_code == 200
    assert len((await owner.get("/api/lists")).json()) == 1
    assert len((await owner.get("/api/tokens")).json()) == 1


async def test_lists_belong_to_one_workspace(two):
    owner, bob, _case, _entry, _token = two
    assert (await bob.get("/api/lists")).json() == []
    # the same value can be listed in both, each with its own reason
    assert (await bob.post("/api/lists", json={"value": "8.8.4.4", "list_type": "block"})).status_code == 201
    assert len((await owner.get("/api/lists")).json()) == 1


async def test_one_workspaces_block_list_does_not_change_anothers_verdict(two):
    owner, bob, _case, _entry, _token = two
    await owner.post("/api/lists", json={"value": KNOWN, "list_type": "block", "reason": "IR-9"})
    mine = (await owner.post("/api/triage", json=TRIAGE)).json()
    theirs = (await bob.post("/api/triage", json=TRIAGE)).json()
    assert mine["indicators"][0]["score"] >= 90
    assert theirs["indicators"][0]["score"] < 90


async def test_history_diffs_compare_only_with_the_same_workspace(two):
    owner, bob, _case, _entry, _token = two
    theirs = (await bob.post("/api/triage", json=TRIAGE)).json()
    mine = (await owner.post("/api/triage", json=TRIAGE)).json()
    assert theirs["diffs"][0]["previous_case_id"] is None      # first time Globex sees it
    assert mine["diffs"][0]["previous_case_id"] is not None    # Acme saw it in the fixture


async def test_the_same_pushed_alert_makes_a_case_in_each_workspace(two, people):
    owner, bob, _case, _entry, _token = two
    alert = {"source": "dwellwatch", "alert_id": "dw-1", "title": "Staging", "severity": "high",
             "indicators": [KNOWN]}
    acme = await (await people.token(owner, "ingest", "acme-dw")).post("/api/alerts", json=alert)
    globex = await (await people.token(bob, "ingest", "globex-dw")).post("/api/alerts", json=alert)
    assert acme.status_code == globex.status_code == 201
    assert acme.json()["case_id"] != globex.json()["case_id"]
    assert (await bob.get(f"/api/cases/{acme.json()['case_id']}")).status_code == 404


async def test_a_token_reaches_only_its_own_workspace(two, people):
    owner, bob, case_id, _entry, _token = two
    globex_script = await people.token(bob, "read", "globex-read")
    assert (await globex_script.get(f"/api/cases/{case_id}")).status_code == 404
    assert (await globex_script.get("/api/cases")).json() == []


async def test_the_audit_log_shows_each_workspace_its_own_records(two):
    owner, bob, case_id, _entry, _token = two
    seen_by_bob = (await bob.get("/api/audit")).json()
    assert all(r["actor"] == "bob" for r in seen_by_bob)
    assert not any(r["target"] == case_id for r in seen_by_bob)
    # the owner also sees the server's records, such as the setup
    actions = {r["action"] for r in (await owner.get("/api/audit")).json()}
    assert {"server.setup", "triage.completed", "token.created"} <= actions
