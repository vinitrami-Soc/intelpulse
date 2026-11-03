#!/usr/bin/env python3
"""Sign up, triage, get a verdict: the deploy kit's smoke test (docs/DEPLOY.md).

    SMOKE_PASSWORD='...' python3 deploy/smoke.py https://intel.example.org --owner ada
    SMOKE_PASSWORD='...' python3 deploy/smoke.py http://127.0.0.1:8000 --setup-code XXXX-XXXX-XXXX-XXXX

Against a server that is set up, it signs in as the owner. Against a new one, with the setup
code, it makes the owner (`--owner`, "owner" unless given) with the password you chose. The
password comes from SMOKE_PASSWORD, or --password, and is never printed.
Then it opens sign-up for a moment, signs up a new individual account, triages a sample alert as
that account, checks the verdict and the stored case, and puts sign-up back the way it was. The
smoke account stays, a workspace of its own with one case in it: an admin can see it in the Server
pane's counts.

Standard library only, so it runs on the server, a laptop or a CI runner as it is. Exit 0 when
every step passed.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request
from typing import Any

SAMPLE = ("Sep 18 02:14:11 fw-edge-01 kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.34 DST=10.20.4.15 "
          "PROTO=TCP DPT=445\nSep 18 02:14:12 proxy-01 squid: TCP_DENIED/403 GET hxxp://malware-drop[.]example/payload.bin")
VERDICTS = {"critical", "high", "medium", "low", "informational"}


class Step(Exception):
    pass


class Client:
    """One person's session: the session cookie by hand, since a Secure cookie on http://localhost
    is one Python's cookie jar would never send back."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.cookie = ""
        self.csrf = ""

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Accept", "application/json")
        request.add_header("User-Agent", "intelpulse-smoke/2")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        if self.cookie:
            request.add_header("Cookie", self.cookie)
        if self.csrf and method != "GET":
            request.add_header("X-CSRF-Token", self.csrf)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                status, raw, headers = response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            status, raw, headers = error.code, error.read(), error.headers
        for value in headers.get_all("Set-Cookie") or []:
            pair = value.split(";", 1)[0]
            if pair.startswith("ip_session="):
                self.cookie = pair
        try:
            answer = json.loads(raw) if raw else None
        except ValueError:
            answer = raw.decode("utf-8", "replace")[:200]
        if isinstance(answer, dict) and answer.get("csrf"):
            self.csrf = answer["csrf"]
        return status, answer


def _waiting(health: Any) -> bool:
    beat = (health or {}).get("checks", {}).get("beat", {}) if isinstance(health, dict) else {}
    return beat.get("detail") == "waiting for the first heartbeat"


def expect(name: str, ok: bool, detail: Any = "") -> None:
    print(("PASS  " if ok else "FAIL  ") + name + (f"  ({detail})" if detail not in ("", None) else ""))
    if not ok:
        raise Step(name)


def main() -> int:
    parser = argparse.ArgumentParser(description="IntelPulse smoke test: sign up, triage, verdict")
    parser.add_argument("base", help="the server's address, e.g. https://intel.example.org")
    parser.add_argument("--setup-code", help="for a new server: the code from `python -m app.cli setup-code`")
    parser.add_argument("--owner", default="owner", help="the owner's username (owner)")
    parser.add_argument("--password", help="the owner's password; SMOKE_PASSWORD keeps it out of the shell's history")
    parser.add_argument("--heartbeat-wait", type=int, default=150, metavar="SECONDS",
                        help="how long a just-started server may wait for its first heartbeat (150)")
    args = parser.parse_args()
    password = args.password or os.environ.get("SMOKE_PASSWORD", "")
    if not password:
        parser.error("set SMOKE_PASSWORD (or pass --password): the owner's password, or the one to give a new owner")

    try:
        probe = Client(args.base)
        status, health = probe.call("GET", "/healthz")
        # A server that has just started waits for the worker's first heartbeat: give it a while,
        # since that heartbeat is what proves beat, the worker, Redis and the database work together.
        deadline = time.monotonic() + args.heartbeat_wait
        while status == 200 and _waiting(health) and time.monotonic() < deadline:
            time.sleep(5)
            status, health = probe.call("GET", "/healthz")
        expect("the server answers /healthz with 200", status == 200, health)
        beat = (health or {}).get("checks", {}).get("beat", {})
        expect("the worker's heartbeat arrives on beat's schedule", beat.get("ok") is None or "age_seconds" in beat, beat)

        owner = Client(args.base)
        if args.setup_code:
            status, made = owner.call("POST", "/api/setup", {
                "code": args.setup_code.strip(), "username": args.owner, "password": password,
                "organization": "Smoke test organization",
            })
            expect("the setup code makes the owner", status == 201, made if status != 201 else args.owner)
        else:
            status, opened = owner.call("POST", "/api/session", {"username": args.owner, "password": password})
            expect("the owner signs in", status == 200, opened if status != 200 else "")

        status, server = owner.call("GET", "/api/server")
        expect("the owner reads the server's settings", status == 200, server if status != 200 else "")
        was_open = bool(server.get("signup"))
        if not was_open:
            status, _ = owner.call("PATCH", "/api/server", {"signup": True})
            expect("the owner opens sign-up for the test", status == 200)
        try:
            person = Client(args.base)
            username = "smoke-" + secrets.token_hex(4)
            status, made = person.call("POST", "/api/signup", {
                "kind": "individual", "username": username, "display_name": "Smoke test",
                "password": secrets.token_urlsafe(18),
            })
            expect("a new account signs up and is signed in", status == 201, made if status != 201 else username)

            status, result = person.call("POST", "/api/triage", {"text": SAMPLE, "title": "Smoke test"})
            expect("the new account triages a sample alert", status == 200, result if status != 200 else "")
            verdict = result.get("verdict")
            expect("and gets a verdict", verdict in VERDICTS, f"{verdict}, score {result.get('score')}")
            found = [i.get("value") for i in result.get("indicators", [])]
            expect("for the indicators in the alert", "185.220.101.34" in found, ", ".join(map(str, found)))

            status, cases = person.call("GET", "/api/cases")
            expect("the case is stored in the new workspace",
                   status == 200 and any(c.get("id") == result.get("case_id") for c in cases or []))
        finally:
            if not was_open:
                status, _ = owner.call("PATCH", "/api/server", {"signup": False})
                expect("sign-up is closed again, as it was", status == 200)
    except Step as failed:
        print(f"\nsmoke test failed at: {failed}")
        return 1
    except (urllib.error.URLError, OSError) as error:
        print(f"\nsmoke test could not reach {args.base}: {error}")
        return 1
    print("\nsmoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
