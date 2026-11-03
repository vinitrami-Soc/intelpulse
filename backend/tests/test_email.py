"""Email (spec 5.5) against a fake SMTP server: the real client delivers each message to it.

A confirmation link confirms only through the page's button (a POST), and only the
address it was sent for. A reset link works once, within the hour, and ends every
session; asking for one answers the same whether or not an account matches.
"""
from __future__ import annotations

import asyncio
import re
from datetime import timedelta
from email import message_from_string
from email.policy import default as email_policy

import pytest
from sqlalchemy import select, update

from app.config import settings
from app.db import session_scope
from app.models import AuditLog, EmailToken, User, utcnow
from app.platform.deps import login_throttle
from app.security import limiter
from tests.conftest import PASSWORD

NEW_PASSWORD = "a brand new passphrase"


class FakeSMTP:
    """Enough of SMTP for smtplib to deliver to: every message is kept, nothing goes anywhere."""

    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        writer.write(b"220 fake.example ESMTP\r\n")
        await writer.drain()
        envelope: dict = {"to": []}
        data: list[bytes] | None = None
        while line := await reader.readline():
            if data is not None:
                if line in (b".\r\n", b".\n"):
                    raw = b"".join(data).decode()
                    parsed = message_from_string(raw, policy=email_policy)
                    self.messages.append({**envelope, "subject": parsed["subject"], "body": parsed.get_content()})
                    envelope, data = {"to": []}, None
                    writer.write(b"250 queued\r\n")
                else:
                    data.append(line[1:] if line.startswith(b"..") else line)
                    continue
            else:
                command = line.decode().strip()
                upper = command.upper()
                if upper.startswith(("EHLO", "HELO")):
                    writer.write(b"250 fake.example\r\n")
                elif upper.startswith("MAIL FROM:"):
                    envelope["from"] = command[10:].strip(" <>")
                    writer.write(b"250 ok\r\n")
                elif upper.startswith("RCPT TO:"):
                    envelope["to"].append(command[8:].strip(" <>"))
                    writer.write(b"250 ok\r\n")
                elif upper == "DATA":
                    data = []
                    writer.write(b"354 go ahead\r\n")
                elif upper == "QUIT":
                    writer.write(b"221 bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 ok\r\n")
            await writer.drain()
        writer.close()

    def links(self, kind: str) -> list[str]:
        return [m for msg in self.messages for m in re.findall(r"#/" + kind + r"/([A-Za-z0-9_-]+)", msg["body"])]


@pytest.fixture
async def mailbox(monkeypatch):
    fake = FakeSMTP()
    server = await asyncio.start_server(fake.handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    for name, value in {"smtp_host": "127.0.0.1", "smtp_port": port, "smtp_from": "intelpulse@example.org",
                        "smtp_tls": "none", "public_url": "https://intelpulse.example.org"}.items():
        monkeypatch.setattr(settings, name, value)
    login_throttle.clear()
    limiter._hits.clear()
    yield fake
    server.close()
    await server.wait_closed()


@pytest.fixture
async def ada(people, mailbox, monkeypatch):
    """The owner, with a confirmed address, signed in. Set up as before email was configured."""
    host = settings.smtp_host
    monkeypatch.setattr(settings, "smtp_host", "")
    owner = await people.set_up("ada", "Acme SOC")
    monkeypatch.setattr(settings, "smtp_host", host)
    async with session_scope() as db:
        await db.execute(update(User).where(User.username == "ada").values(email="ada@example.org", email_confirmed_at=utcnow()))
    return owner


async def test_the_session_says_whether_email_is_on(browser, mailbox, monkeypatch):
    assert (await browser.get("/api/session")).json()["email"] is True
    monkeypatch.setattr(settings, "smtp_host", "")
    assert (await browser.get("/api/session")).json()["email"] is False


async def test_a_new_address_is_confirmed_through_the_page_s_button(ada, mailbox):
    changed = await ada.patch("/api/profile", json={"email": "ada.l@example.org"})
    assert changed.status_code == 200 and changed.json()["email_confirmed"] is False
    assert len(mailbox.messages) == 1 and mailbox.messages[0]["to"] == ["ada.l@example.org"]
    assert mailbox.messages[0]["body"].count("https://intelpulse.example.org/#/confirm/") == 1
    token = mailbox.links("confirm")[0]
    answer = await ada.post("/api/email/confirm", json={"token": token})
    assert answer.status_code == 200 and answer.json()["email"] == "ada.l@example.org"
    assert (await ada.get("/api/profile")).json()["email_confirmed"] is True
    assert (await ada.post("/api/email/confirm", json={"token": token})).status_code == 404   # once


async def test_a_link_for_an_old_address_confirms_nothing(ada, mailbox):
    await ada.patch("/api/profile", json={"email": "first@example.org"})
    old = mailbox.links("confirm")[0]
    await ada.patch("/api/profile", json={"email": "second@example.org"})
    assert (await ada.post("/api/email/confirm", json={"token": old})).status_code == 404
    assert (await ada.get("/api/profile")).json()["email_confirmed"] is False


async def test_a_reset_link_works_once_within_the_hour_and_ends_every_session(ada, mailbox, people):
    other_browser = await people.signed_in("ada")
    asked = await people._client().post("/api/password/forgot", json={"login": "ada@example.org"})
    assert asked.status_code == 202
    assert mailbox.messages[-1]["to"] == ["ada@example.org"] and "within the hour" in mailbox.messages[-1]["body"]
    token = mailbox.links("reset")[-1]
    stranger = people._client()
    done = await stranger.post("/api/password/reset", json={"token": token, "password": NEW_PASSWORD})
    assert done.status_code == 200, done.text
    # every session of the account has ended, the old password is gone, the new one works
    assert (await ada.get("/api/cases")).status_code == 401
    assert (await other_browser.get("/api/cases")).status_code == 401
    assert (await stranger.post("/api/session", json={"username": "ada", "password": PASSWORD})).status_code == 401
    assert (await stranger.post("/api/session", json={"username": "ada", "password": NEW_PASSWORD})).status_code == 200
    # and the link works once
    again = await people._client().post("/api/password/reset", json={"token": token, "password": "yet another passphrase"})
    assert again.status_code == 404


async def test_a_reset_link_expires_after_an_hour(ada, mailbox, people):
    await people._client().post("/api/password/forgot", json={"login": "ada"})
    token = mailbox.links("reset")[-1]
    async with session_scope() as db:   # a fake clock: the hour has passed
        await db.execute(update(EmailToken).values(expires_at=utcnow() - timedelta(seconds=1)))
    late = await people._client().post("/api/password/reset", json={"token": token, "password": NEW_PASSWORD})
    assert late.status_code == 404 and "expired" in late.json()["detail"]


async def test_a_new_password_too_short_keeps_the_link(ada, mailbox, people):
    await people._client().post("/api/password/forgot", json={"login": "ada"})
    token = mailbox.links("reset")[-1]
    client = people._client()
    assert (await client.post("/api/password/reset", json={"token": token, "password": "short"})).status_code == 422
    assert (await client.post("/api/password/reset", json={"token": token, "password": NEW_PASSWORD})).status_code == 200


async def test_asking_answers_the_same_whether_or_not_an_account_matches(ada, mailbox, people):
    answers = []
    for login in ("ada", "nobody", "nobody@example.org"):
        answer = await people._client().post("/api/password/forgot", json={"login": login})
        answers.append((answer.status_code, answer.json()))
    assert answers[0] == answers[1] == answers[2]
    assert len(mailbox.messages) == 1   # only the real account was sent anything


async def test_nothing_is_sent_to_an_unconfirmed_address(ada, mailbox, people):
    async with session_scope() as db:
        await db.execute(update(User).where(User.username == "ada").values(email_confirmed_at=None))
    assert (await people._client().post("/api/password/forgot", json={"login": "ada"})).status_code == 202
    assert mailbox.messages == []


async def test_one_account_is_sent_three_resets_an_hour(ada, mailbox, people):
    for _ in range(5):
        await people._client().post("/api/password/forgot", json={"login": "ada"})
    assert len(mailbox.links("reset")) == 3


async def test_a_disabled_account_is_sent_nothing(ada, mailbox, people):
    await people.member("bea")
    async with session_scope() as db:
        await db.execute(update(User).where(User.username == "bea").values(
            email="bea@example.org", email_confirmed_at=utcnow(), disabled=True))
    await people._client().post("/api/password/forgot", json={"login": "bea@example.org"})
    assert mailbox.messages == []


async def test_without_email_there_is_no_forgotten_password(browser):
    answer = await browser.post("/api/password/forgot", json={"login": "ada"})
    assert answer.status_code == 409 and answer.json()["error"] == "email_off"


async def test_with_email_on_setup_and_sign_up_need_an_address(people, mailbox):
    client = people._client()
    code = await people.code()
    refused = await client.post("/api/setup", json={"code": code, "username": "ada", "password": PASSWORD,
                                                    "organization": "Acme SOC"})
    assert refused.status_code == 422 and "address" in refused.json()["detail"]
    made = await client.post("/api/setup", json={"code": code, "username": "ada", "password": PASSWORD,
                                                 "organization": "Acme SOC", "email": "ada@example.org"})
    assert made.status_code == 201
    assert mailbox.messages[-1]["to"] == ["ada@example.org"] and mailbox.links("confirm")


async def test_a_confirmation_can_be_sent_again_three_times_an_hour(ada, mailbox):
    await ada.patch("/api/profile", json={"email": "ada.l@example.org"})
    for _ in range(2):
        assert (await ada.post("/api/profile/email/confirm")).status_code == 202
    assert (await ada.post("/api/profile/email/confirm")).status_code == 429
    assert len(mailbox.links("confirm")) == 3


async def test_a_mail_server_that_is_down_changes_no_answer(ada, mailbox, people, monkeypatch):
    monkeypatch.setattr(settings, "smtp_port", 1)   # nothing listens there
    answer = await people._client().post("/api/password/forgot", json={"login": "ada"})
    assert answer.status_code == 202


async def test_the_flows_are_audited_without_the_tokens(ada, mailbox, people):
    await people._client().post("/api/password/forgot", json={"login": "ada"})
    token = mailbox.links("reset")[-1]
    await people._client().post("/api/password/reset", json={"token": token, "password": NEW_PASSWORD})
    async with session_scope() as db:
        rows = (await db.execute(select(AuditLog.action, AuditLog.detail, AuditLog.target))).all()
    actions = [action for action, _, _ in rows]
    assert "password.reset_requested" in actions and "password.reset" in actions
    assert all(token not in str(detail) + str(target) for _, detail, target in rows)
