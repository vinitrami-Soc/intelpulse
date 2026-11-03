"""Sending email (spec 5.5), when the operator configured it: SMTP_HOST, SMTP_FROM and PUBLIC_URL.

Plain text only, one message at a time, from the standard library's SMTP client
in a worker thread so the event loop keeps serving. A message that cannot be sent
is logged without its address or its text; whoever asked is told the same thing
either way, so a mail server's failure reveals nothing about an account.
"""
from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage

from ..config import settings

logger = logging.getLogger(__name__)


def enabled() -> bool:
    return bool(settings.smtp_host and settings.smtp_from and settings.public_url.strip())


def link(path: str) -> str:
    """An address on this server for a console route such as "#/reset/<token>"."""
    return settings.public_url.strip().rstrip("/") + "/" + path


def _deliver(message: EmailMessage) -> None:
    mode = (settings.smtp_tls or "starttls").lower()
    context = ssl.create_default_context()
    connect = smtplib.SMTP_SSL if mode == "ssl" else smtplib.SMTP
    kwargs = {"context": context} if mode == "ssl" else {}
    with connect(settings.smtp_host, settings.smtp_port, timeout=15, **kwargs) as smtp:
        if mode == "starttls":
            smtp.starttls(context=context)
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password or "")
        smtp.send_message(message)


async def send(to: str, subject: str, text: str) -> bool:
    """Send one message; True when the mail server took it."""
    if not enabled():
        return False
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text)
    try:
        await asyncio.to_thread(_deliver, message)
    except (OSError, smtplib.SMTPException) as exc:
        logger.warning("an email could not be sent", extra={"error": type(exc).__name__})
        return False
    return True
