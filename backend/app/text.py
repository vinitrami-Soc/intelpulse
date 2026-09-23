"""Untrusted text on its way into a label, a log line or a Markdown ticket.

Case titles come from whoever typed them or named the uploaded file; rationales,
tags and family names come from vendors; allowlist reasons come from any client
of the API. None of it may decide the structure of what it is written into.
"""
from __future__ import annotations

import re

# C0/C1 controls, zero-width characters and the bidi overrides that let text
# display in a different order than it is stored ("Trojan Source").
_INVISIBLE = re.compile(
    "[\\x00-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u2028\\u2029\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u2069\\ufeff]"
)
_SPACE = re.compile(r"\s+")
# Enough to stop a string making a link, an image, raw HTML, a code span or a
# table cell. Emphasis characters are left alone: at worst they italicise.
_MD_SPECIAL = re.compile(r"([\\`\[\]<>|])")
_SCHEME = re.compile(r"\bhttp(s?)://", re.I)


def clean_label(value: object, limit: int = 200) -> str:
    """One line of visible text, at most `limit` characters."""
    text = _SPACE.sub(" ", _INVISIBLE.sub(" ", str(value if value is not None else ""))).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def md_text(value: object, limit: int = 300) -> str:
    """`clean_label`, then defanged and escaped for inline Markdown.

    A newline is what lets a title forge a section of the ticket, so there is
    none. A bracket is what makes a link or an image, so it is escaped. A URL
    scheme is defanged, the SOC convention, so nothing in the ticket is one
    click away from where the attacker wanted it to go.
    """
    text = clean_label(value, limit)
    text = _SCHEME.sub(lambda m: "hxxp" + m.group(1) + "://", text)
    return _MD_SPECIAL.sub(r"\\\1", text)
