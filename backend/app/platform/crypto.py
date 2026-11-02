"""AES-256-GCM sealing for raw alert text and stored secrets.

Each sealed value has a fresh 96-bit nonce and is bound to the place it is
stored (``table:column:row``) as associated data, so a value copied onto
another record does not open. Ported from PhishHawk's ``server/crypto.py``.
"""
from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"IPB1"
NONCE_BYTES = 12
TAG_BYTES = 16


class DecryptError(Exception):
    """Wrong key, a value bound to another record, or a damaged value."""


class KeyMissingError(RuntimeError):
    """The server was started without an encryption key."""


def new_key() -> str:
    """A fresh key in the form ENCRYPTION_KEY expects: 32 random bytes, base64."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


class Box:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise ValueError("the encryption key must be 32 bytes")
        self._aead = AESGCM(key)

    @classmethod
    def from_b64(cls, text: str) -> Box:
        try:
            return cls(base64.b64decode(text.strip(), validate=True))
        except (binascii.Error, ValueError) as exc:
            raise ValueError("ENCRYPTION_KEY must be 32 bytes in base64 (make keys prints one)") from exc

    def seal(self, data: bytes, bound_to: str) -> bytes:
        nonce = os.urandom(NONCE_BYTES)
        return MAGIC + nonce + self._aead.encrypt(nonce, data, bound_to.encode("utf-8"))

    def open(self, sealed: bytes, bound_to: str) -> bytes:
        if not sealed.startswith(MAGIC) or len(sealed) < len(MAGIC) + NONCE_BYTES + TAG_BYTES:
            raise DecryptError("not a sealed value")
        start = len(MAGIC)
        nonce, body = sealed[start:start + NONCE_BYTES], sealed[start + NONCE_BYTES:]
        try:
            return self._aead.decrypt(nonce, body, bound_to.encode("utf-8"))
        except InvalidTag as exc:
            raise DecryptError("wrong key, wrong record, or damaged") from exc


def box_from(key: str | None, key_file: Path | None) -> Box:
    """The server's Box, from ENCRYPTION_KEY or the file ENCRYPTION_KEY_FILE names.

    There is no fallback: a server that seals alert text and secrets must not
    start with a key someone else could guess, so a missing key stops it.
    """
    if key:
        return Box.from_b64(key)
    if key_file is not None:
        try:
            return Box.from_b64(key_file.read_text(encoding="ascii"))
        except OSError as exc:
            raise KeyMissingError(f"ENCRYPTION_KEY_FILE could not be read: {exc.strerror}") from exc
    raise KeyMissingError(
        "ENCRYPTION_KEY is not set: IntelPulse seals alert text and secrets with it and will not start "
        "without one. Run `make keys` (or `python -m app.cli new-key`) and put the result in .env."
    )
