"""The server's one Box, built from the settings the first time it is needed.

Startup calls ``server_box()`` before anything else, so a missing or malformed
key stops the server at once instead of on the first request that seals.
"""
from __future__ import annotations

from functools import lru_cache

from ..config import settings
from .crypto import Box, box_from


@lru_cache(maxsize=1)
def server_box() -> Box:
    key = settings.encryption_key.get_secret_value() if settings.encryption_key else None
    return box_from(key, settings.encryption_key_file)
