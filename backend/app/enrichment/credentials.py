"""The provider keys a lookup may use: the workspace's own, and nobody else's (spec 7).

A triage runs inside `using(credentials)`; every provider reads its key from
here, and the task gather() starts inherit it, so a lookup can only ever spend
the key of the workspace it runs for. Outside a workspace there are no keys at
all: a keyed provider reports itself as not configured.

Key slots, not providers, hold keys: ThreatFox and URLhaus share abuse.ch's.
"""
from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

# slot -> what the person setting it is asked for
KEY_SLOTS: dict[str, str] = {
    "abuseipdb": "AbuseIPDB API key",
    "otx": "AlienVault OTX API key",
    "greynoise": "GreyNoise API key",
    "abusech": "abuse.ch Auth-Key (ThreatFox and URLhaus)",
}
# where IntelPulse 1.x read each key, for the one-time import into the default organization
ENV_KEYS: dict[str, str] = {
    "abuseipdb": "abuseipdb_api_key",
    "otx": "otx_api_key",
    "greynoise": "greynoise_api_key",
    "abusech": "abusech_auth_key",
}


@dataclass(frozen=True)
class Credentials:
    workspace_id: int
    keys: Mapping[str, str] = field(default_factory=dict)
    disabled: frozenset[str] = frozenset()


_current: ContextVar[Credentials | None] = ContextVar("intelpulse_credentials", default=None)


def current() -> Credentials | None:
    return _current.get()


def key(slot: str | None) -> str | None:
    creds = _current.get()
    if creds is None or not slot:
        return None
    return creds.keys.get(slot) or None


def disabled(provider: str) -> bool:
    creds = _current.get()
    return creds is not None and provider in creds.disabled


@contextmanager
def using(creds: Credentials) -> Iterator[Credentials]:
    token = _current.set(creds)
    try:
        yield creds
    finally:
        _current.reset(token)
