"""The Box seals values so that only the right key, for the right record, opens them."""
from __future__ import annotations

import base64

import pytest

from app.platform.crypto import Box, DecryptError, KeyMissingError, box_from, new_key

KEY = base64.b64encode(bytes(range(32))).decode("ascii")


def test_a_sealed_value_opens_with_the_same_key_and_record():
    box = Box.from_b64(KEY)
    sealed = box.seal(b"Sep 18 02:14:11 edr-01 alert", "case_inputs:sealed:abc")
    assert box.open(sealed, "case_inputs:sealed:abc") == b"Sep 18 02:14:11 edr-01 alert"


def test_the_same_value_sealed_twice_differs():
    box = Box.from_b64(KEY)
    first, second = box.seal(b"x", "r"), box.seal(b"x", "r")
    assert first != second
    assert first[4:16] != second[4:16]  # a fresh nonce each time


def test_a_value_moved_to_another_record_does_not_open():
    box = Box.from_b64(KEY)
    sealed = box.seal(b"secret", "settings:1:otx_api_key")
    with pytest.raises(DecryptError):
        box.open(sealed, "settings:2:otx_api_key")


def test_the_wrong_key_does_not_open():
    sealed = Box.from_b64(KEY).seal(b"secret", "r")
    with pytest.raises(DecryptError):
        Box.from_b64(new_key()).open(sealed, "r")


@pytest.mark.parametrize("damaged", [b"", b"IPB1", b"nope" * 10, b"IPB1" + b"\x00" * 40])
def test_damaged_values_do_not_open(damaged):
    with pytest.raises(DecryptError):
        Box.from_b64(KEY).open(damaged, "r")


@pytest.mark.parametrize("bad", ["", "not base64!", base64.b64encode(b"short").decode()])
def test_a_key_that_is_not_32_bytes_of_base64_is_refused(bad):
    with pytest.raises(ValueError, match="ENCRYPTION_KEY"):
        Box.from_b64(bad)


def test_new_key_is_32_random_bytes():
    assert len(base64.b64decode(new_key())) == 32
    assert new_key() != new_key()


def test_without_a_key_the_server_has_no_box(tmp_path):
    with pytest.raises(KeyMissingError, match="ENCRYPTION_KEY"):
        box_from(None, None)
    with pytest.raises(KeyMissingError, match="could not be read"):
        box_from(None, tmp_path / "missing.key")


async def test_the_server_will_not_start_without_a_key(monkeypatch):
    from app.config import settings
    from app.main import app
    from app.platform.box import server_box

    monkeypatch.setattr(settings, "encryption_key", None)
    monkeypatch.setattr(settings, "encryption_key_file", None)
    server_box.cache_clear()
    try:
        with pytest.raises(KeyMissingError, match="ENCRYPTION_KEY"):
            for handler in app.router.on_startup:
                await handler()
    finally:
        server_box.cache_clear()


def test_the_key_can_come_from_a_file(tmp_path):
    key_file = tmp_path / "encryption.key"
    key_file.write_text(KEY + "\n", encoding="ascii")
    sealed = box_from(None, key_file).seal(b"v", "r")
    assert Box.from_b64(KEY).open(sealed, "r") == b"v"
