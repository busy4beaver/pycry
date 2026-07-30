"""Unit-тесты GOST 28147-89 (ECB / CBC / OFB / CTR)."""

from __future__ import annotations

import pytest

from pycry import (
    CRYPT_MODE,
    KEY1,
    KEY2,
    KEY3,
    Gost28147,
    decrypt_hex,
    encrypt_hex,
)


@pytest.fixture
def gost() -> Gost28147:
    return Gost28147()


def test_ecb_roundtrip(gost: Gost28147) -> None:
    plain = bytearray(b"1234567890123456")
    original = bytes(plain)
    gost.crypt(plain, KEY1, encrypt=True, mode=CRYPT_MODE.ECB)
    assert bytes(plain) != original
    gost.crypt(plain, KEY1, encrypt=False, mode=CRYPT_MODE.ECB)
    assert bytes(plain) == original


def test_cbc_roundtrip(gost: Gost28147) -> None:
    plain = bytearray(b"1234567890123456")
    original = bytes(plain)
    gost.crypt(plain, KEY1, encrypt=True, mode=CRYPT_MODE.CBC)
    assert bytes(plain) != original
    gost.crypt(plain, KEY1, encrypt=False, mode=CRYPT_MODE.CBC)
    assert bytes(plain) == original


def test_ofb_stream_is_involutive(gost: Gost28147) -> None:
    plain = bytearray(b"abcdefgh")
    original = bytes(plain)
    gost.crypt(plain, KEY1, encrypt=True, mode=CRYPT_MODE.OFB)
    assert bytes(plain) != original
    gost.crypt(plain, KEY1, encrypt=True, mode=CRYPT_MODE.OFB)
    assert bytes(plain) == original


def test_ctr_stream_is_involutive(gost: Gost28147) -> None:
    plain = bytearray(b"abcdefgh")
    original = bytes(plain)
    gost.crypt(plain, KEY1, encrypt=True, mode=CRYPT_MODE.CTR)
    gost.crypt(plain, KEY1, encrypt=True, mode=CRYPT_MODE.CTR)
    assert bytes(plain) == original


def test_ecb_padding_spaces(gost: Gost28147) -> None:
    plain = bytearray(b"hello gost")
    gost.crypt(plain, KEY1, encrypt=True, mode=CRYPT_MODE.ECB)
    assert len(plain) % 8 == 0
    gost.crypt(plain, KEY1, encrypt=False, mode=CRYPT_MODE.ECB)
    assert bytes(plain).rstrip(b" ") == b"hello gost"


def test_encrypt_decrypt_hex_level0() -> None:
    ct = encrypt_hex("hello gost", level=0)
    pt = decrypt_hex(ct, level=0)
    assert "hello gost" in pt


def test_keys_distinct() -> None:
    assert KEY1 != KEY2 != KEY3


def test_empty_message(gost: Gost28147) -> None:
    msg = bytearray()
    assert gost.crypt(msg, KEY1, encrypt=True, mode=CRYPT_MODE.ECB) == 0
