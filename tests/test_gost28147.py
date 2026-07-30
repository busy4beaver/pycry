"""Unit-тесты GOST 28147-89 (ECB / CBC / OFB / CTR)."""

from __future__ import annotations

import pytest

from rucry import (
    CRYPT_MODE,
    SBOX_TEST,
    Gost28147,
    decrypt_bytes,
    encrypt_bytes,
    encrypt_hex,
    decrypt_hex,
    resolve_sbox,
)

KEY = [
    0x01020304,
    0x05060708,
    0x090A0B0C,
    0x0D0E0F10,
    0x11121314,
    0x15161718,
    0x191A1B1C,
    0x1D1E1F20,
]


@pytest.fixture
def gost() -> Gost28147:
    return Gost28147(sbox="cryptopro-a")


def test_ecb_roundtrip(gost: Gost28147) -> None:
    plain = bytearray(b"1234567890123456")
    original = bytes(plain)
    gost.crypt(plain, KEY, encrypt=True, mode=CRYPT_MODE.ECB)
    assert bytes(plain) != original
    gost.crypt(plain, KEY, encrypt=False, mode=CRYPT_MODE.ECB)
    assert bytes(plain) == original


def test_cbc_roundtrip(gost: Gost28147) -> None:
    plain = bytearray(b"1234567890123456")
    original = bytes(plain)
    iv = b"\x00" * 8
    gost.crypt(plain, KEY, encrypt=True, mode=CRYPT_MODE.CBC, iv=iv)
    assert bytes(plain) != original
    gost.crypt(plain, KEY, encrypt=False, mode=CRYPT_MODE.CBC, iv=iv)
    assert bytes(plain) == original


def test_ofb_stream_is_involutive(gost: Gost28147) -> None:
    plain = bytearray(b"abcdefgh")
    original = bytes(plain)
    iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    gost.crypt(plain, KEY, encrypt=True, mode=CRYPT_MODE.OFB, iv=iv)
    assert bytes(plain) != original
    gost.crypt(plain, KEY, encrypt=True, mode=CRYPT_MODE.OFB, iv=iv)
    assert bytes(plain) == original


def test_ctr_stream_is_involutive(gost: Gost28147) -> None:
    plain = bytearray(b"abcdefgh")
    original = bytes(plain)
    iv = b"\x00" * 8
    gost.crypt(plain, KEY, encrypt=True, mode=CRYPT_MODE.CTR, iv=iv)
    gost.crypt(plain, KEY, encrypt=True, mode=CRYPT_MODE.CTR, iv=iv)
    assert bytes(plain) == original


def test_ecb_padding_zeros(gost: Gost28147) -> None:
    plain = bytearray(b"hello")
    gost.crypt(plain, KEY, encrypt=True, mode=CRYPT_MODE.ECB, pad=True)
    assert len(plain) % 8 == 0
    gost.crypt(plain, KEY, encrypt=False, mode=CRYPT_MODE.ECB, pad=False)
    assert bytes(plain).rstrip(b"\x00") == b"hello"


def test_encrypt_decrypt_hex() -> None:
    ct = encrypt_hex("hello!!!", KEY, mode=CRYPT_MODE.ECB, sbox="cryptopro-a")
    pt = decrypt_hex(ct, KEY, mode=CRYPT_MODE.ECB, sbox="cryptopro-a")
    assert pt.startswith(b"hello!!!")


def test_sbox_by_name() -> None:
    g1 = Gost28147(sbox="test")
    g2 = Gost28147(sbox=SBOX_TEST)
    plain1 = bytearray(b"12345678")
    plain2 = bytearray(b"12345678")
    g1.crypt(plain1, KEY, encrypt=True, mode=CRYPT_MODE.ECB)
    g2.crypt(plain2, KEY, encrypt=True, mode=CRYPT_MODE.ECB)
    assert plain1 == plain2


def test_custom_sbox() -> None:
    custom = resolve_sbox("cryptopro-a")
    g = Gost28147(sbox=custom)
    plain = bytearray(b"12345678")
    original = bytes(plain)
    g.crypt(plain, KEY, encrypt=True, mode=CRYPT_MODE.ECB)
    g.crypt(plain, KEY, encrypt=False, mode=CRYPT_MODE.ECB)
    assert bytes(plain) == original


def test_different_sboxes_differ() -> None:
    p1 = bytearray(b"12345678")
    p2 = bytearray(b"12345678")
    Gost28147(sbox="cryptopro-a").crypt(p1, KEY, encrypt=True, mode=CRYPT_MODE.ECB)
    Gost28147(sbox="test").crypt(p2, KEY, encrypt=True, mode=CRYPT_MODE.ECB)
    assert p1 != p2


def test_encrypt_bytes_helpers() -> None:
    ct = encrypt_bytes(b"12345678", KEY, mode=CRYPT_MODE.ECB, sbox="cryptopro-a")
    pt = decrypt_bytes(ct, KEY, mode=CRYPT_MODE.ECB, sbox="cryptopro-a")
    assert pt == b"12345678"


def test_empty_message(gost: Gost28147) -> None:
    msg = bytearray()
    assert gost.crypt(msg, KEY, encrypt=True, mode=CRYPT_MODE.ECB) == 0


def test_unknown_sbox() -> None:
    with pytest.raises(ValueError, match="unknown sbox"):
        Gost28147(sbox="no-such-box")


def test_key_as_32_bytes() -> None:
    key_bytes = bytes(range(32))
    plain = bytearray(b"12345678")
    original = bytes(plain)
    g = Gost28147()
    g.crypt(plain, key_bytes, encrypt=True, mode=CRYPT_MODE.ECB)
    g.crypt(plain, key_bytes, encrypt=False, mode=CRYPT_MODE.ECB)
    assert bytes(plain) == original
