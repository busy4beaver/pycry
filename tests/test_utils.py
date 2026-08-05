"""Тесты utils."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from rucry import (
    ansi_pad,
    ansi_unpad,
    bytes_to_hex,
    bytes_to_int_list,
    bytes_to_time,
    from_bytearray,
    future,
    hex_to_bytes,
    hex_to_str,
    int_list_to_bytes,
    is_reached,
    now,
    pkcs7_pad,
    pkcs7_unpad,
    random_iv,
    random_key_words,
    str_to_hex,
    time_to_bytes,
    to_bytearray,
    zero_pad,
    zero_unpad,
)


def test_hex_roundtrip() -> None:
    s = "hello мир"
    h = str_to_hex(s)
    assert hex_to_str(h) == s
    assert bytes_to_hex(b"\x00\xff") == "00FF"
    assert hex_to_bytes("00 ff") == bytearray(b"\x00\xff")


def test_bytearray_helpers() -> None:
    ba = to_bytearray("abc")
    assert isinstance(ba, bytearray)
    assert from_bytearray(ba) == b"abc"
    assert from_bytearray(ba, as_str=True) == "abc"


def test_key_words() -> None:
    words = [0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10,
             0x11121314, 0x15161718, 0x191A1B1C, 0x1D1E1F20]
    raw = int_list_to_bytes(words)
    assert len(raw) == 32
    assert bytes_to_int_list(raw) == words


def test_padding() -> None:
    assert zero_pad(b"ab", 8) == bytearray(b"ab\x00\x00\x00\x00\x00\x00")
    assert zero_unpad(zero_pad(b"ab", 8)) == b"ab"

    p = pkcs7_pad(b"ab", 8)
    assert p[-1] == 6
    assert pkcs7_unpad(p) == b"ab"

    p2 = pkcs7_pad(b"12345678", 8)
    assert len(p2) == 16
    assert pkcs7_unpad(p2) == b"12345678"

    with pytest.raises(ValueError):
        pkcs7_unpad(b"\x00" * 8)

    # ANSI X.923: zeros + last byte = pad length
    a = ansi_pad(b"ab", 8)
    assert len(a) == 8
    assert a[-1] == 6
    assert a[-6:-1] == b"\x00" * 5
    assert ansi_unpad(a) == b"ab"

    a2 = ansi_pad(b"12345678", 8)
    assert len(a2) == 16
    assert a2[-1] == 8
    assert ansi_unpad(a2) == b"12345678"

    with pytest.raises(ValueError):
        ansi_unpad(b"\x00" * 5 + b"\xff\x00\x03")  # non-zero in padding zone
    with pytest.raises(ValueError):
        ansi_unpad(b"\x00" * 7 + b"\x09")  # pad_len > block_size


def test_time() -> None:
    t0 = now()
    t1 = future(days=1, hours=2)
    assert t1 > t0
    assert not is_reached(t1)
    assert is_reached(t0 - timedelta(seconds=1))

    t2 = future(months=1, days=3, hours=2)
    assert t2 > t0

    ts = time_to_bytes(t0, length=8)
    assert len(ts) == 8
    back = bytes_to_time(ts, utc=True)
    assert abs(back.timestamp() - t0.replace(tzinfo=timezone.utc).timestamp() if t0.tzinfo is None else t0.timestamp()) < 2


def test_random() -> None:
    iv = random_iv(8)
    assert len(iv) == 8
    assert random_iv(8) != iv  # extremely unlikely equal
    words = random_key_words()
    assert len(words) == 8
