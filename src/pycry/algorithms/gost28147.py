"""
GOST 28147-89 (Magma-style) — port of AUTOCAD alx/CRYPTLIB (.h/.cpp).

Modes: ECB, CBC, OFB, CTR (CRYPT_MODE 0..3).
S-boxes and sync packs match the C++ sources exactly (custom tables, not
the standard GOST CryptoPro boxes).

Usage:
    from pycry import Gost28147, CRYPT_MODE, KEY1

    g = Gost28147()
    data = bytearray(b"hello world!!!")  # padded to 8 for ECB/CBC encrypt
    g.crypt(data, KEY1, encrypt=True, mode=CRYPT_MODE.ECB)
    g.crypt(data, KEY1, encrypt=False, mode=CRYPT_MODE.ECB)

    # High-level hex API (like CRY::encrypt / CRY::decrypt, level 0..2):
    from pycry import encrypt_hex, decrypt_hex
    hex_ct = encrypt_hex("secret", level=0)
    plain = decrypt_hex(hex_ct, level=0)
"""

from __future__ import annotations

from enum import IntEnum
from typing import List, Sequence, Union

FULL_INT = 0xFFFFFFFF
MASK_INT = 0x00000001

# Fixed keys from alx/CRY.cpp (level 0 / 1 / 2)
KEY1: List[int] = [
    0xAF4C019D,
    0x85F9A53E,
    0x68A37F68,
    0x62213BD9,
    0x51A3C0CF,
    0x4F1D58BB,
    0xFD316B50,
    0x5C326771,
]
KEY2: List[int] = [
    0xA169AF87,
    0xFB464C8B,
    0x3A69EE4B,
    0x9602151E,
    0x75E2D3F8,
    0x66EEAD7A,
    0xFF9112C2,
    0xBF82ED25,
]
KEY3: List[int] = [
    0xC284B0E5,
    0x394A97E2,
    0x3C6C0D97,
    0x0D8BC5BF,
    0x4E195971,
    0x8627685F,
    0xA7BDC236,
    0x357E86FD,
]
KEYS = (KEY1, KEY2, KEY3)


class CRYPT_MODE(IntEnum):
    ECB = 0
    CBC = 1
    OFB = 2
    CTR = 3


# Custom S-boxes from CRYPTLIB.h (not standard GOST tables)
_SBOX = (
    (0x35, 0x8B, 0x18, 0xA4, 0x5F, 0xC9, 0xFA, 0x01, 0x23, 0x38, 0xBC, 0xE6, 0x9C, 0xA2, 0x2E, 0x97),
    (0xE1, 0xFC, 0x1F, 0x83, 0x48, 0x07, 0xD4, 0xE5, 0x6E, 0x19, 0x06, 0x74, 0x8B, 0xD7, 0x0D, 0x9A),
    (0x8A, 0xD7, 0x5C, 0x86, 0x11, 0x4E, 0x38, 0xAB, 0x0F, 0xD3, 0x05, 0x0D, 0x44, 0x05, 0x39, 0xA2),
    (0xDD, 0x24, 0x4E, 0x6A, 0x05, 0x01, 0xB9, 0xC8, 0x42, 0xC6, 0x1F, 0x27, 0x83, 0xAC, 0x9A, 0x7E),
    (0x74, 0xDF, 0x0A, 0xEE, 0x79, 0xE3, 0x9C, 0xE7, 0x61, 0x08, 0x5B, 0xD2, 0xF5, 0xCD, 0x76, 0x07),
    (0x58, 0xEA, 0x93, 0x85, 0xAF, 0x0B, 0x47, 0x3E, 0xFD, 0x52, 0x09, 0x3C, 0x06, 0x2A, 0x64, 0xF1),
    (0x76, 0x02, 0xCB, 0x6D, 0x63, 0x85, 0x5C, 0x74, 0xB7, 0xCE, 0xBA, 0x31, 0x0F, 0xC9, 0xED, 0x28),
    (0x9B, 0xF5, 0x36, 0xA1, 0x74, 0xBD, 0x68, 0xAA, 0x59, 0x07, 0x13, 0x0E, 0x02, 0x5F, 0xA8, 0x8C),
)

# Sync pack (CBC / OFB / CTR IV halves), little-endian words as in C++
_SYNCPACK_R = 0xE9FC68AD
_SYNCPACK_L = 0xA54D1B93
_NUM_BIT = 22  # bits taken from gamma for OFB/CTR stream


def mod32(a: int, b: int) -> int:
    """Addition mod 2^32 (matches gost28147::mod32)."""
    s = (a & FULL_INT) + (b & FULL_INT)
    if s <= FULL_INT:
        return s
    return s - FULL_INT + 1


def mod32m1(a: int, b: int) -> int:
    """Addition mod 2^32-1 (matches gost28147::mod32m1)."""
    s = (a & FULL_INT) + (b & FULL_INT)
    if s <= FULL_INT:
        return s
    return s - FULL_INT + 2


def rol(a: int, k: int) -> int:
    """Rotate left by k bits within 32-bit word."""
    a &= FULL_INT
    k &= 31
    return ((a << k) | (a >> (32 - k))) & FULL_INT


def ror(a: int, k: int) -> int:
    """Rotate right by k bits within 32-bit word."""
    a &= FULL_INT
    k &= 31
    return ((a >> k) | (a << (32 - k))) & FULL_INT


def _u32_to_bytes_le(x: int) -> bytes:
    return bytes(
        (
            x & 0xFF,
            (x >> 8) & 0xFF,
            (x >> 16) & 0xFF,
            (x >> 24) & 0xFF,
        )
    )


def _bytes_le_to_u32(b: Sequence[int]) -> int:
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) & FULL_INT


def _block_to_rl(block8: Sequence[int]) -> tuple[int, int]:
    """8 bytes → (R, L) as little-endian uint32 pair (u64.i[0], u64.i[1])."""
    r = _bytes_le_to_u32(block8[0:4])
    l = _bytes_le_to_u32(block8[4:8])
    return r, l


def _rl_to_block(r: int, l: int) -> bytearray:
    return bytearray(_u32_to_bytes_le(r) + _u32_to_bytes_le(l))


class Gost28147:
    """Port of C++ class gost28147 from AUTOCAD CRYPTLIB."""

    def __init__(self) -> None:
        self._T: List[List[int]] = [[0] * 256 for _ in range(4)]
        self._init_subst_table()
        self._rkey = [0] * 32

    def _init_subst_table(self) -> None:
        for i in range(256):
            for j in range(4):
                val = mod32(_SBOX[j * 2][i % 16], 16 * _SBOX[j * 2 + 1][i // 16])
                self._T[j][i] = val & 0xFF

    def _setup_round_keys(self, key: Sequence[int], encrypt: bool, mode: CRYPT_MODE) -> None:
        key = [k & FULL_INT for k in key]
        if mode in (CRYPT_MODE.ECB, CRYPT_MODE.CBC):
            if encrypt:
                for i in range(32):
                    if i < 24:
                        self._rkey[i] = key[i % 8]
                    else:
                        self._rkey[i] = key[7 - (i % 8)]
            else:
                for i in range(32):
                    if i < 8:
                        self._rkey[i] = key[i]
                    else:
                        self._rkey[i] = key[7 - (i % 8)]
        else:
            # OFB / CTR — always encrypt schedule
            for i in range(32):
                if i < 24:
                    self._rkey[i] = key[i % 8]
                else:
                    self._rkey[i] = key[7 - (i % 8)]

    def _base_cycle(self, r: int, l: int) -> tuple[int, int]:
        for i in range(32):
            x = mod32(r, self._rkey[i])
            # substitute each byte via T
            b0 = self._T[0][x & 0xFF]
            b1 = self._T[1][(x >> 8) & 0xFF]
            b2 = self._T[2][(x >> 16) & 0xFF]
            b3 = self._T[3][(x >> 24) & 0xFF]
            x = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
            l = (l ^ rol(x, 11)) & FULL_INT
            r, l = l, r
        return r, l

    def crypt(
        self,
        msg: Union[bytearray, List[int]],
        key: Sequence[int],
        encrypt: bool = True,
        mode: CRYPT_MODE = CRYPT_MODE.ECB,
    ) -> int:
        """
        In-place encrypt/decrypt of msg (bytearray or list of ints 0..255).

        For ECB/CBC encrypt, pads with spaces to a multiple of 8 (as in C++).
        Returns len(msg) after processing (same as GetCrypt).
        """
        if isinstance(msg, list):
            # allow list[int] by working on a bytearray view then copy back
            ba = bytearray(msg)
            n = self.crypt(ba, key, encrypt=encrypt, mode=mode)
            msg[:] = list(ba)
            return n

        if not msg:
            return 0

        mode = CRYPT_MODE(mode)
        if mode in (CRYPT_MODE.ECB, CRYPT_MODE.CBC) and encrypt and (len(msg) % 8):
            pad = 8 - (len(msg) % 8)
            msg.extend(b" " * pad)

        self._setup_round_keys(key, encrypt, mode)

        if mode == CRYPT_MODE.ECB:
            self._ecb(msg, encrypt)
        elif mode == CRYPT_MODE.CBC:
            self._cbc(msg, encrypt)
        elif mode == CRYPT_MODE.OFB:
            self._ofb_ctr(msg, use_counter=False)
        elif mode == CRYPT_MODE.CTR:
            self._ofb_ctr(msg, use_counter=True)
        else:
            raise ValueError(f"unknown mode: {mode!r}")

        return len(msg)

    def _ecb(self, msg: bytearray, encrypt: bool) -> None:
        for off in range(0, len(msg), 8):
            block = msg[off : off + 8]
            r, l = _block_to_rl(block)
            if encrypt:
                r, l = self._base_cycle(r, l)
            else:
                # decrypt: pass (L, R) as in C++ base_cycle(u64.i[1], u64.i[0]);
                # after 32 rounds the recovered plain is (L_out, R_out) relative
                # to those refs → swap back to (R, L) memory order.
                r, l = self._base_cycle(l, r)
                r, l = l, r
            msg[off : off + 8] = _rl_to_block(r, l)

    def _cbc(self, msg: bytearray, encrypt: bool) -> None:
        if encrypt:
            prev = bytearray(_u32_to_bytes_le(_SYNCPACK_R) + _u32_to_bytes_le(_SYNCPACK_L))
            for off in range(0, len(msg), 8):
                for i in range(8):
                    prev[i] ^= msg[off + i]
                r, l = _block_to_rl(prev)
                r, l = self._base_cycle(r, l)
                prev = _rl_to_block(r, l)
                msg[off : off + 8] = prev
        else:
            out = bytearray()
            for off in range(0, len(msg), 8):
                block = msg[off : off + 8]
                r, l = _block_to_rl(block)
                r, l = self._base_cycle(l, r)  # decrypt order (L,R refs)
                r, l = l, r
                plain = _rl_to_block(r, l)
                if off == 0:
                    plain[0] ^= _SYNCPACK_R & 0xFF
                    plain[1] ^= (_SYNCPACK_R >> 8) & 0xFF
                    plain[2] ^= (_SYNCPACK_R >> 16) & 0xFF
                    plain[3] ^= (_SYNCPACK_R >> 24) & 0xFF
                    plain[4] ^= _SYNCPACK_L & 0xFF
                    plain[5] ^= (_SYNCPACK_L >> 8) & 0xFF
                    plain[6] ^= (_SYNCPACK_L >> 16) & 0xFF
                    plain[7] ^= (_SYNCPACK_L >> 24) & 0xFF
                else:
                    for i in range(8):
                        plain[i] ^= msg[off + i - 8]
                out.extend(plain)
            msg[:] = out

    def _ofb_ctr(self, msg: bytearray, use_counter: bool) -> None:
        """OFB / CTR stream: build bit vector then XOR into message (C++ layout)."""
        need_bits = len(msg) * 8
        bits: List[bool] = []
        counter = 0

        while len(bits) < need_bits:
            if use_counter:
                r = mod32(_SYNCPACK_R, counter)
                l = mod32(_SYNCPACK_L, counter)
                counter += 1
            else:
                if not bits:
                    r, l = _SYNCPACK_R, _SYNCPACK_L
                # else r,l already updated by previous base_cycle
            r, l = self._base_cycle(r, l)
            u32 = (l >> (32 - _NUM_BIT)) & FULL_INT
            for i in range(_NUM_BIT):
                # matches: MASK_INT & (u32.i >> (num_bit - i))
                shift = _NUM_BIT - i
                bit = bool((MASK_INT & (u32 >> shift)) == 1) if shift >= 0 else False
                bits.append(bit)
                if len(bits) >= need_bits:
                    break

        for bi, byte_i in enumerate(range(len(msg))):
            mask = 0
            base = bi * 8
            for i in range(8):
                if bits[base + i]:
                    mask += 1
                mask = (mask << 1) & 0xFF
            msg[byte_i] ^= mask


# ---------------------------------------------------------------------------
# High-level helpers (CRY::encrypt / CRY::decrypt style)
# ---------------------------------------------------------------------------

def bytes_to_hex(data: Sequence[int]) -> str:
    return "".join(f"{b:02X}" for b in data)


def hex_to_bytes(hex_str: str) -> bytearray:
    hex_str = hex_str.strip()
    if len(hex_str) % 2:
        raise ValueError("hex string length must be even")
    out = bytearray()
    for i in range(0, len(hex_str), 2):
        h0, h1 = hex_str[i], hex_str[i + 1]
        n0 = ord(h0) - (ord("A") - 10 if h0 > "9" else ord("0"))
        n1 = ord(h1) - (ord("A") - 10 if h1 > "9" else ord("0"))
        # support lowercase too
        if h0 >= "a":
            n0 = ord(h0) - (ord("a") - 10)
        if h1 >= "a":
            n1 = ord(h1) - (ord("a") - 10)
        out.append(((n0 & 0xF) << 4) | (n1 & 0xF))
    return out


def encrypt_hex(message: Union[str, bytes, bytearray], level: int = 0) -> str:
    """
    Encrypt message with KEY{level+1}, mode=level (0=ECB, 1=CBC, 2=OFB, 3=CTR).
    Returns uppercase hex ciphertext (same as CRY::encrypt).
    """
    key = KEYS[level if 0 <= level < 3 else 0]
    mode = CRYPT_MODE(level if 0 <= level <= 3 else 0)
    if isinstance(message, str):
        data = bytearray(message.encode("utf-8"))
    else:
        data = bytearray(message)
    Gost28147().crypt(data, key, encrypt=True, mode=mode)
    return bytes_to_hex(data)


def decrypt_hex(hex_msg: str, level: int = 0) -> str:
    """
    Decrypt hex ciphertext; returns latin-1 / raw byte string like CRY::decrypt
    (binary-safe via latin-1).
    """
    key = KEYS[level if 0 <= level < 3 else 0]
    mode = CRYPT_MODE(level if 0 <= level <= 3 else 0)
    data = hex_to_bytes(hex_msg)
    Gost28147().crypt(data, key, encrypt=False, mode=mode)
    return data.decode("latin-1")


def encrypt_bytes(
    message: Union[str, bytes, bytearray],
    key: Sequence[int] = KEY1,
    mode: CRYPT_MODE = CRYPT_MODE.ECB,
) -> bytes:
    data = bytearray(message.encode("utf-8") if isinstance(message, str) else message)
    Gost28147().crypt(data, key, encrypt=True, mode=mode)
    return bytes(data)


def decrypt_bytes(
    ciphertext: Union[bytes, bytearray],
    key: Sequence[int] = KEY1,
    mode: CRYPT_MODE = CRYPT_MODE.ECB,
) -> bytes:
    data = bytearray(ciphertext)
    Gost28147().crypt(data, key, encrypt=False, mode=mode)
    return bytes(data)


if __name__ == "__main__":
    # Self-check: ECB round-trip
    g = Gost28147()
    plain = bytearray(b"1234567890123456")  # 16 bytes, two blocks
    original = bytes(plain)
    g.crypt(plain, KEY1, encrypt=True, mode=CRYPT_MODE.ECB)
    assert plain != original
    g.crypt(plain, KEY1, encrypt=False, mode=CRYPT_MODE.ECB)
    assert bytes(plain) == original, (plain, original)

    # High-level hex API
    ct = encrypt_hex("hello gost", level=0)
    pt = decrypt_hex(ct, level=0)
    assert pt.rstrip(" ") == "hello gost" or "hello gost" in pt
    print("self-check OK")
    print("ECB encrypt_hex('hello gost') =", ct)
    print("decrypt ->", repr(pt))
