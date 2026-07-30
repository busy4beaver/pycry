"""
GOST 28147-89 — блочный шифр (64-bit block, 256-bit key).

Режимы: ECB, CBC, OFB, CTR.
S-боксы и ключ передаются снаружи (или выбираются из предопределённых наборов).

Usage:
    from pycry import Gost28147, CRYPT_MODE, SBOX_CRYPTOPRO_A

    key = [0x01234567, 0x89ABCDEF, 0x01234567, 0x89ABCDEF,
           0x01234567, 0x89ABCDEF, 0x01234567, 0x89ABCDEF]
    g = Gost28147(sbox="cryptopro-a")  # или SBOX_CRYPTOPRO_A, или свой 8×16
    data = bytearray(b"hello!!!")       # 8 байт
    g.crypt(data, key, encrypt=True, mode=CRYPT_MODE.ECB)
    g.crypt(data, key, encrypt=False, mode=CRYPT_MODE.ECB)
"""

from __future__ import annotations

from enum import IntEnum
from typing import List, Optional, Sequence, Tuple, Union

FULL_INT = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Predefined S-boxes (8 × 16, nibble → nibble). RFC 4357 / common practice.
# ---------------------------------------------------------------------------

SBOX_TEST: Tuple[Tuple[int, ...], ...] = (
    (4, 2, 15, 5, 9, 1, 0, 8, 14, 3, 11, 12, 13, 7, 10, 6),
    (12, 9, 15, 14, 8, 1, 3, 10, 2, 7, 4, 13, 6, 0, 11, 5),
    (13, 8, 14, 12, 7, 3, 9, 10, 1, 5, 2, 4, 6, 15, 0, 11),
    (14, 9, 11, 2, 5, 15, 7, 1, 0, 13, 12, 6, 10, 4, 3, 8),
    (3, 14, 5, 9, 6, 8, 0, 13, 10, 11, 7, 12, 2, 1, 15, 4),
    (8, 15, 6, 11, 1, 9, 12, 5, 13, 3, 7, 10, 0, 14, 2, 4),
    (9, 11, 12, 0, 3, 6, 7, 5, 4, 8, 14, 15, 1, 10, 2, 13),
    (12, 6, 5, 2, 11, 0, 9, 13, 3, 14, 7, 10, 15, 4, 1, 8),
)

SBOX_CRYPTOPRO_A: Tuple[Tuple[int, ...], ...] = (
    (9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5),
    (3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1),
    (14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9),
    (14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6),
    (11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6),
    (3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6),
    (1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14),
    (11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4),
)

SBOX_CRYPTOPRO_B: Tuple[Tuple[int, ...], ...] = (
    (8, 4, 11, 1, 3, 5, 0, 9, 2, 14, 10, 12, 13, 6, 7, 15),
    (0, 1, 2, 10, 4, 13, 5, 12, 9, 7, 3, 15, 11, 8, 6, 14),
    (14, 12, 0, 10, 9, 2, 13, 11, 7, 5, 8, 15, 3, 6, 1, 4),
    (7, 5, 0, 13, 11, 6, 1, 2, 3, 10, 12, 15, 4, 14, 9, 8),
    (2, 7, 12, 15, 9, 5, 10, 11, 1, 4, 0, 13, 6, 8, 14, 3),
    (8, 3, 2, 6, 4, 13, 14, 11, 12, 1, 7, 15, 10, 0, 9, 5),
    (5, 2, 10, 11, 9, 1, 12, 3, 7, 4, 13, 0, 6, 15, 8, 14),
    (0, 4, 11, 14, 8, 3, 7, 1, 10, 2, 9, 6, 15, 13, 5, 12),
)

SBOX_CRYPTOPRO_C: Tuple[Tuple[int, ...], ...] = (
    (1, 11, 12, 2, 9, 13, 0, 15, 4, 5, 8, 14, 10, 7, 6, 3),
    (0, 1, 7, 13, 11, 4, 5, 2, 8, 14, 15, 12, 9, 10, 6, 3),
    (8, 2, 5, 0, 4, 9, 15, 10, 3, 7, 12, 13, 6, 14, 1, 11),
    (3, 6, 0, 1, 5, 13, 10, 8, 11, 2, 9, 7, 14, 15, 12, 4),
    (8, 13, 11, 0, 4, 5, 1, 2, 9, 3, 12, 14, 6, 15, 10, 7),
    (12, 9, 11, 1, 8, 14, 2, 4, 7, 3, 6, 5, 10, 0, 15, 13),
    (10, 9, 6, 8, 13, 14, 2, 0, 15, 3, 5, 11, 4, 1, 12, 7),
    (7, 4, 0, 5, 10, 2, 15, 14, 12, 6, 1, 11, 13, 9, 3, 8),
)

SBOX_CRYPTOPRO_D: Tuple[Tuple[int, ...], ...] = (
    (15, 12, 2, 10, 6, 4, 5, 0, 7, 9, 14, 13, 1, 11, 8, 3),
    (11, 6, 3, 4, 12, 15, 14, 2, 7, 13, 8, 0, 5, 10, 9, 1),
    (1, 12, 11, 0, 15, 14, 6, 5, 10, 13, 4, 8, 9, 3, 7, 2),
    (1, 5, 14, 12, 10, 7, 0, 13, 6, 2, 11, 4, 9, 3, 15, 8),
    (0, 12, 8, 9, 13, 2, 10, 11, 7, 3, 6, 5, 4, 14, 15, 1),
    (8, 0, 15, 3, 2, 5, 14, 11, 1, 10, 4, 7, 12, 9, 13, 6),
    (3, 0, 6, 15, 1, 14, 9, 2, 13, 8, 12, 4, 11, 10, 5, 7),
    (1, 10, 6, 8, 15, 11, 0, 4, 12, 3, 5, 9, 7, 13, 2, 14),
)

# Short aliases → tables
SBOXES = {
    "test": SBOX_TEST,
    "cryptopro-a": SBOX_CRYPTOPRO_A,
    "cryptopro-b": SBOX_CRYPTOPRO_B,
    "cryptopro-c": SBOX_CRYPTOPRO_C,
    "cryptopro-d": SBOX_CRYPTOPRO_D,
    # long RFC-style names
    "id-Gost28147-89-TestParamSet": SBOX_TEST,
    "id-Gost28147-89-CryptoPro-A-ParamSet": SBOX_CRYPTOPRO_A,
    "id-Gost28147-89-CryptoPro-B-ParamSet": SBOX_CRYPTOPRO_B,
    "id-Gost28147-89-CryptoPro-C-ParamSet": SBOX_CRYPTOPRO_C,
    "id-Gost28147-89-CryptoPro-D-ParamSet": SBOX_CRYPTOPRO_D,
}

DEFAULT_SBOX = "cryptopro-a"


class CRYPT_MODE(IntEnum):
    ECB = 0
    CBC = 1
    OFB = 2
    CTR = 3


def mod32(a: int, b: int) -> int:
    """(a + b) mod 2^32."""
    return (a + b) & FULL_INT


def rol(a: int, k: int) -> int:
    a &= FULL_INT
    k &= 31
    return ((a << k) | (a >> (32 - k))) & FULL_INT


def ror(a: int, k: int) -> int:
    a &= FULL_INT
    k &= 31
    return ((a >> k) | (a << (32 - k))) & FULL_INT


def _u32_le(x: int) -> bytes:
    return bytes((x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF))


def _le_u32(b: Sequence[int]) -> int:
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) & FULL_INT


def _block_to_nl(block8: Sequence[int]) -> Tuple[int, int]:
    """8 bytes LE → (N1, N2) — first half N1, second N2 (GOST notation)."""
    return _le_u32(block8[0:4]), _le_u32(block8[4:8])


def _nl_to_block(n1: int, n2: int) -> bytearray:
    return bytearray(_u32_le(n1) + _u32_le(n2))


def resolve_sbox(
    sbox: Union[str, Sequence[Sequence[int]], None] = None,
) -> Tuple[Tuple[int, ...], ...]:
    """
    Resolve S-box parameter to 8×16 tables.

    * ``None`` / omitted → DEFAULT_SBOX (``cryptopro-a``)
    * ``str`` → name from :data:`SBOXES`
    * sequence of 8 sequences of 16 ints 0..15 → custom tables
    """
    if sbox is None:
        return SBOXES[DEFAULT_SBOX]
    if isinstance(sbox, str):
        key = sbox.strip()
        if key not in SBOXES:
            known = ", ".join(sorted({k for k in SBOXES if not k.startswith("id-")}))
            raise ValueError(f"unknown sbox {sbox!r}; known: {known}")
        return SBOXES[key]
    tables = tuple(tuple(int(x) & 0xF for x in row) for row in sbox)
    if len(tables) != 8 or any(len(r) != 16 for r in tables):
        raise ValueError("custom sbox must be 8 rows × 16 values (0..15)")
    return tables  # type: ignore[return-value]


def normalize_key(key: Sequence[int]) -> List[int]:
    """Key = 8 × uint32 (256 bit). Accepts 8 ints or 32 bytes-as-ints."""
    if len(key) == 8:
        return [int(k) & FULL_INT for k in key]
    if len(key) == 32:
        out = []
        for i in range(0, 32, 4):
            out.append(_le_u32(key[i : i + 4]))
        return out
    raise ValueError("key must be 8×uint32 or 32 bytes")


class Gost28147:
    """
    GOST 28147-89.

    Parameters
    ----------
    sbox :
        Name (``\"cryptopro-a\"``, ``\"test\"``, …) or custom 8×16 tables.
        Default: CryptoPro-A.
    """

    def __init__(
        self,
        sbox: Union[str, Sequence[Sequence[int]], None] = None,
    ) -> None:
        self._sbox = resolve_sbox(sbox)
        self._rkey = [0] * 32

    def _substitute(self, x: int) -> int:
        """Apply 8 nibble S-boxes to 32-bit word (standard GOST)."""
        s = self._sbox
        return (
            (s[0][(x >> 0) & 0xF] << 0)
            | (s[1][(x >> 4) & 0xF] << 4)
            | (s[2][(x >> 8) & 0xF] << 8)
            | (s[3][(x >> 12) & 0xF] << 12)
            | (s[4][(x >> 16) & 0xF] << 16)
            | (s[5][(x >> 20) & 0xF] << 20)
            | (s[6][(x >> 24) & 0xF] << 24)
            | (s[7][(x >> 28) & 0xF] << 28)
        )

    def _setup_round_keys(self, key: Sequence[int], encrypt: bool) -> None:
        k = normalize_key(key)
        if encrypt:
            for i in range(24):
                self._rkey[i] = k[i % 8]
            for i in range(8):
                self._rkey[24 + i] = k[7 - i]
        else:
            for i in range(8):
                self._rkey[i] = k[i]
            for i in range(24):
                self._rkey[8 + i] = k[7 - (i % 8)]

    def _base_cycle(self, n1: int, n2: int) -> Tuple[int, int]:
        """32-round Feistel (encrypt or decrypt depending on key schedule)."""
        for i in range(32):
            x = mod32(n1, self._rkey[i])
            x = self._substitute(x)
            x = rol(x, 11)
            n1, n2 = n2 ^ x, n1
        return n2, n1

    def crypt(
        self,
        msg: Union[bytearray, List[int]],
        key: Sequence[int],
        encrypt: bool = True,
        mode: CRYPT_MODE = CRYPT_MODE.ECB,
        iv: Optional[Sequence[int]] = None,
        pad: bool = True,
    ) -> int:
        """
        In-place encrypt/decrypt.

        Parameters
        ----------
        msg :
            ``bytearray`` (preferred) or ``list[int]`` of bytes.
        key :
            8×uint32 or 32 bytes.
        encrypt :
            ``True`` — encrypt, ``False`` — decrypt.
        mode :
            ECB / CBC / OFB / CTR.
        iv :
            8-byte IV for CBC/OFB/CTR (default: zeros).
        pad :
            For ECB/CBC encrypt, pad with ``0x00`` to multiple of 8 if needed.

        Returns
        -------
        int
            Length of ``msg`` after processing.
        """
        if isinstance(msg, list):
            ba = bytearray(msg)
            n = self.crypt(ba, key, encrypt=encrypt, mode=mode, iv=iv, pad=pad)
            msg[:] = list(ba)
            return n

        if not msg:
            return 0

        mode = CRYPT_MODE(mode)
        if (
            pad
            and mode in (CRYPT_MODE.ECB, CRYPT_MODE.CBC)
            and encrypt
            and (len(msg) % 8)
        ):
            msg.extend(b"\x00" * (8 - (len(msg) % 8)))

        if len(msg) % 8 and mode in (CRYPT_MODE.ECB, CRYPT_MODE.CBC):
            raise ValueError("message length must be multiple of 8 for ECB/CBC")

        self._setup_round_keys(
            key, encrypt=encrypt if mode in (CRYPT_MODE.ECB, CRYPT_MODE.CBC) else True
        )

        iv_ba = bytearray(iv) if iv is not None else bytearray(8)
        if len(iv_ba) != 8:
            raise ValueError("iv must be 8 bytes")

        if mode == CRYPT_MODE.ECB:
            self._ecb(msg)
        elif mode == CRYPT_MODE.CBC:
            self._cbc(msg, encrypt, iv_ba)
        elif mode == CRYPT_MODE.OFB:
            self._ofb(msg, iv_ba)
        elif mode == CRYPT_MODE.CTR:
            self._ctr(msg, iv_ba)
        else:
            raise ValueError(f"unknown mode: {mode!r}")

        return len(msg)

    def _ecb(self, msg: bytearray) -> None:
        for off in range(0, len(msg), 8):
            n1, n2 = _block_to_nl(msg[off : off + 8])
            n1, n2 = self._base_cycle(n1, n2)
            msg[off : off + 8] = _nl_to_block(n1, n2)

    def _cbc(self, msg: bytearray, encrypt: bool, iv: bytearray) -> None:
        prev = bytearray(iv)
        if encrypt:
            for off in range(0, len(msg), 8):
                for i in range(8):
                    msg[off + i] ^= prev[i]
                n1, n2 = _block_to_nl(msg[off : off + 8])
                n1, n2 = self._base_cycle(n1, n2)
                block = _nl_to_block(n1, n2)
                msg[off : off + 8] = block
                prev = block
        else:
            out = bytearray()
            for off in range(0, len(msg), 8):
                block = msg[off : off + 8]
                n1, n2 = _block_to_nl(block)
                n1, n2 = self._base_cycle(n1, n2)
                plain = _nl_to_block(n1, n2)
                for i in range(8):
                    plain[i] ^= prev[i]
                out.extend(plain)
                prev = bytearray(block)
            msg[:] = out

    def _ofb(self, msg: bytearray, iv: bytearray) -> None:
        """Output feedback: keystream from repeated encrypt(IV)."""
        state = bytearray(iv)
        for off in range(0, len(msg), 8):
            n1, n2 = _block_to_nl(state)
            n1, n2 = self._base_cycle(n1, n2)
            state = _nl_to_block(n1, n2)
            chunk = min(8, len(msg) - off)
            for i in range(chunk):
                msg[off + i] ^= state[i]

    def _ctr(self, msg: bytearray, iv: bytearray) -> None:
        """Counter mode: encrypt(IV + counter)."""
        counter = int.from_bytes(iv, "big")
        for off in range(0, len(msg), 8):
            ctr_block = counter.to_bytes(8, "big")
            n1, n2 = _block_to_nl(ctr_block)
            n1, n2 = self._base_cycle(n1, n2)
            gamma = _nl_to_block(n1, n2)
            chunk = min(8, len(msg) - off)
            for i in range(chunk):
                msg[off + i] ^= gamma[i]
            counter = (counter + 1) & ((1 << 64) - 1)


def bytes_to_hex(data: Sequence[int]) -> str:
    return "".join(f"{b:02X}" for b in data)


def hex_to_bytes(hex_str: str) -> bytearray:
    hex_str = hex_str.strip().replace(" ", "")
    if len(hex_str) % 2:
        raise ValueError("hex string length must be even")
    return bytearray.fromhex(hex_str)


def encrypt_bytes(
    message: Union[str, bytes, bytearray],
    key: Sequence[int],
    mode: CRYPT_MODE = CRYPT_MODE.ECB,
    sbox: Union[str, Sequence[Sequence[int]], None] = None,
    iv: Optional[Sequence[int]] = None,
) -> bytes:
    data = bytearray(message.encode("utf-8") if isinstance(message, str) else message)
    Gost28147(sbox=sbox).crypt(data, key, encrypt=True, mode=mode, iv=iv)
    return bytes(data)


def decrypt_bytes(
    ciphertext: Union[bytes, bytearray],
    key: Sequence[int],
    mode: CRYPT_MODE = CRYPT_MODE.ECB,
    sbox: Union[str, Sequence[Sequence[int]], None] = None,
    iv: Optional[Sequence[int]] = None,
) -> bytes:
    data = bytearray(ciphertext)
    Gost28147(sbox=sbox).crypt(data, key, encrypt=False, mode=mode, iv=iv, pad=False)
    return bytes(data)


def encrypt_hex(
    message: Union[str, bytes, bytearray],
    key: Sequence[int],
    mode: CRYPT_MODE = CRYPT_MODE.ECB,
    sbox: Union[str, Sequence[Sequence[int]], None] = None,
    iv: Optional[Sequence[int]] = None,
) -> str:
    return bytes_to_hex(encrypt_bytes(message, key, mode=mode, sbox=sbox, iv=iv))


def decrypt_hex(
    hex_msg: str,
    key: Sequence[int],
    mode: CRYPT_MODE = CRYPT_MODE.ECB,
    sbox: Union[str, Sequence[Sequence[int]], None] = None,
    iv: Optional[Sequence[int]] = None,
) -> bytes:
    return decrypt_bytes(hex_to_bytes(hex_msg), key, mode=mode, sbox=sbox, iv=iv)


if __name__ == "__main__":
    key = [0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10,
           0x11121314, 0x15161718, 0x191A1B1C, 0x1D1E1F20]
    g = Gost28147(sbox="cryptopro-a")
    plain = bytearray(b"12345678ABCDEFGH")
    original = bytes(plain)
    g.crypt(plain, key, encrypt=True, mode=CRYPT_MODE.ECB)
    assert plain != original
    g.crypt(plain, key, encrypt=False, mode=CRYPT_MODE.ECB)
    assert bytes(plain) == original
    print("self-check OK")
