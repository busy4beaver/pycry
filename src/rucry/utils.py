"""
Вспомогательные утилиты rucry.

- Конвертация строк / байт / hex / bytearray
- Время: сейчас, будущее, проверка достижения
- Паддинг: zero, PKCS#7, ANSI X.923
- Случайная синхропосылка
"""

from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Sequence, Union

# ---------------------------------------------------------------------------
# Bytes / hex / string
# ---------------------------------------------------------------------------

def to_bytearray(data: Union[str, bytes, bytearray, Sequence[int]], encoding: str = "utf-8") -> bytearray:
    """Привести данные к bytearray."""
    if isinstance(data, bytearray):
        return data
    if isinstance(data, bytes):
        return bytearray(data)
    if isinstance(data, str):
        return bytearray(data.encode(encoding))
    return bytearray(int(x) & 0xFF for x in data)


def from_bytearray(
    data: Union[bytes, bytearray],
    *,
    as_str: bool = False,
    encoding: str = "utf-8",
    errors: str = "strict",
) -> Union[bytes, str]:
    """bytearray/bytes → bytes или str."""
    b = bytes(data)
    if as_str:
        return b.decode(encoding, errors=errors)
    return b


def str_to_hex(s: str, encoding: str = "utf-8") -> str:
    """Строка → hex-строка (верхний регистр, без пробелов)."""
    return bytes_to_hex(s.encode(encoding))


def hex_to_str(hex_str: str, encoding: str = "utf-8", errors: str = "strict") -> str:
    """Hex-строка → обычная строка."""
    return hex_to_bytes(hex_str).decode(encoding, errors=errors)


def bytes_to_hex(data: Sequence[int]) -> str:
    """Байты → hex (верхний регистр)."""
    return "".join(f"{b:02X}" for b in data)


def hex_to_bytes(hex_str: str) -> bytearray:
    """Hex-строка → bytearray. Пробелы игнорируются."""
    hex_str = hex_str.strip().replace(" ", "").replace("\n", "").replace("\t", "")
    if len(hex_str) % 2:
        raise ValueError("hex string length must be even")
    return bytearray.fromhex(hex_str)


def int_list_to_bytes(words: Sequence[int], *, byteorder: str = "little") -> bytes:
    """Список uint32 → 32 байта (для ключа GOST)."""
    if len(words) != 8:
        raise ValueError("expected 8 uint32 words")
    out = bytearray()
    for w in words:
        out.extend(int(w).to_bytes(4, byteorder=byteorder))
    return bytes(out)


def bytes_to_int_list(data: Sequence[int], *, byteorder: str = "little") -> list[int]:
    """32 байта → список 8 uint32."""
    if len(data) != 32:
        raise ValueError("expected 32 bytes")
    b = bytes(data)
    return [int.from_bytes(b[i : i + 4], byteorder=byteorder) for i in range(0, 32, 4)]


# ---------------------------------------------------------------------------
# Padding
# ---------------------------------------------------------------------------

def zero_pad(data: Union[bytes, bytearray], block_size: int = 8) -> bytearray:
    """Дополнить нулями до кратности block_size."""
    ba = to_bytearray(data)
    rem = len(ba) % block_size
    if rem:
        ba.extend(b"\x00" * (block_size - rem))
    return ba


def zero_unpad(data: Union[bytes, bytearray]) -> bytearray:
    """Снять trailing-нули (неоднозначно, если данные сами заканчивались нулями)."""
    ba = to_bytearray(data)
    return ba.rstrip(b"\x00")


def pkcs7_pad(data: Union[bytes, bytearray], block_size: int = 8) -> bytearray:
    """
    PKCS#7 паддинг.
    Всегда добавляет хотя бы 1 байт. Если длина уже кратна блоку —
    добавляется целый блок со значением block_size.
    """
    ba = to_bytearray(data)
    pad_len = block_size - (len(ba) % block_size)
    ba.extend(bytes([pad_len]) * pad_len)
    return ba


def pkcs7_unpad(data: Union[bytes, bytearray], block_size: int = 8) -> bytearray:
    """Снять PKCS#7 паддинг. Бросает ValueError при некорректном паддинге."""
    ba = to_bytearray(data)
    if not ba or len(ba) % block_size:
        raise ValueError("invalid PKCS#7 data length")
    pad_len = ba[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError(f"invalid PKCS#7 pad length: {pad_len}")
    if ba[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS#7 padding bytes")
    return ba[:-pad_len]


def ansi_pad(data: Union[bytes, bytearray], block_size: int = 8) -> bytearray:
    """
    ANSI X.923 паддинг.

    Нули, последний байт = длина паддинга (включая сам этот байт).
    Если длина уже кратна блоку — добавляется целый блок:
    00 00 … 00 <block_size>.
    """
    ba = to_bytearray(data)
    pad_len = block_size - (len(ba) % block_size)
    ba.extend(b"\x00" * (pad_len - 1))
    ba.append(pad_len)
    return ba


def ansi_unpad(data: Union[bytes, bytearray], block_size: int = 8) -> bytearray:
    """Снять ANSI X.923 паддинг. Бросает ValueError при некорректном паддинге."""
    ba = to_bytearray(data)
    if not ba or len(ba) % block_size:
        raise ValueError("invalid ANSI X.923 data length")
    pad_len = ba[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError(f"invalid ANSI X.923 pad length: {pad_len}")
    if ba[-pad_len:-1] != b"\x00" * (pad_len - 1):
        raise ValueError("invalid ANSI X.923 padding bytes")
    return ba[:-pad_len]


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------

def now(*, utc: bool = False) -> datetime:
    """Текущее время (local или UTC)."""
    if utc:
        return datetime.now(timezone.utc)
    return datetime.now()


def future(
    *,
    years: int = 0,
    months: int = 0,
    days: int = 0,
    hours: int = 0,
    minutes: int = 0,
    seconds: int = 0,
    utc: bool = False,
) -> datetime:
    """
    Время через указанный интервал от сейчас.

    Пример:
        future(months=1, days=3, hours=2)
    """
    dt = now(utc=utc)

    # months / years — без внешних зависимостей
    if years or months:
        total_months = dt.month - 1 + months + years * 12
        year = dt.year + total_months // 12
        month = total_months % 12 + 1
        # ограничить день по длине целевого месяца
        days_in_month = [31, 29 if _is_leap(year) else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        day = min(dt.day, days_in_month[month - 1])
        dt = dt.replace(year=year, month=month, day=day)

    return dt + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)


def is_reached(target: datetime, current: Optional[datetime] = None) -> bool:
    """Достигло ли текущее время (или переданное) значения target."""
    if current is None:
        # сравниваем в одной зоне
        if target.tzinfo is not None:
            current = now(utc=True)
            if target.tzinfo != timezone.utc:
                target = target.astimezone(timezone.utc)
        else:
            current = now(utc=False)
    return current >= target


def time_to_bytes(dt: datetime, *, length: int = 8) -> bytes:
    """
    Упаковать datetime в байты (unix timestamp, big-endian).
    length=4 → uint32, length=8 → uint64.
    """
    ts = int(dt.timestamp())
    if length not in (4, 8):
        raise ValueError("length must be 4 or 8")
    return ts.to_bytes(length, "big", signed=False)


def bytes_to_time(data: Sequence[int], *, utc: bool = True) -> datetime:
    """Распаковать байты (unix timestamp) обратно в datetime."""
    b = bytes(data)
    if len(b) not in (4, 8):
        raise ValueError("expected 4 or 8 bytes")
    ts = int.from_bytes(b, "big", signed=False)
    if utc:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    return datetime.fromtimestamp(ts)


def _is_leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


# ---------------------------------------------------------------------------
# Random IV (синхропосылка)
# ---------------------------------------------------------------------------

def random_iv(length: int = 8) -> bytes:
    """Криптографически стойкая случайная синхропосылка."""
    if length < 1:
        raise ValueError("length must be >= 1")
    return os.urandom(length)


def random_key_words() -> list[int]:
    """Случайный ключ GOST как 8 × uint32 (little-endian слова)."""
    raw = os.urandom(32)
    return bytes_to_int_list(raw, byteorder="little")
