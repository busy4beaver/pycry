# **rucry**

Криптографические примитивы на чистом Python.

[![Tag](https://img.shields.io/github/v/tag/busy4beaver/rucry?color=00c2e8)](https://github.com/busy4beaver/rucry)
[![Supported Python versions](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=FFE873)](https://www.python.org/downloads/)
[![Licence](https://img.shields.io/github/license/busy4beaver/rucry.svg)](LICENSE)

---

## Содержание

- [Особенности](#особенности)
- [Структура пакета](#структура-пакета)
- [Установка](#установка)
- [Быстрый старт](#быстрый-старт)
- [GOST 28147-89](#gost-28147-89)
- [Тесты](#тесты)
- [Поддержать проект](#-поддержать-проект)

---

## Особенности

| Область | Что даёт |
|---------|----------|
| **GOST 28147-89** | ECB / CBC / OFB / CTR |
| **S-боксы** | предопределённые наборы (CryptoPro A–D, Test) или свои 8×16 |
| **Ключ** | 8×uint32 или 32 байта — передаётся снаружи |
| **Чистый Python** | без нативных расширений и внешних crypto-зависимостей |
| **Hex API** | `encrypt_hex` / `decrypt_hex` |
| **Расширяемость** | `algorithms/` — сюда добавляются новые шифры |

---

## Структура пакета

```text
src/rucry/
├── __init__.py              # публичный API
├── __version__.py
├── py.typed
└── algorithms/
    ├── __init__.py
    └── gost28147.py         # GOST 28147-89

tests/
└── test_gost28147.py

.github/
├── FUNDING.yml
└── workflows/
    └── workflow.yml         # Publish to PyPI (workflow_dispatch)
```

### Публичный импорт

```python
from rucry import (
    Gost28147,
    CRYPT_MODE,
    SBOXES, SBOX_CRYPTOPRO_A, SBOX_TEST,
    encrypt_hex, decrypt_hex,
    encrypt_bytes, decrypt_bytes,
    resolve_sbox, normalize_key,
)
```

---

## Установка

Из GitHub:

```bash
pip install git+https://github.com/busy4beaver/rucry.git
```

Локально (editable):

```bash
git clone https://github.com/busy4beaver/rucry.git
cd rucry
pip install -e .
```

Зависимостей нет (stdlib only). Для тестов: `pip install pytest`.

---

## Быстрый старт

```python
from rucry import Gost28147, CRYPT_MODE

key = [
    0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10,
    0x11121314, 0x15161718, 0x191A1B1C, 0x1D1E1F20,
]

g = Gost28147(sbox="cryptopro-a")  # default
data = bytearray(b"12345678")
g.crypt(data, key, encrypt=True, mode=CRYPT_MODE.ECB)
g.crypt(data, key, encrypt=False, mode=CRYPT_MODE.ECB)

# Hex API
from rucry import encrypt_hex, decrypt_hex
ct = encrypt_hex("12345678", key, mode=CRYPT_MODE.ECB)
pt = decrypt_hex(ct, key, mode=CRYPT_MODE.ECB)
```

---

## GOST 28147-89

Блочный шифр: блок 64 бит, ключ 256 бит. S-боксы — параметр алгоритма
(в стандарте не зафиксированы).

### Режимы

| `CRYPT_MODE` | Значение | Примечание |
|--------------|----------|------------|
| `ECB` | 0 | при encrypt дополнение нулями до кратности 8 |
| `CBC` | 1 | нужен `iv` (8 байт; default — нули) |
| `OFB` | 2 | потоковый; encrypt ≡ decrypt |
| `CTR` | 3 | потоковый со счётчиком; encrypt ≡ decrypt |

### S-боксы

| Имя | Описание |
|-----|----------|
| `cryptopro-a` **(default)** | CryptoPro-A (RFC 4357) |
| `cryptopro-b` / `c` / `d` | CryptoPro B–D |
| `test` | TestParamSet (RFC 4357) |
| custom | любая последовательность 8×16 значений 0..15 |

```python
from rucry import Gost28147, SBOX_TEST, resolve_sbox

Gost28147()                          # cryptopro-a
Gost28147(sbox="test")
Gost28147(sbox=SBOX_TEST)
Gost28147(sbox=resolve_sbox("cryptopro-b"))

# свой набор
my_sbox = [
    list(range(16)),  # 8 строк × 16 значений 0..15
    # ...
]
Gost28147(sbox=my_sbox)
```

Длинные OID-имена (`id-Gost28147-89-CryptoPro-A-ParamSet` и т.п.) тоже принимаются.

### Ключ

```python
# 8 × uint32
key = [0x01234567, 0x89ABCDEF, ...]  # 8 слов

# или 32 байта (little-endian слова)
key = bytes(range(32))
```

Ключ **не хранится** в модуле — всегда передаётся в `crypt` / helper-функции.

### API

```python
from rucry import Gost28147, CRYPT_MODE

g = Gost28147(sbox="cryptopro-a")
msg = bytearray(b"1234567890123456")
g.crypt(msg, key, encrypt=True, mode=CRYPT_MODE.ECB)
g.crypt(msg, key, encrypt=False, mode=CRYPT_MODE.ECB)

# CBC с IV
iv = b"\x00" * 8
g.crypt(msg, key, encrypt=True, mode=CRYPT_MODE.CBC, iv=iv)

# OFB / CTR — повторный crypt с encrypt=True восстанавливает plaintext
g.crypt(msg, key, encrypt=True, mode=CRYPT_MODE.OFB, iv=iv)
```

Вспомогательные: `mod32`, `rol`, `ror`, `bytes_to_hex`, `hex_to_bytes`,
`normalize_key`, `resolve_sbox`.

---

## Тесты

```bash
pip install pytest
pytest tests/ -v
```

Покрывают round-trip ECB/CBC, involution OFB/CTR, padding, hex API,
выбор S-боксов по имени и custom, ключ как 32 байта.

---

## ☕ Поддержать проект

[![YooMoney](https://img.shields.io/badge/Donation-Yoo.money-blue.svg)](https://yoomoney.ru/to/4100118099549894)
[![Boosty](https://img.shields.io/badge/Boosty-donate-orange.svg)](https://boosty.to/busybeaver/donate)
