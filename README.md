# **pycry**

Криптографические примитивы

[![Tag](https://img.shields.io/github/v/tag/busy4beaver/pycry?color=00c2e8)](https://github.com/busy4beaver/pycry)
[![Supported Python versions](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=FFE873)](https://www.python.org/downloads/)
[![Licence](https://img.shields.io/github/license/busy4beaver/pycry.svg)](LICENSE)

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
| **GOST 28147-89** | ECB / CBC / OFB / CTR, S-боксы и ключи как в AUTOCAD CRYPTLIB |
| **Чистый Python** | без нативных расширений и внешних crypto-зависимостей |
| **Hex API** | `encrypt_hex` / `decrypt_hex` — как `CRY::encrypt` / `decrypt` |
| **Расширяемость** | `algorithms/` — сюда добавляются новые шифры |

---

## Структура пакета

```text
src/pycry/
├── __init__.py              # публичный API
├── __version__.py
├── py.typed
└── algorithms/
    ├── __init__.py
    └── gost28147.py         # GOST 28147-89 (Magma-style)

tests/
└── test_gost28147.py

.github/
├── FUNDING.yml
└── workflows/
    └── workflow.yml         # Publish to PyPI (workflow_dispatch)
```

### Публичный импорт

```python
from pycry import (
    Gost28147,
    CRYPT_MODE,
    KEY1, KEY2, KEY3,
    encrypt_hex, decrypt_hex,
    encrypt_bytes, decrypt_bytes,
)
```

---

## Установка

Из GitHub:

```bash
pip install git+https://github.com/busy4beaver/pycry.git
```

Локально (editable):

```bash
git clone https://github.com/busy4beaver/pycry.git
cd pycry
pip install -e .
```

Зависимостей нет (stdlib only). Для тестов: `pip install pytest`.

---

## Быстрый старт

```python
from pycry import Gost28147, CRYPT_MODE, KEY1, encrypt_hex, decrypt_hex

# Блочный шифр (in-place)
data = bytearray(b"hello world!!!!")
g = Gost28147()
g.crypt(data, KEY1, encrypt=True, mode=CRYPT_MODE.ECB)
g.crypt(data, KEY1, encrypt=False, mode=CRYPT_MODE.ECB)

# Высокоуровневый hex API (level 0 → KEY1 + ECB)
ct = encrypt_hex("secret", level=0)
pt = decrypt_hex(ct, level=0)
print(pt.rstrip())  # secret (+ pad spaces для ECB)
```

---

## GOST 28147-89

Порт `gost28147` из `alx/CRYPTLIB.h` / `.cpp` репозитория AUTOCAD.

### Режимы

| `CRYPT_MODE` | Значение | Примечание |
|--------------|----------|------------|
| `ECB` | 0 | pad пробелами до кратности 8 при encrypt |
| `CBC` | 1 | IV = syncpack (R=`0xE9FC68AD`, L=`0xA54D1B93`) |
| `OFB` | 2 | потоковый; encrypt ≡ decrypt |
| `CTR` | 3 | потоковый со счётчиком; encrypt ≡ decrypt |

### Ключи (как в `CRY.cpp`)

| level | Ключ | Режим в `encrypt_hex` |
|-------|------|------------------------|
| 0 | `KEY1` | ECB |
| 1 | `KEY2` | CBC |
| 2 | `KEY3` | OFB |

S-боксы — **кастомные** (не CryptoPro / не «стандартный» GOST). Совместимость
с AUTOCAD важнее «стандартности» таблиц.

### API

```python
from pycry import Gost28147, CRYPT_MODE, KEY1, KEY2

g = Gost28147()

# GetCrypt-совместимый интерфейс
msg = bytearray(b"1234567890123456")
g.crypt(msg, KEY1, encrypt=True, mode=CRYPT_MODE.ECB)
g.crypt(msg, KEY1, encrypt=False, mode=CRYPT_MODE.ECB)

# CBC
msg = bytearray(b"1234567890123456")
g.crypt(msg, KEY2, encrypt=True, mode=CRYPT_MODE.CBC)
g.crypt(msg, KEY2, encrypt=False, mode=CRYPT_MODE.CBC)

# OFB / CTR — повторный crypt с encrypt=True восстанавливает plaintext
msg = bytearray(b"stream!!")
g.crypt(msg, KEY1, encrypt=True, mode=CRYPT_MODE.OFB)
g.crypt(msg, KEY1, encrypt=True, mode=CRYPT_MODE.OFB)
```

Вспомогательные функции: `mod32`, `mod32m1`, `rol`, `ror`,
`bytes_to_hex`, `hex_to_bytes`.

---

## Тесты

```bash
pip install pytest
pytest tests/ -v
```

Покрывают round-trip ECB/CBC, involution OFB/CTR, padding, hex API, пустое сообщение.

---

## ☕ Поддержать проект

[![YooMoney](https://img.shields.io/badge/Donation-Yoo.money-blue.svg)](https://yoomoney.ru/to/4100118099549894)
[![Boosty](https://img.shields.io/badge/Boosty-donate-orange.svg)](https://boosty.to/busybeaver/donate)
