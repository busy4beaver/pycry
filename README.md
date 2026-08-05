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
- [Паддинг](#паддинг)
- [Утилиты](#утилиты)
- [Тесты](#тесты)
- [Поддержать проект](#-поддержать-проект)

---

## Особенности

| Область | Что даёт |
|---------|----------|
| **GOST 28147-89** | ECB / CBC / OFB / CTR |
| **S-боксы** | предопределённые наборы (CryptoPro A–D, Test) или свои 8×16 |
| **Ключ / IV / mode** | задаются при создании класса **или** передаются в `crypt` |
| **encrypt / decrypt** | высокоуровневые методы, возвращают `bytes` |
| **Паддинг** | zero (по умолчанию) или PKCS#7 |
| **Чистый Python** | без нативных расширений и внешних crypto-зависимостей |
| **Hex API** | `encrypt_hex` / `decrypt_hex` |
| **utils** | hex, время, паддинг, случайная синхропосылка |
| **Расширяемость** | `algorithms/` — сюда добавляются новые шифры |

---

## Структура пакета

```text
src/rucry/
├── __init__.py              # публичный API
├── __version__.py
├── utils.py                 # хелперы (hex, время, паддинг, IV)
├── py.typed
└── algorithms/
    ├── __init__.py
    └── gost28147.py         # GOST 28147-89

tests/
└── test_gost28147.py
```

### Публичный импорт

```python
from rucry import (
    Gost28147, CRYPT_MODE,
    SBOXES, SBOX_CRYPTOPRO_A, SBOX_TEST,
    encrypt_hex, decrypt_hex,
    encrypt_bytes, decrypt_bytes,
    # utils
    bytes_to_hex, hex_to_bytes, str_to_hex,
    now, future, is_reached,
    random_iv, pkcs7_pad, pkcs7_unpad,
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

### Новый стиль (рекомендуется)

```python
from rucry import Gost28147, CRYPT_MODE, random_iv

key = [
    0x01020304, 0x05060708, 0x090A0B0C, 0x0D0E0F10,
    0x11121314, 0x15161718, 0x191A1B1C, 0x1D1E1F20,
]

g = Gost28147(
    key=key,
    sbox="cryptopro-a",          # default
    mode=CRYPT_MODE.CBC,
    iv=random_iv(8),             # синхропосылка
    padding="zero",              # или "pkcs7"
)

ct = g.encrypt(b"hello!!!")
pt = g.decrypt(ct)
assert pt == b"hello!!!"
```

### Старый стиль (crypt) — сохранён

```python
from rucry import Gost28147, CRYPT_MODE

g = Gost28147(sbox="cryptopro-a")
data = bytearray(b"12345678")
g.crypt(data, key, encrypt=True, mode=CRYPT_MODE.ECB)
g.crypt(data, key, encrypt=False, mode=CRYPT_MODE.ECB)
```

### Hex API

```python
from rucry import encrypt_hex, decrypt_hex, CRYPT_MODE

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
| `ECB` | 0 | нужен паддинг до кратности 8 |
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
Gost28147(key=key)                          # cryptopro-a
Gost28147(key=key, sbox="test")
Gost28147(key=key, sbox=SBOX_TEST)

# свой набор
my_sbox = [list(range(16))] * 8
Gost28147(key=key, sbox=my_sbox)
```

### Ключ

```python
# 8 × uint32
key = [0x01234567, 0x89ABCDEF, ...]  # 8 слов

# или 32 байта (little-endian слова)
key = bytes(range(32))
```

### Синхропосылка (IV)

```python
from rucry import random_iv

iv = random_iv(8)                    # случайная
iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"

g = Gost28147(key=key, mode=CRYPT_MODE.CBC, iv=iv)
# или позже:
g.iv = iv
```

В ECB IV не используется. В CTR — это начальное значение счётчика.

### API

```python
g = Gost28147(key=key, mode=CRYPT_MODE.CBC, iv=iv, padding="pkcs7")

# высокоуровневый
ct = g.encrypt(b"data")
pt = g.decrypt(ct)

# низкоуровневый (in-place, как раньше)
msg = bytearray(b"12345678")
g.crypt(msg, key, encrypt=True, mode=CRYPT_MODE.ECB)
```

Параметры `encrypt`/`decrypt` можно переопределить на лету:

```python
ct = g.encrypt(data, mode=CRYPT_MODE.OFB, iv=other_iv)
```

---

## Паддинг

Для **ECB** и **CBC** длина данных должна быть кратна 8 байтам.

| Схема | Поведение | Когда использовать |
|-------|-----------|--------------------|
| **`zero`** (default) | Дополняет `\x00`. При decrypt — `rstrip(b'\\x00')` | Обратная совместимость, исторический GOST |
| **`pkcs7`** | Добавляет N байт со значением N (1…8). Если длина уже кратна — целый блок `08…08` | Когда нужны хвостовые нули в данных или однозначное снятие |
| **`ansi`** | Нули + последний байт = длина паддинга (ANSI X.923) | Однозначное снятие, часто в банковских протоколах |
| **`none`** | Без паддинга. Длина уже должна быть кратна 8 | Когда вы сами управляете длиной |

В **OFB** / **CTR** паддинг не применяется (потоковые режимы).

```python
from rucry import pkcs7_pad, pkcs7_unpad, zero_pad, zero_unpad

g = Gost28147(key=key, padding="pkcs7")
ct = g.encrypt(b"hello")   # 5 → 8 байт
pt = g.decrypt(ct)         # → b"hello"
```

**Важно про zero-padding:** если исходные данные заканчиваются нулевыми байтами, `zero_unpad` их тоже срежет. Для бинарных данных с возможными хвостовыми нулями используйте `pkcs7`.

---

## Утилиты

```python
from rucry import (
    str_to_hex, hex_to_str, bytes_to_hex, hex_to_bytes,
    to_bytearray, from_bytearray,
    now, future, is_reached, time_to_bytes, bytes_to_time,
    random_iv, random_key_words,
    pkcs7_pad, pkcs7_unpad, zero_pad, zero_unpad,
    int_list_to_bytes, bytes_to_int_list,
)

# hex
h = str_to_hex("привет")
s = hex_to_str(h)

# время
t0 = now()
t1 = future(months=1, days=3, hours=2)
assert not is_reached(t1)
ts = time_to_bytes(t1)          # 8 байт unix timestamp
dt = bytes_to_time(ts)

# случайная синхропосылка / ключ
iv = random_iv(8)
key_words = random_key_words()  # 8 × uint32
```

---

## Тесты

```bash
pip install pytest
pytest tests/ -v
```

Покрывают round-trip ECB/CBC, involution OFB/CTR, padding (zero + PKCS#7),
новый API `encrypt`/`decrypt`, hex API, выбор S-боксов, ключ как 32 байта.

---

## ☕ Поддержать проект

[![YooMoney](https://img.shields.io/badge/Donation-Yoo.money-blue.svg)](https://yoomoney.ru/to/4100118099549894)
[![Boosty](https://img.shields.io/badge/Boosty-donate-orange.svg)](https://boosty.to/busybeaver/donate)
