# 📁 aes.h

## 🎯 НАЗНАЧЕНИЕ  
Заголовочный файл для AES-256 шифрования с режимом GCM (аутентифицированное шифрование).  
- AES-256-GCM — основной режим для шифрования файлов (уровни INDIVIDUAL, CONTAINER, HYPER).  
- AES-256-CBC — legacy-режим для совместимости с форматом контейнеров v1.  
- Использует аппаратное ускорение AES-NI при наличии.  
- Все операции выполняются в константном времени для защиты от side-channel атак.  
- Расширение ключа (key schedule) для AES-256 (14 раундов).

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **aes_256_gcm_encrypt** | `key` | `const Aes256Key&` | KeyManager / KDF | 256-битный AES ключ |
| | `iv` | `const AesGcmIv&` | Random generator | 12-байтный GCM IV/nonce |
| | `plaintext` | `ByteSpan` | Container / File | Данные для шифрования |
| | `aad` | `ByteSpan` | Container metadata | Additional Authenticated Data (опционально) |
| **aes_256_gcm_decrypt** | `key` | `const Aes256Key&` | KeyManager / KDF | 256-битный AES ключ |
| | `iv` | `const AesGcmIv&` | Container metadata | 12-байтный GCM IV/nonce |
| | `ciphertext` | `ByteSpan` | Container / File | Зашифрованные данные |
| | `aad` | `ByteSpan` | Container metadata | Additional Authenticated Data |
| | `tag` | `const AesGcmTag&` | Container metadata | 16-байтный тег аутентификации |
| **aes_256_cbc_encrypt** | `key` | `const Aes256Key&` | KeyManager / KDF | 256-битный AES ключ |
| | `iv` | `const std::array<uint8_t, 16>&` | Random generator | 16-байтный CBC IV |
| | `plaintext` | `ByteSpan` | Container v1 | Данные для шифрования |
| **aes_256_cbc_decrypt** | `key` | `const Aes256Key&` | KeyManager / KDF | 256-битный AES ключ |
| | `iv` | `const std::array<uint8_t, 16>&` | Container v1 | 16-байтный CBC IV |
| | `ciphertext` | `ByteSpan` | Container v1 | Зашифрованные данные |
| **aes_256_expand_key** | `key` | `const Aes256Key&` | KeyManager | 256-битный AES ключ |
| **constant_time_equals** | `a`, `b` | `const uint8_t*` | Внутренние вызовы | Два массива для сравнения |
| | `length` | `size_t` | Внутренние вызовы | Длина сравнения |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **aes_256_gcm_encrypt** | `result` | `ErrorCode` | Вызывающий код | `SUCCESS` или код ошибки |
| | `output` | `MutableByteSpan` | Вызывающий код | Шифротекст (размер = plaintext) |
| | `tag` | `AesGcmTag&` | Вызывающий код | 16-байтный тег аутентификации |
| **aes_256_gcm_decrypt** | `result` | `ErrorCode` | Вызывающий код | `SUCCESS` или `TAG_MISMATCH` |
| | `output` | `MutableByteSpan` | Вызывающий код | Открытый текст |
| **aes_256_cbc_encrypt** | `result` | `ErrorCode` | Вызывающий код | `SUCCESS` или код ошибки |
| | `output` | `MutableByteSpan` | Вызывающий код | Шифротекст + PKCS#7 padding |
| **aes_256_cbc_decrypt** | `result` | `ErrorCode` | Вызывающий код | `SUCCESS` или код ошибки |
| | `output` | `MutableByteSpan` | Вызывающий код | Открытый текст |
| **aes_256_expand_key** | `result` | `ErrorCode` | Вызывающий код | `SUCCESS` или код ошибки |
| | `expanded_key` | `Aes256ExpandedKey&` | Вызывающий код | Расширенный ключ (240 байт) |
| **constant_time_equals** | `equal` | `bool` | Вызывающий код | `true` если массивы равны |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неверный тег GCM** – `aes_256_gcm_decrypt` возвращает `TAG_MISMATCH`, данные не раскрываются.
- [x] **Константное время** – `constant_time_equals` предотвращает timing-атаки.
- [x] **AES-NI** – аппаратное ускорение используется при наличии, fallback на software.
- [x] **PKCS#7 padding** – CBC режим использует стандартный padding.
- [ ] **Нулевой plaintext** – поведение зависит от реализации (пустой вывод).
- [ ] **Переполнение буфера** – вызывающий код должен обеспечить достаточный размер `output`.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] `aes_256_gcm_encrypt` / `decrypt` roundtrip — шифрование и расшифровка.
- [ ] `aes_256_gcm_decrypt` с неверным тегом — `TAG_MISMATCH`.
- [ ] `aes_256_gcm_encrypt` с AAD — проверка аутентификации метаданных.
- [ ] `aes_256_cbc_encrypt` / `decrypt` roundtrip — legacy-режим.
- [ ] `aes_256_cbc_decrypt` с неверным padding — ошибка.
- [ ] `aes_256_expand_key` — корректность key schedule.
- [ ] `constant_time_equals` — равные и неравные массивы.
- [ ] Тесты с NIST-векторами (FIPS-197, GCM test vectors).
- [ ] Проверка константного времени (timing analysis).

---

## 🔗 ЗАВИСИМОСТИ

- **`common_types.h`** – `Aes256Key`, `AesGcmIv`, `AesGcmTag`, `ByteSpan`, `MutableByteSpan`.
- **`error_codes.h`** – `ErrorCode` (`SUCCESS`, `TAG_MISMATCH` и др.).
- Стандартные библиотеки: `<cstdint>`, `<array>`, `<vector>`.
- *(Аппаратная)* **AES-NI** – инструкции процессора для ускорения.
- *(Software fallback)* – реализация на C++ при отсутствии AES-NI.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| AES-256-GCM | 🟢 Готово | Основной режим шифрования |
| AES-256-CBC | 🟢 Готово | Legacy для контейнеров v1 |
| Key schedule | 🟢 Готово | 14 раундов, 240 байт |
| AES-NI ускорение | 🟢 Готово | Автоопределение |
| Константное время | 🟢 Готово | `constant_time_equals` |
| Side-channel защита | 🟢 Готово | Все операции constant-time |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово