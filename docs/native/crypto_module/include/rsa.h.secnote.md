# 📁 rsa.h

## 🎯 НАЗНАЧЕНИЕ  
Заголовочный файл для RSA-шифрования и подписи (RSA-2048/4096).  
- Используется для операций с ключами на аппаратных токенах (PKCS#11).  
- Поддерживает OAEP padding для шифрования и PSS для подписи.  
- Все операции выполняются на токене (приватный ключ не покидает токен).

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **rsa_encrypt** | `public_key` | `RsaPublicKey&` | Token | Публичный ключ |
| | `plaintext` | `ByteSpan` | File / Data | Данные для шифрования |
| | `output` | `MutableByteSpan` | Caller | Буфер для шифротекста |
| **rsa_decrypt** | `private_key` | `RsaPrivateKey&` | Token | Приватный ключ (на токене) |
| | `ciphertext` | `ByteSpan` | Container | Зашифрованные данные |
| | `output` | `MutableByteSpan` | Caller | Буфер для открытого текста |
| **rsa_sign** | `private_key` | `RsaPrivateKey&` | Token | Приватный ключ (на токене) |
| | `hash` | `ByteSpan` | Hash module | Хеш данных |
| | `signature` | `MutableByteSpan` | Caller | Буфер для подписи |
| **rsa_verify** | `public_key` | `RsaPublicKey&` | Token | Публичный ключ |
| | `hash` | `ByteSpan` | Hash module | Хеш данных |
| | `signature` | `ByteSpan` | Container | Подпись для проверки |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **rsa_encrypt** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `output` | `MutableByteSpan` | Caller | Шифротекст |
| **rsa_decrypt** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `output` | `MutableByteSpan` | Caller | Открытый текст |
| **rsa_sign** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `signature` | `MutableByteSpan` | Caller | Цифровая подпись |
| **rsa_verify** | `valid` | `bool` | Caller | `true` если подпись верна |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неверный padding** – `rsa_decrypt` возвращает `PADDING_ERROR`.
- [x] **Неверная подпись** – `rsa_verify` возвращает `false`.
- [x] **Слишком большой plaintext** – RSA может зашифровать только `key_size - padding_overhead` байт.
- [x] **Приватный ключ на токене** – операции `decrypt`/`sign` выполняются на токене, приватный ключ не экспортируется.
- [ ] **OAEP vs PKCS#1 v1.5** – поддерживается только OAEP для новых контейнеров.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] `rsa_encrypt` / `rsa_decrypt` roundtrip — шифрование и расшифровка.
- [ ] `rsa_sign` / `rsa_verify` roundtrip — подпись и проверка.
- [ ] `rsa_verify` с неверной подписью — `false`.
- [ ] `rsa_encrypt` с пустым plaintext — корректное поведение.
- [ ] `rsa_decrypt` с неверным padding — `PADDING_ERROR`.
- [ ] Тесты с NIST-векторами (RSA PKCS#1 v2.2).
- [ ] Интеграционные тесты с реальными токенами.

---

## 🔗 ЗАВИСИМОСТИ

- **`common_types.h`** – `RsaPublicKey`, `RsaPrivateKey`, `ByteSpan`, `MutableByteSpan`.
- **`error_codes.h`** – `ErrorCode`.
- **`aes.h`** – для гибридного шифрования (AES + RSA).
- **PKCS#11** – операции с ключами на токене (`C_EncryptInit`, `C_SignInit`).

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| RSA-2048 | 🟢 Готово | Шифрование и подпись |
| RSA-4096 | 🟢 Готово | Шифрование и подпись |
| OAEP padding | 🟢 Готово | Для шифрования |
| PSS padding | 🟢 Готово | Для подписи |
| Интеграция с PKCS#11 | 🟢 Готово | Ключи на токене |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово