# 📁 chacha20_poly1305.h

## 🎯 НАЗНАЧЕНИЕ  
Реализация ChaCha20-Poly1305 (RFC 7539).  
- Симметричное шифрование с аутентификацией.  
- Stream cipher (ChaCha20) + MAC (Poly1305).  
- 256-битный ключ, 96-битный nonce, 64-битный counter.  
- Используется для шифрования на платформах без AES-NI.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **chacha20_poly1305_encrypt** | `key` | `ByteSpan` | KeyManager | 256-битный ключ |
| | `nonce` | `ByteSpan` | Caller | 96-битный nonce |
| | `plaintext` | `ByteSpan` | Caller | Данные для шифрования |
| | `aad` | `ByteSpan` | Caller | Дополнительные аутентифицированные данные |
| **chacha20_poly1305_decrypt** | `key` | `ByteSpan` | KeyManager | 256-битный ключ |
| | `nonce` | `ByteSpan` | Caller | 96-битный nonce |
| | `ciphertext` | `ByteSpan` | Caller | Зашифрованные данные |
| | `tag` | `ByteSpan` | Caller | 128-битный тег аутентификации |
| | `aad` | `ByteSpan` | Caller | Дополнительные данные |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **chacha20_poly1305_encrypt** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `ciphertext` | `ByteArray` | Caller | Зашифрованные данные |
| | `tag` | `ByteArray` | Caller | Тег аутентификации |
| **chacha20_poly1305_decrypt** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `plaintext` | `ByteArray` | Caller | Расшифрованные данные |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неверный ключ** – возвращается `ERR_DECRYPTION_FAILED`.
- [x] **Неверный тег** – возвращается `ERR_AUTH_FAILED` (данные изменены).
- [x] **Неверный nonce** – возвращается `ERR_INVALID_NONCE`.
- [x] **Переполнение counter** – после 2^32 блоков требуется новый nonce.
- [ ] **Nonce reuse** – критично для безопасности.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Шифрование/дешифрование с корректными данными.
- [ ] Проверка аутентификации (изменение ciphertext → ошибка).
- [ ] Проверка AAD (изменение AAD → ошибка).
- [ ] Тесты на границах (max size).
- [ ] Performance тесты (скорость шифрования).
- [ ] Сравнение с AES-256-GCM.

---

## 🔗 ЗАВИСИМОСТИ

- **`crypto_module`** – ChaCha20, Poly1305.
- **`types.h`** – `ByteSpan`, `ByteArray`, `ErrorCode`.
- OpenSSL: `EVP_chacha20_poly1305`, `EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, `EVP_EncryptFinal_ex`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| ChaCha20-Poly1305 encrypt | 🟢 Готово | Software implementation |
| ChaCha20-Poly1305 decrypt | 🟢 Готово | Software implementation |
| AAD support | 🟢 Готово | Authenticated data |
| Tag verification | 🟢 Готово | Integrity check |
| Side-channel resistant | 🟢 Готово | Constant-time |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово