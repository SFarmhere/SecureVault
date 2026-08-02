# 📁 aes256_gcm.h

## 🎯 НАЗНАЧЕНИЕ  
Реализация AES-256-GCM (Advanced Encryption Standard).  
- Симметричное шифрование с аутентификацией.  
- Режим GCM (Galois/Counter Mode) для confidentiality + integrity.  
- 256-битный ключ, 128-битный IV/nonce.  
- Используется для шифрования данных в контейнерах.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **aes256_gcm_encrypt** | `key` | `ByteSpan` | KeyManager | 256-битный ключ |
| | `iv` | `ByteSpan` | Caller | 96-битный nonce |
| | `plaintext` | `ByteSpan` | Caller | Данные для шифрования |
| | `aad` | `ByteSpan` | Caller | Дополнительные аутентифицированные данные |
| **aes256_gcm_decrypt** | `key` | `ByteSpan` | KeyManager | 256-битный ключ |
| | `iv` | `ByteSpan` | Caller | 96-битный nonce |
| | `ciphertext` | `ByteSpan` | Caller | Зашифрованные данные |
| | `tag` | `ByteSpan` | Caller | 128-битный тег аутентификации |
| | `aad` | `ByteSpan` | Caller | Дополнительные данные |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **aes256_gcm_encrypt** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `ciphertext` | `ByteArray` | Caller | Зашифрованные данные |
| | `tag` | `ByteArray` | Caller | Тег аутентификации |
| **aes256_gcm_decrypt** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `plaintext` | `ByteArray` | Caller | Расшифрованные данные |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неверный ключ** – возвращается `ERR_DECRYPTION_FAILED`.
- [x] **Неверный тег** – возвращается `ERR_AUTH_FAILED` (данные изменены).
- [x] **Неверный IV** – возвращается `ERR_INVALID_IV`.
- [x] **Переполнение** – GCM имеет лимит на размер данных (64GB).
- [ ] **Nonce reuse** – критично для безопасности.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Шифрование/дешифрование с корректными данными.
- [ ] Проверка аутентификации (изменение ciphertext → ошибка).
- [ ] Проверка AAD (изменение AAD → ошибка).
- [ ] Тесты на границах (max size).
- [ ] Performance тесты (скорость шифрования).

---

## 🔗 ЗАВИСИМОСТИ

- **`crypto_module`** – AES-NI, OpenSSL.
- **`types.h`** – `ByteSpan`, `ByteArray`, `ErrorCode`.
- OpenSSL: `EVP_aes_256_gcm`, `EVP_EncryptInit_ex`, `EVP_EncryptUpdate`, `EVP_EncryptFinal_ex`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| AES-256-GCM encrypt | 🟢 Готово | Hardware accelerated |
| AES-256-GCM decrypt | 🟢 Готово | Hardware accelerated |
| AAD support | 🟢 Готово | Authenticated data |
| Tag verification | 🟢 Готово | Integrity check |
| Side-channel resistant | 🟢 Готово | Constant-time |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово