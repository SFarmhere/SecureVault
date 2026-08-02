# 📁 crypto_api.h

## 🎯 НАЗНАЧЕНИЕ  
Публичный API криптографического модуля.  
- Единый интерфейс для шифрования/дешифрования, подписи/проверки.  
- Абстрагирует алгоритмы: AES, RSA, Kyber, ChaCha20.  
- Используется Python-биндингами, CLI, веб-бэкендом.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **encrypt** | `algorithm` | `CryptoAlgorithm` | Caller | Алгоритм шифрования |
| | `key` | `ByteSpan` | KeyManager | Ключ |
| | `iv` | `ByteSpan` | Random | IV/nonce |
| | `plaintext` | `ByteSpan` | File | Данные |
| **decrypt** | `algorithm` | `CryptoAlgorithm` | Caller | Алгоритм |
| | `key` | `ByteSpan` | KeyManager | Ключ |
| | `ciphertext` | `ByteSpan` | Container | Шифротекст |
| | `tag` | `ByteSpan` | Container | Тег (GCM) |
| **sign** | `algorithm` | `SignAlgorithm` | Caller | Алгоритм подписи |
| | `key` | `ByteSpan` | Token | Приватный ключ |
| | `hash` | `ByteSpan` | Hash module | Хеш |
| **verify** | `algorithm` | `SignAlgorithm` | Caller | Алгоритм подписи |
| | `key` | `ByteSpan` | Token | Публичный ключ |
| | `signature` | `ByteSpan` | Container | Подпись |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **encrypt** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `output` | `MutableByteSpan` | Caller | Шифротекст |
| | `tag` | `MutableByteSpan` | Caller | Тег аутентификации |
| **decrypt** | `result` | `ErrorCode` | Caller | `SUCCESS` или `TAG_MISMATCH` |
| | `output` | `MutableByteSpan` | Caller | Открытый текст |
| **sign** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `signature` | `MutableByteSpan` | Caller | Подпись |
| **verify** | `valid` | `bool` | Caller | `true` если подпись верна |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неверный тег** – `decrypt` возвращает `TAG_MISMATCH`.
- [x] **Неверная подпись** – `verify` возвращает `false`.
- [x] **Неподдерживаемый алгоритм** – `ERR_UNSUPPORTED_ALGORITHM`.
- [x] **Неверный размер ключа** – `ERR_INVALID_KEY_SIZE`.
- [ ] **Пустые данные** – поведение зависит от алгоритма.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Roundtrip для AES-GCM, AES-CBC, RSA-OAEP, RSA-PSS.
- [ ] Неверный тег/подпись.
- [ ] Неподдерживаемый алгоритм.
- [ ] Граничные размеры ключей.

---

## 🔗 ЗАВИСИМОСТИ

- **`aes.h`** – AES-256-GCM/CBC.
- **`rsa.h`** – RSA-OAEP/PSS.
- **`kyber.h`** – пост-квантовый Kyber1024.
- **`chacha20.h`** – ChaCha20-Poly1305.
- **`common_types.h`** – `ByteSpan`, `CryptoAlgorithm`.
- **`error_codes.h`** – `ErrorCode`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| AES-256-GCM | 🟢 Готово | Основной алгоритм |
| AES-256-CBC | 🟢 Готово | Legacy |
| RSA-OAEP | 🟢 Готово | Шифрование |
| RSA-PSS | 🟢 Готово | Подпись |
| Kyber1024 | 🟢 Готово | Пост-квантовый |
| ChaCha20 | 🟡 В работе | Для ARM/Mobile |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово