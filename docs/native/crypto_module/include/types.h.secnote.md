# 📁 types.h

## 🎯 НАЗНАЧЕНИЕ  
Общие криптографические типы и псевдонимы для `crypto_module`.  
- `ByteSpan` / `MutableByteSpan` — безопасные представления буферов.  
- `Aes256Key`, `AesGcmIv`, `AesGcmTag` — типы для AES-256-GCM.  
- `RsaPublicKey`, `RsaPrivateKey` — типы для RSA.  
- `CryptoAlgorithm`, `SignAlgorithm` — перечисления алгоритмов.  
- `ErrorCode` — коды ошибок криптографических операций.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

Нет — это заголовочный файл, только определения типов.

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Тип/Перечисление | Где используется | Файлы |
|------------------|------------------|-------|
| `ByteSpan` | Все crypto функции | `aes.h`, `rsa.h`, `kyber.h` |
| `MutableByteSpan` | Выходные буферы | `aes.h`, `rsa.h` |
| `Aes256Key` | AES операции | `aes.h` |
| `AesGcmIv` | AES-GCM IV | `aes.h` |
| `AesGcmTag` | AES-GCM тег | `aes.h` |
| `RsaPublicKey` | RSA операции | `rsa.h` |
| `RsaPrivateKey` | RSA операции | `rsa.h` |
| `CryptoAlgorithm` | `crypto_api.h` | `encrypt`, `decrypt` |
| `SignAlgorithm` | `crypto_api.h` | `sign`, `verify` |
| `ErrorCode` | Все модули | `error_codes.h` |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Zero-initialization** — все структуры инициализируются `{}`.
- [x] **Фиксированные размеры** — нет `std::string`/`std::vector` в ABI.
- [x] **TriviallyCopyable** — все типы можно безопасно копировать.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] `static_assert` размеров структур.
- [ ] Проверка `ByteSpan` на пустые буферы.
- [ ] Проверка `ErrorCode` значений.

---

## 🔗 ЗАВИСИМОСТИ

- **`error_codes.h`** — `ErrorCode`.
- Стандартные библиотеки: `<cstdint>`, `<span>`, `<array>`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Базовые типы | 🟢 Готово | `ByteSpan`, `MutableByteSpan` |
| AES типы | 🟢 Готово | `Aes256Key`, `AesGcmIv`, `AesGcmTag` |
| RSA типы | 🟢 Готово | `RsaPublicKey`, `RsaPrivateKey` |
| Перечисления | 🟢 Готово | `CryptoAlgorithm`, `SignAlgorithm` |
| ABI-стабильность | 🟢 Готово | Все типы фиксированного размера |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово