# 📁 test_key_operations.cpp

## 🎯 НАЗНАЧЕНИЕ  
Модульные тесты для функций генерации и управления ключами на аппаратных токенах.  
- Тестирование `GenerateRsaKeyPair`, `GenerateRsaKeyPairDefault`, `IsRsaKeyGenerationSupported`.  
- Тестирование `ListKeys`, `FindKeyById`, `FindKeyByLabel`, `DeleteKey`, `ExportPublicKeyPem`, `CountKeys`.  
- Использует мок-реализации `ITokenModule` для изоляции от реального железа.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `mock_module` | `MockTokenModule` | Тестовый фреймворк | Мок-реализация `ITokenModule` |
| `session_id` | `SessionId` | `MakeTestSessionId()` | Тестовый ID сессии |
| `params` | `RsaKeyParams` | `MakeTestKeyParams()` | Параметры генерации ключа |
| `key_id` | `std::string` | `GenerateHexId()` | Тестовый ID ключа |
| `label` | `std::string` | Тестовые данные | Метка ключа |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Данные | Тип | Куда | Описание |
|--------|-----|------|----------|
| Результат теста | `bool` / assertion | Google Test | `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE` |
| `KeyGenerationResult` | `KeyGenerationResult` | Тест | Проверка полей `result`, `key_id`, `public_key_pem` |
| `KeyInfo` | `KeyInfo` | Тест | Проверка через `IsKeyInfoEqual` |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неинициализированный модуль** – проверка возврата `ERR_NOT_INITIALIZED`.
- [x] **Недопустимый размер ключа** – проверка возврата `ERR_KEY_SIZE` для 1024 бит.
- [x] **Пустой `key_id`** – `FindKeyById`, `DeleteKey`, `ExportPublicKeyPem` возвращают `nullptr`/`""`/`ERR_NOT_INITIALIZED`.
- [x] **Несуществующий ключ** – `FindKeyById` возвращает `nullptr`.
- [ ] **Реальный токен** – интеграционные тесты с реальным железом (опционально).

---

## 🧪 ТЕСТЫ

- [x] `GenerateRsaKeyPair_Success_2048` – успешная генерация RSA-2048.
- [x] `GenerateRsaKeyPair_Success_4096` – успешная генерация RSA-4096.
- [x] `GenerateRsaKeyPair_NotInitialized` – неинициализированный модуль.
- [x] `GenerateRsaKeyPair_InvalidSize` – недопустимый размер (1024).
- [x] `IsRsaKeyGenerationSupported_True` – поддерживаемый размер.
- [x] `IsRsaKeyGenerationSupported_False` – неподдерживаемый размер.
- [x] `ListKeys_Success` – список ключей.
- [x] `FindKeyById_Success` – поиск по ID.
- [x] `FindKeyById_NotFound` – несуществующий ключ.
- [x] `FindKeyByLabel_Success` – поиск по метке.
- [x] `DeleteKey_Success` – удаление ключа.
- [x] `ExportPublicKeyPem_Success` – экспорт публичного ключа.
- [x] `CountKeys_Success` – количество ключей.

---

## 🔗 ЗАВИСИМОСТИ

- **`key_generation.h`** – тестируемые функции генерации.
- **`key_management.h`** – тестируемые функции управления.
- **`test_utils.h`** – `GenerateHexId`, `MakeTestKeyInfo`, `IsKeyInfoEqual`.
- **`pkcs11_api.h`** – `ITokenModule`, `TokenResult`, `RsaKeyParams`.
- **`token_types.h`** – `KeyInfo`, `KeyType`, `KeySizeBits`.
- **Google Test** – фреймворк тестирования.
- **Google Mock** – мок-реализации `ITokenModule`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Unit-тесты генерации | 🟢 Готово | Покрыты все сценарии |
| Unit-тесты управления | 🟢 Готово | Покрыты все сценарии |
| Мок-реализации | 🟢 Готово | `MockTokenModule` |
| Интеграционные тесты | 🔴 Отсутствует | Требуют реального токена |

**Общий статус:** 🟢 Готово (unit-тесты).

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово