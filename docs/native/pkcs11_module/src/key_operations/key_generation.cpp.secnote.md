# 📁 key_generation.cpp

## 🎯 НАЗНАЧЕНИЕ  
Реализует высокоуровневые функции генерации ключевых пар на аппаратных токенах, делегируя низкоуровневую работу интерфейсу `ITokenModule::GenerateRsaKeyPair()`.

- `GenerateRsaKeyPair` — основная функция с полной проверкой параметров.
- `GenerateRsaKeyPairDefault` — удобная обёртка с параметрами по умолчанию.
- `IsRsaKeyGenerationSupported` — проверка поддержки RSA и размера ключа.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **GenerateRsaKeyPair** | `module` | `ITokenModule&` | Вызывающий код | Инициализированный модуль токена |
| | `session_id` | `SessionId` | Вызывающий код | ID аутентифицированной сессии |
| | `params` | `const RsaKeyParams&` | Вызывающий код | Размер ключа, метка, флаги |
| **GenerateRsaKeyPairDefault** | `module` | `ITokenModule&` | Вызывающий код | Инициализированный модуль |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `label` | `const std::string&` | Вызывающий код | Метка ключа |
| | `bits` | `KeySizeBits` | Вызывающий код | 2048 или 4096 |
| **IsRsaKeyGenerationSupported** | `module` | `ITokenModule&` | Вызывающий код | Модуль токена |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `bits` | `KeySizeBits` | Вызывающий код | Размер ключа |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **GenerateRsaKeyPair** | `result` | `KeyGenerationResult` | Вызывающий код | Результат с `key_id`, `public_key_pem`, `key_type`, `size_bits`, `on_token` |
| **GenerateRsaKeyPairDefault** | `result` | `KeyGenerationResult` | Вызывающий код | Делегирует `GenerateRsaKeyPair` |
| **IsRsaKeyGenerationSupported** | `supported` | `bool` | Вызывающий код | `true` если RSA и размер поддерживаются |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неинициализированный модуль** – проверяется `module.IsInitialized()`, возвращается `ERR_NOT_INITIALIZED`.
- [x] **Недопустимый размер ключа** – только 2048 и 4096; иначе `ERR_KEY_SIZE`.
- [x] **Ошибка генерации** – пустой `key_id` от модуля → `ERR_KEY_TYPE`.
- [x] **Экспорт публичного ключа** – вызывается `ExportPublicKeyPem()` из `key_management.h` для заполнения `public_key_pem`.
- [ ] **Поддержка EC-ключей** – не реализована.
- [ ] **Проверка реальной поддержки механизма** – `IsRsaKeyGenerationSupported` проверяет только размер, а не механизм на токене.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Успешная генерация RSA-2048 – `SUCCESS`, непустой `key_id`, заполненный `public_key_pem`.
- [ ] Успешная генерация RSA-4096.
- [ ] Неинициализированный модуль – `ERR_NOT_INITIALIZED`.
- [ ] Недопустимый размер (1024) – `ERR_KEY_SIZE`.
- [ ] `IsRsaKeyGenerationSupported` для 2048 и 4096.

---

## 🔗 ЗАВИСИМОСТИ

- **`key_generation.h`** – объявления функций и `KeyGenerationResult`.
- **`key_management.h`** – `ExportPublicKeyPem()` для получения публичного ключа.
- **`pkcs11_api.h`** – `ITokenModule`, `TokenResult`, `RsaKeyParams`.
- **`session_types.h`** – `SessionId`.
- **`token_types.h`** – `KeyType`, `KeySizeBits`, `KeyInfo`.
- Стандартные библиотеки: `<string>`, `<vector>`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Реализация генерации RSA | 🟢 Готово | Делегирует `ITokenModule` |
| Проверка параметров | 🟢 Готово | Размер, инициализация |
| Экспорт публичного ключа | 🟢 Готово | Через `ExportPublicKeyPem` |
| Поддержка EC | 🔴 Отсутствует | Только RSA |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово
</arg_value></tool_call>