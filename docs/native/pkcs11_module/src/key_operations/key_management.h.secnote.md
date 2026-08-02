# 📁 key_management.h

## 🎯 НАЗНАЧЕНИЕ  
Заголовочный файл для управления ключами на аппаратных токенах.  
- Объявляет функции: `ListKeys`, `FindKeyById`, `FindKeyByLabel`, `DeleteKey`, `ExportPublicKeyPem`, `CountKeys`.  
- Делегирует низкоуровневые операции интерфейсу `ITokenModule`.

Приватный ключ **никогда не экспортируется** — `ExportPublicKeyPem` возвращает только публичную часть.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **ListKeys** | `module` | `ITokenModule&` | Вызывающий код | Инициализированный модуль токена |
| | `session_id` | `SessionId` | Вызывающий код | ID аутентифицированной сессии |
| **FindKeyById** | `module` | `ITokenModule&` | Вызывающий код | Модуль токена |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `key_id` | `const std::string&` | Вызывающий код | Идентификатор ключа (hex) |
| **FindKeyByLabel** | `module` | `ITokenModule&` | Вызывающий код | Модуль токена |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `label` | `const std::string&` | Вызывающий код | Метка ключа (CKA_LABEL) |
| **DeleteKey** | `module` | `ITokenModule&` | Вызывающий код | Модуль токена |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `key_id` | `const std::string&` | Вызывающий код | Идентификатор ключа для удаления |
| **ExportPublicKeyPem** | `module` | `ITokenModule&` | Вызывающий код | Модуль токена |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `key_id` | `const std::string&` | Вызывающий код | Идентификатор ключа |
| **CountKeys** | `module` | `ITokenModule&` | Вызывающий код | Модуль токена |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **ListKeys** | `keys` | `std::vector<KeyInfo>` | Вызывающий код | Список ключей или пустой вектор при ошибке |
| **FindKeyById** | `key` | `std::unique_ptr<KeyInfo>` | Вызывающий код | Информация о ключе или `nullptr` |
| **FindKeyByLabel** | `key` | `std::unique_ptr<KeyInfo>` | Вызывающий код | Информация о ключе или `nullptr` |
| **DeleteKey** | `result` | `TokenResult` | Вызывающий код | `SUCCESS` или код ошибки |
| **ExportPublicKeyPem** | `pem` | `std::string` | Вызывающий код | PEM-представление публичного ключа или пустая строка |
| **CountKeys** | `count` | `int` | Вызывающий код | Количество ключей или `-1` при ошибке |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неинициализированный модуль** – все функции проверяют `module.IsInitialized()`.
- [x] **Пустой `key_id`/`label`** – `FindKeyById`, `FindKeyByLabel`, `DeleteKey`, `ExportPublicKeyPem` возвращают `nullptr`/`""`/`ERR_NOT_INITIALIZED`.
- [x] **Экспорт только публичного ключа** – `ExportPublicKeyPem` ищет публичный ключ с тем же `key_id`, если передан приватный.
- [ ] **Потокобезопасность FindKeyByLabel** – использует `ListKeys`, который может быть не thread-safe на уровне модуля.
- [ ] **Удаление связанного публичного ключа** – `DeleteKey` удаляет только объект по `key_id`, не очищает связанные объекты.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] `ListKeys` с инициализированным модулем – непустой вектор.
- [ ] `ListKeys` с неинициализированным модулем – пустой вектор.
- [ ] `FindKeyById` с существующим и несуществующим `key_id`.
- [ ] `FindKeyByLabel` с существующей и несуществующей меткой.
- [ ] `DeleteKey` с валидным `key_id` – `SUCCESS`.
- [ ] `ExportPublicKeyPem` для приватного и публичного ключа.
- [ ] `CountKeys` – корректное количество.

---

## 🔗 ЗАВИСИМОСТИ

- **`pkcs11_api.h`** – `ITokenModule`, `TokenResult`, `KeyInfo`.
- **`session_types.h`** – `SessionId`.
- **`token_types.h`** – `KeyType`, `KeySizeBits`.
- Стандартные библиотеки: `<string>`, `<vector>`, `<memory>`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Объявления функций | 🟢 Готово | Полный набор |
| Реализация | 🟢 Готово | Делегирует `ITokenModule` |
| Экспорт только публичного ключа | 🟢 Готово | Приватный ключ не покидает токен |
| Потокобезопасность | 🟡 Частично | Зависит от реализации модуля |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово
