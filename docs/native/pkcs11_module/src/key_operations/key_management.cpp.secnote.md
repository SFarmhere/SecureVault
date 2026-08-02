# 📁 key_management.cpp

## 🎯 НАЗНАЧЕНИЕ  
Реализует высокоуровневые функции управления ключами на токенах, делегируя работу `ITokenModule`.

- `ListKeys` — список всех ключей на токене.
- `FindKeyById` / `FindKeyByLabel` — поиск ключа.
- `DeleteKey` — удаление ключа.
- `ExportPublicKeyPem` — экспорт **только публичного** ключа в PEM.
- `CountKeys` — количество ключей.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **ListKeys** | `module` | `ITokenModule&` | Вызывающий код | Инициализированный модуль |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| **FindKeyById** | `module` | `ITokenModule&` | Вызывающий код | Модуль |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `key_id` | `const std::string&` | Вызывающий код | ID ключа (hex) |
| **FindKeyByLabel** | `module` | `ITokenModule&` | Вызывающий код | Модуль |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `label` | `const std::string&` | Вызывающий код | Метка ключа |
| **DeleteKey** | `module` | `ITokenModule&` | Вызывающий код | Модуль |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `key_id` | `const std::string&` | Вызывающий код | ID ключа |
| **ExportPublicKeyPem** | `module` | `ITokenModule&` | Вызывающий код | Модуль |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |
| | `key_id` | `const std::string&` | Вызывающий код | ID ключа |
| **CountKeys** | `module` | `ITokenModule&` | Вызывающий код | Модуль |
| | `session_id` | `SessionId` | Вызывающий код | ID сессии |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **ListKeys** | `keys` | `std::vector<KeyInfo>` | Вызывающий код | Список ключей или пустой вектор |
| **FindKeyById** | `key` | `std::unique_ptr<KeyInfo>` | Вызывающий код | Ключ или `nullptr` |
| **FindKeyByLabel** | `key` | `std::unique_ptr<KeyInfo>` | Вызывающий код | Ключ или `nullptr` |
| **DeleteKey** | `result` | `TokenResult` | Вызывающий код | `SUCCESS` или ошибка |
| **ExportPublicKeyPem** | `pem` | `std::string` | Вызывающий код | PEM публичного ключа или `""` |
| **CountKeys** | `count` | `int` | Вызывающий код | Количество ключей или `-1` |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неинициализированный модуль** – все функции проверяют `module.IsInitialized()`.
- [x] **Пустой `key_id`/`label`** – возвращаются `nullptr`/`""`/`ERR_NOT_INITIALIZED`.
- [x] **Экспорт только публичного ключа** – если передан приватный ключ, ищется публичный с тем же `key_id`.
- [ ] **Потокобезопасность** – зависит от реализации `ITokenModule`.
- [ ] **Удаление связанных объектов** – `DeleteKey` удаляет только один объект.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] `ListKeys` с инициализированным/неинициализированным модулем.
- [ ] `FindKeyById` с существующим/несуществующим `key_id`.
- [ ] `FindKeyByLabel` с существующей/несуществующей меткой.
- [ ] `DeleteKey` с валидным `key_id`.
- [ ] `ExportPublicKeyPem` для приватного и публичного ключа.
- [ ] `CountKeys` – корректное количество.

---

## 🔗 ЗАВИСИМОСТИ

- **`key_management.h`** – объявления функций.
- **`pkcs11_api.h`** – `ITokenModule`, `TokenResult`, `KeyInfo`.
- **`session_types.h`** – `SessionId`.
- **`token_types.h`** – `KeyType`, `KeySizeBits`.
- Стандартные библиотеки: `<string>`, `<vector>`, `<memory>`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Реализация | 🟢 Готово | Делегирует `ITokenModule` |
| Экспорт публичного ключа | 🟢 Готово | Приватный ключ не экспортируется |
| Потокобезопасность | 🟡 Частично | Зависит от модуля |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово
