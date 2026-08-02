# 📁 nitrokey.cpp

## 🎯 НАЗНАЧЕНИЕ  
Адаптер для FIDO2 токенов Nitrokey (Nitrokey FIDO2, Nitrokey 3).  
- Реализует CTAP2 протокол для устройств Nitrokey.  
- Поддержка HID транспорта (USB).  
- Аутентификация и регистрация credentials.  
- Интеграция с SecureVault для 2FA.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **nitrokey_init** | `device_path` | `std::string` | OS | Путь к устройству |
| **nitrokey_make_credential** | `rp_id` | `std::string` | WebAuthn | Relying Party ID |
| | `user_id` | `ByteSpan` | WebAuthn | User ID |
| | `challenge` | `ByteSpan` | WebAuthn | Random challenge |
| **nitrokey_get_assertion** | `credential_id` | `ByteSpan` | WebAuthn | Credential ID |
| | `challenge` | `ByteSpan` | WebAuthn | Random challenge |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **nitrokey_init** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `device_info` | `NitrokeyInfo` | Caller | Информация об устройстве |
| **nitrokey_make_credential** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `credential_id` | `ByteArray` | Caller | ID credential |
| | `attestation` | `ByteArray` | Caller | Attestation object |
| **nitrokey_get_assertion** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `assertion` | `ByteArray` | Caller | Assertion response |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Устройство не найдено** – возвращается `ERR_DEVICE_NOT_FOUND`.
- [x] **Неверный challenge** – возвращается `ERR_INVALID_CHALLENGE`.
- [x] **Токен извлечен** – возвращается `ERR_DEVICE_REMOVED`.
- [x] **Неподдерживаемая версия firmware** – возвращается `ERR_UNSUPPORTED_VERSION`.
- [ ] **Rate limit** – слишком много запросов.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Инициализация устройства Nitrokey FIDO2.
- [ ] Регистрация credential.
- [ ] Аутентификация с credential.
- [ ] Обработка извлечения токена.
- [ ] Обработка неверного challenge.
- [ ] Интеграционные тесты с Nitrokey 3.

---

## 🔗 ЗАВИСИМОСТИ

- **`ctap.h`** – CTAP2 протокол.
- **`fido2_api.h`** – высокоуровневый API.
- **`webauthn.h`** – WebAuthn структуры.
- **HID API** – `hidapi` для USB.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Nitrokey FIDO2 | 🟢 Готово | USB HID |
| Nitrokey 3 | 🟢 Готово | USB HID |
| CTAP2 support | 🟢 Готово | HID transport |
| Attestation | 🟢 Готово | Full attestation |
| Assertion | 🟢 Готово | User verification |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово