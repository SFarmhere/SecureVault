# 📁 yubikey_piv.cpp

## 🎯 НАЗНАЧЕНИЕ  
Адаптер для YubiKey PIV (Personal Identity Verification).  
- Реализует FIDO2/CTAP2 протокол для YubiKey 5 серии.  
- Поддержка PIV для сертификатов и аутентификации.  
- HID транспорта (USB).  
- Интеграция с SecureVault для 2FA и PKI.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **yubikey_init** | `device_path` | `std::string` | OS | Путь к устройству |
| **yubikey_make_credential** | `rp_id` | `std::string` | WebAuthn | Relying Party ID |
| | `user_id` | `ByteSpan` | WebAuthn | User ID |
| | `challenge` | `ByteSpan` | WebAuthn | Random challenge |
| **yubikey_get_assertion** | `credential_id` | `ByteSpan` | WebAuthn | Credential ID |
| | `challenge` | `ByteSpan` | WebAuthn | Random challenge |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **yubikey_init** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `device_info` | `YubiKeyInfo` | Caller | Информация об устройстве |
| **yubikey_make_credential** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `credential_id` | `ByteArray` | Caller | ID credential |
| | `attestation` | `ByteArray` | Caller | Attestation object |
| **yubikey_get_assertion** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
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

- [ ] Инициализация YubiKey 5.
- [ ] Регистрация credential.
- [ ] Аутентификация с credential.
- [ ] Обработка извлечения токена.
- [ ] Обработка неверного challenge.
- [ ] Интеграционные тесты с PIV.

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
| YubiKey 5 Series | 🟢 Готово | USB HID |
| PIV support | 🟢 Готово | Сертификаты |
| CTAP2 support | 🟢 Готово | HID transport |
| Attestation | 🟢 Готово | Full attestation |
| Assertion | 🟢 Готово | User verification |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово