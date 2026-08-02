# 📁 fido2_api.h

## 🎯 НАЗНАЧЕНИЕ  
Публичный API модуля FIDO2/WebAuthn аутентификации.  
- Поддержка FIDO2 стандарта (CTAP2, U2F).  
- Аутентификация через аппаратные ключи (YubiKey, Nitrokey, SoloKey).  
- Защита от фишинга (origin binding), brute-force (rate limiting).  
- Интеграция с PKCS#11 модулем для токенов.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **register_credential** | `rp_id` | `std::string` | WebAuthn | Relying Party ID |
| | `user_handle` | `ByteSpan` | WebAuthn | User ID |
| | `challenge` | `ByteSpan` | WebAuthn | Random challenge |
| **authenticate** | `credential_id` | `ByteSpan` | WebAuthn | Credential ID |
| | `challenge` | `ByteSpan` | WebAuthn | Random challenge |
| | `rp_id` | `std::string` | WebAuthn | Relying Party ID |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **register_credential** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `credential_id` | `ByteArray` | Caller | ID созданного credential |
| | `public_key` | `ByteArray` | Caller | Публичный ключ |
| **authenticate** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `signature` | `ByteArray` | Caller | Подпись аутентификации |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неподдерживаемый токен** – возвращается `ERR_UNSUPPORTED_TOKEN`.
- [x] **Токен извлечен** – возвращается `ERR_DEVICE_REMOVED`.
- [x] **Неверный challenge** – аутентификация отклонена.
- [x] **Brute-force защита** – rate limiting после N неудачных попыток.
- [ ] **Phishing** – origin binding предотвращает атаки.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Регистрация credential через YubiKey.
- [ ] Аутентификация с правильным credential.
- [ ] Аутентификация с неверным challenge.
- [ ] Обработка извлечения токена.
- [ ] Rate limiting после N неудачных попыток.

---

## 🔗 ЗАВИСИМОСТИ

- **`ctap.h`** – CTAP2 протокол.
- **`webauthn.h`** – WebAuthn API.
- **`pkcs11_module`** – интеграция с токенами.
- **`crypto_module`** – ECDSA, Ed25519.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| CTAP2 поддержка | 🟢 Готово | HID, BLE |
| WebAuthn | 🟢 Готово | Assertion, Attestation |
| YubiKey | 🟢 Готово | PIV, FIDO2 |
| Nitrokey | 🟢 Готово | FIDO2 |
| SoloKey | 🟢 Готово | FIDO2 |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово