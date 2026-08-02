# 📁 webauthn.h

## 🎯 НАЗНАЧЕНИЕ  
Заголовочный файл для WebAuthn API (W3C Web Authentication).  
- Определяет структуры для регистрации и аутентификации.  
- Поддерживает Attestation и Assertion.  
- Интеграция с CTAP2 протоколом.  
- Используется в веб-интерфейсе SecureVault.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **webauthn_register** | `rp_id` | `std::string` | WebApp | Relying Party ID |
| | `user_id` | `ByteSpan` | WebApp | User ID |
| | `challenge` | `ByteSpan` | WebApp | Random challenge |
| **webauthn_authenticate** | `credential_id` | `ByteSpan` | WebApp | Credential ID |
| | `challenge` | `ByteSpan` | WebApp | Random challenge |
| | `rp_id` | `std::string` | WebApp | Relying Party ID |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **webauthn_register** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `credential_id` | `ByteArray` | Caller | ID credential |
| | `public_key` | `ByteArray` | Caller | Публичный ключ |
| **webauthn_authenticate** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `signature` | `ByteArray` | Caller | Подпись аутентификации |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неверный challenge** – аутентификация отклонена.
- [x] **Токен извлечен** – возвращается `ERR_DEVICE_REMOVED`.
- [x] **Неподдерживаемый токен** – возвращается `ERR_UNSUPPORTED_TOKEN`.
- [x] **Phishing** – origin binding предотвращает атаки.
- [ ] **User verification** – требует PIN/biometric.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Регистрация через WebAuthn API.
- [ ] Аутентификация с правильным credential.
- [ ] Аутентификация с неверным challenge.
- [ ] Обработка извлечения токена.
- [ ] Интеграционные тесты с браузером.

---

## 🔗 ЗАВИСИМОСТИ

- **`ctap.h`** – CTAP2 протокол.
- **`fido2_api.h`** – высокоуровневый API.
- **`crypto_module`** – ECDSA, Ed25519.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Attestation | 🟢 Готово | Full attestation |
| Assertion | 🟢 Готово | User verification |
| Origin binding | 🟢 Готово | Anti-phishing |
| Browser integration | 🟢 Готово | Chrome, Firefox, Safari |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово