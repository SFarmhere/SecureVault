# 📁 ctap.h

## 🎯 НАЗНАЧЕНИЕ  
Заголовочный файл для CTAP2 (Cloud-to-Device Authentication Protocol).  
- Определяет протокол обмена между FIDO2 устройством и хостом.  
- Поддерживает CTAP2.0 и CTAP2.1 (BLE, HID, NFC).  
- Используется для регистрации и аутентификации.  
- Безопасный канал: HID (USB), BLE (Bluetooth Low Energy).

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **ctap2_make_credential** | `rp_id` | `std::string` | WebAuthn | Relying Party ID |
| | `user_id` | `ByteSpan` | WebAuthn | User ID |
| | `challenge` | `ByteSpan` | WebAuthn | Random challenge |
| | `key_agreement` | `ByteSpan` | Device | Публичный ключ устройства |
| **ctap2_get_assertion** | `rp_id` | `std::string` | WebAuthn | Relying Party ID |
| | `challenge` | `ByteSpan` | WebAuthn | Random challenge |
| | `allow_list` | `ByteSpan` | WebAuthn | Список credential IDs |
| **ctap2_get_info** | — | — | Caller | Запрос информации об устройстве |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **ctap2_make_credential** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `credential_id` | `ByteArray` | Caller | ID созданного credential |
| | `attestation_object` | `ByteArray` | Caller | Attestation object |
| **ctap2_get_assertion** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `assertion` | `ByteArray` | Caller | Assertion response |
| **ctap2_get_info** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `info` | `Ctap2Info` | Caller | Информация об устройстве |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Устройство не найдено** – возвращается `ERR_DEVICE_NOT_FOUND`.
- [x] **Неверный challenge** – возвращается `ERR_INVALID_CHALLENGE`.
- [x] **Таймаут** – возвращается `ERR_TIMEOUT`.
- [x] **Устройство извлечено** – возвращается `ERR_DEVICE_REMOVED`.
- [ ] **BLE разрыв** – переподключение требуется.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] CTAP2 make_credential через HID.
- [ ] CTAP2 get_assertion через HID.
- [ ] CTAP2 через BLE.
- [ ] Обработка ошибок (таймаут, устройство извлечено).
- [ ] Интеграционные тесты с YubiKey, Nitrokey.

---

## 🔗 ЗАВИСИМОСТИ

- **`fido2_api.h`** – высокоуровневый API.
- **`webauthn.h`** – WebAuthn структуры.
- **HID API** – `hidapi` для USB.
- **BLE** – BlueZ, CoreBluetooth, WinRT.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| CTAP2.0 HID | 🟢 Готово | USB HID |
| CTAP2.0 BLE | 🟡 В работе | Требует BlueZ |
| CTAP2.1 | 🟡 В работе | В разработке |
| Attestation | 🟢 Готово | Full attestation |
| Assertion | 🟢 Готово | User verification |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово