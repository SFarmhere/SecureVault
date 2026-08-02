# 📁 fido2.py

## 🎯 НАЗНАЧЕНИЕ
FIDO2/WebAuthn аутентификация через аппаратные токены
YubiKey, SoloKey, Nitrokey, Touch ID

## 📥 ВХОДНЫЕ ДАННЫЕ
| Параметр | Откуда | Описание |
|----------|--------|----------|
| challenge | WebAuthn server | Случайные данные |
| user_id | DB | ID пользователя |
| pin | PIN dialog | PIN токена |
| origin | HTTP request | https://securevault.local |

## 📤 ВЫХОДНЫЕ ДАННЫЕ
| Данные | Куда |
|--------|------|
| assertion | WebAuthn server |
| attestation | DB |
| credential_id | DB |

## 🧪 ТЕСТЫ
- [ ] Регистрация нового ключа
- [ ] Аутентификация
- [ ] Resident keys
- [ ] PIN management

## 🔗 ЗАВИСИМОСТИ
- `fido2>=1.1.0`
- `cryptography`
- USB HID backend

## 🔗 СВЯЗАННЫЕ ФАЙЛЫ
- `api/routes/auth.py` — WebAuthn endpoints
- `gui/dialogs/pin_dialog.py` — ввод PIN
- `db/models.py` — FIDOCredential
