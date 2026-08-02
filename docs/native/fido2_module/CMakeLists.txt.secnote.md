# 📁 CMakeLists.txt

## 🎯 НАЗНАЧЕНИЕ  
CMake-сборочный файл для `fido2_module` — модуля FIDO2/WebAuthn аутентификации.  
- Определяет библиотеку `securevault_fido2` (статическая).  
- Компилирует реализации CTAP2, HID, BLE транспорта.  
- Подключает адаптеры: YubiKey PIV, Nitrokey, SoloKey.  
- Устанавливает экспортированные цели для `find_package`.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `CMAKE_BUILD_TYPE` | `string` | CLI | Тип сборки (Release/Debug) |
| `SECUREVAULT_ENABLE_FIDO2_BLE` | `bool` | CLI | Включить BLE поддержку |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Данные | Тип | Куда | Описание |
|--------|-----|------|----------|
| `securevault_fido2` | `target` | CMake | Статическая библиотека |
| `securevault_fido2_test` | `target` | CMake | Тесты (Google Test) |
| `SecureVaultFIDO2Config.cmake` | `file` | install | Конфигурация пакета |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **HID не найден** – на Linux проверяется `/dev/hidraw*`.
- [x] **BLE не доступен** – требуется BlueZ/D-Bus.
- [x] **Windows** – используется WinUSB для HID.

---

## 🧪 ТЕСТЫ

- [ ] Сборка библиотеки на Windows/Linux/macOS.
- [ ] Сборка тестов с Google Test.
- [ ] `find_package(SecureVaultFIDO2)` из внешнего проекта.

---

## 🔗 ЗАВИСИМОСТИ

- **HID API** – `hidapi` для USB HID устройств.
- **BLE** – BlueZ (Linux), CoreBluetooth (macOS), WinRT (Windows).
- **Google Test** – для тестов (опционально).

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| CTAP2 HID | 🟢 Готово | USB HID |
| CTAP2 BLE | 🟡 В работе | Требует BlueZ |
| YubiKey PIV | 🟢 Готово | Адаптер |
| Nitrokey | 🟢 Готово | Адаптер |
| SoloKey | 🟢 Готово | Адаптер |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово