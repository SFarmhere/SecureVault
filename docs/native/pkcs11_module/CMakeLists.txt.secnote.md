# 📁 CMakeLists.txt

## 🎯 НАЗНАЧЕНИЕ  
CMake-сборочный файл для `pkcs11_module` — модуля поддержки аппаратных токенов PKCS#11.  
- Определяет библиотеку `securevault_pkcs11` (статическая или динамическая).  
- Компилирует исходники: адаптеры (rutoken, etoken, smartcard), сессии, ключи, сертификаты, детектор.  
- Подключает зависимости: PC/SC (Linux/macOS), WinSCard (Windows).  
- Устанавливает экспортированные цели для `find_package`.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `CMAKE_BUILD_TYPE` | `string` | CLI | Тип сборки (Release/Debug) |
| `SECUREVAULT_BUILD_SHARED` | `bool` | CLI | Собирать как shared-библиотеку |
| `SECUREVAULT_ENABLE_FUZZING` | `bool` | CLI | Включить fuzzing-цели |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Данные | Тип | Куда | Описание |
|--------|-----|------|----------|
| `securevault_pkcs11` | `target` | CMake | Библиотека модуля |
| `securevault_pkcs11_test` | `target` | CMake | Тесты (Google Test) |
| `SecureVaultPKCS11Config.cmake` | `file` | install | Конфигурация пакета |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **PC/SC не найден** – на Linux проверяется `libpcsclite-dev`, на macOS — `PCSC.framework`.
- [x] **Windows** – используется `winscard.lib` из Windows SDK.
- [x] **Тесты** – включаются только если найден Google Test.
- [ ] **Fuzzing** – включается только с `-DSECUREVAULT_ENABLE_FUZZING=ON`.

---

## 🧪 ТЕСТЫ

- [ ] Сборка библиотеки на Windows/Linux/macOS.
- [ ] Сборка тестов с Google Test.
- [ ] `find_package(SecureVaultPKCS11)` из внешнего проекта.

---

## 🔗 ЗАВИСИМОСТИ

- **PC/SC** – `libpcsclite` (Linux), `PCSC.framework` (macOS), `winscard` (Windows).
- **Google Test** – для тестов (опционально).
- **CMake** – `CMakePackageConfigHelpers` для экспорта пакета.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Сборка библиотеки | 🟢 Готово | Windows/Linux/macOS |
| Тесты | 🟢 Готово | Google Test |
| Экспорт пакета | 🟢 Готово | `find_package` |
| Fuzzing | 🟡 Частично | Опционально |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово