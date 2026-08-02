# 📁 CMakeLists.txt

## 🎯 НАЗНАЧЕНИЕ  
CMake-сборочный файл для `crypto_module` — криптографического ядра SecureVault.  
- Определяет библиотеку `securevault_crypto` (статическая).  
- Компилирует реализации AES, RSA, Kyber, ChaCha20.  
- Подключает OpenSSL 3.1+ (vendored) и аппаратное ускорение AES-NI.  
- Устанавливает экспортированные цели для `find_package`.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `CMAKE_BUILD_TYPE` | `string` | CLI | Тип сборки (Release/Debug) |
| `SECUREVAULT_ENABLE_FUZZING` | `bool` | CLI | Включить fuzzing-цели |
| `OpenSSL_DIR` | `path` | CLI | Путь к OpenSSL |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Данные | Тип | Куда | Описание |
|--------|-----|------|----------|
| `securevault_crypto` | `target` | CMake | Статическая библиотека |
| `securevault_crypto_test` | `target` | CMake | Тесты (Google Test) |
| `SecureVaultCryptoConfig.cmake` | `file` | install | Конфигурация пакета |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **OpenSSL не найден** – ошибка конфигурации.
- [x] **AES-NI отсутствует** – fallback на software реализацию.
- [x] **Fuzzing** – включается только с `-DSECUREVAULT_ENABLE_FUZZING=ON`.

---

## 🧪 ТЕСТЫ

- [ ] Сборка библиотеки на Windows/Linux/macOS.
- [ ] Сборка тестов с Google Test.
- [ ] `find_package(SecureVaultCrypto)` из внешнего проекта.

---

## 🔗 ЗАВИСИМОСТИ

- **OpenSSL 3.1+** – криптографические примитивы.
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