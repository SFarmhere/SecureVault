# 📁 SecureVaultPKCS11Config.cmake.in

## 🎯 НАЗНАЧЕНИЕ  
Шаблон CMake-конфигурационного файла для пакета `SecureVaultPKCS11`.  
- Генерируется CMake при установке пакета (configure_package_config_file).  
- Позволяет внешним проектам находить `SecureVaultPKCS11` через `find_package(SecureVaultPKCS11)`.  
- Экспортирует целевые библиотеки, include-пути и зависимости.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `PACKAGE_VERSION` | `string` | CMake | Версия пакета |
| `SecureVaultPKCS11_INCLUDE_DIRS` | `path` | CMake | Пути к заголовкам |
| `SecureVaultPKCS11_LIBRARIES` | `target` | CMake | Целевые библиотеки |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Данные | Тип | Куда | Описание |
|--------|-----|------|----------|
| `SecureVaultPKCS11_FOUND` | `bool` | CMake | `TRUE` если пакет найден |
| `SecureVaultPKCS11_VERSION` | `string` | CMake | Версия пакета |
| `SecureVaultPKCS11_INCLUDE_DIRS` | `path` | CMake | Пути к заголовкам |
| `SecureVaultPKCS11_LIBRARIES` | `target` | CMake | Целевые библиотеки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Пакет не найден** – `find_package` сообщает `NOT FOUND`.
- [x] **Несовместимая версия** – проверка `PACKAGE_VERSION_COMPATIBLE`.
- [x] **Отсутствующие зависимости** – проверка через `find_dependency`.

---

## 🧪 ТЕСТЫ

- [ ] `find_package(SecureVaultPKCS11)` из внешнего проекта.
- [ ] Проверка `SecureVaultPKCS11_FOUND` = `TRUE`.
- [ ] Проверка `SecureVaultPKCS11_VERSION`.
- [ ] Компиляция тестового проекта с использованием пакета.

---

## 🔗 ЗАВИСИМОСТИ

- **CMake** – `configure_package_config_file`, `write_basic_package_version_file`.
- **CMakePackageConfigHelpers** – модуль CMake для генерации конфигурации.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Шаблон конфигурации | 🟢 Готово | Стандартный CMake-шаблон |
| Экспорт целей | 🟢 Готово | Библиотеки и include-пути |
| Проверка версии | 🟢 Готово | Через `PACKAGE_VERSION` |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово