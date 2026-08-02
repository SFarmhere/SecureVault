# 📁 file_permissions.cpp

## 🎯 НАЗНАЧЕНИЕ  
Управление правами доступа к файлам для криптографических операций.  
- Установка минимальных прав (0600, 0400) для ключей и контейнеров.  
- Проверка прав перед операциями шифрования/дешифрования.  
- Защита от unauthorized access к зашифрованным данным.  
- Используется в secure_io для всех файловых операций.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **set_file_permissions** | `path` | `std::string` | Caller | Путь к файлу |
| | `mode` | `FileMode` | Caller | Права доступа |
| **check_file_permissions** | `path` | `std::string` | Caller | Путь к файлу |
| | `required_mode` | `FileMode` | Caller | Требуемые права |
| **restrict_file_access** | `fd` | `int` | Caller | File descriptor |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **set_file_permissions** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **check_file_permissions** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `has_access` | `bool` | Caller | `true` если права достаточны |
| **restrict_file_access** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Нет прав** – возвращается `ERR_ACCESS_DENIED`.
- [x] **Файл не существует** – возвращается `ERR_FILE_NOT_FOUND`.
- [x] **Неподдерживаемая ОС** – возвращается `ERR_NOT_SUPPORTED`.
- [x] **Symlink attack** – проверка на символические ссылки.
- [ ] **ACL** – поддержка расширенных ACL.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Установка прав 0600 (owner only).
- [ ] Установка прав 0400 (read only).
- [ ] Проверка прав доступа.
- [ ] Обработка symlink атак.
- [ ] Cross-platform тесты (Windows, Linux, macOS).
- [ ] Privilege escalation защита.

---

## 🔗 ЗАВИСИМОСТИ

- **`secure_file.cpp`** – безопасные файловые операции.
- **`file_lock.cpp`** – блокировка файлов.
- **`secure_io_api.h`** – API для I/O операций.
- POSIX: `chmod`, `fchmod`, `stat`, `lstat`.
- Windows: `SetFileSecurity`, `GetFileSecurity`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| POSIX permissions | 🟢 Готово | chmod, fchmod |
| Windows ACL | 🟢 Готово | SetFileSecurity |
| Symlink protection | 🟢 Готово | O_NOFOLLOW, lstat |
| Privilege check | 🟢 Готово | geteuid, getuid |
| Cross-platform | 🟢 Готово | Windows, Linux, macOS |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово