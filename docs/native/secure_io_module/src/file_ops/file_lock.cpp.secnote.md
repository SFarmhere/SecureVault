# 📁 file_lock.cpp

## 🎯 НАЗНАЧЕНИЕ  
Реализация блокировки файлов для защиты от concurrent access.  
- Advisory locking (fcntl, flock) для предотвращения гонок.  
- Mandatory locking для критичных операций.  
- Защита от race conditions при шифровании/дешифровании.  
- Используется в secure_io для атомарных операций.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **file_lock** | `fd` | `int` | Caller | File descriptor |
| | `lock_type` | `LockType` | Caller | Тип блокировки |
| **file_trylock** | `fd` | `int` | Caller | File descriptor |
| | `lock_type` | `LockType` | Caller | Тип блокировки |
| **file_unlock** | `fd` | `int` | Caller | File descriptor |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **file_lock** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **file_trylock** | `acquired` | `bool` | Caller | `true` если блокировка получена |
| **file_unlock** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Файл уже заблокирован** – возвращается `ERR_ALREADY_LOCKED`.
- [x] **Нет прав** – возвращается `ERR_ACCESS_DENIED`.
- [x] **Файл не существует** – возвращается `ERR_FILE_NOT_FOUND`.
- [x] **Deadlock** – обнаружение deadlock при блокировке.
- [ ] **NFS** – блокировки не работают над NFS.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Блокировка файла (exclusive/shared).
- [ ] Try-lock (неблокирующая попытка).
- [ ] Разблокировка файла.
- [ ] Concurrent access тесты (мultiple processes).
- [ ] Deadlock detection тесты.
- [ ] NFS compatibility тесты.

---

## 🔗 ЗАВИСИМОСТИ

- **`secure_file.cpp`** – безопасные файловые операции.
- **`file_permissions.cpp`** – права доступа.
- **`secure_io_api.h`** – API для I/O операций.
- POSIX: `fcntl`, `flock`, `lockf`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Advisory locking | 🟢 Готово | fcntl, flock |
| Mandatory locking | 🟢 Готово | chmod + setgid |
| Deadlock detection | 🟢 Готово | Lock ordering |
| NFS support | 🟡 Частично | NLM required |
| Cross-platform | 🟢 Готово | Windows, Linux, macOS |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово