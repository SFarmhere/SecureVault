# 📁 secure_file.cpp

## 🎯 НАЗНАЧЕНИЕ  
Безопасные файловые операции с шифрованием на лету.  
- Чтение/запись файлов с прозрачным шифрованием.  
- Интеграция с crypto_module для AES-256-GCM.  
- Защита от unauthorized access и data leakage.  
- Используется для работы с контейнерами и ключами.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **secure_file_open** | `path` | `std::string` | Caller | Путь к файлу |
| | `mode` | `FileOpenMode` | Caller | Режим открытия |
| | `key` | `ByteSpan` | KeyManager | Ключ шифрования |
| **secure_file_read** | `fd` | `int` | Caller | File descriptor |
| | `buf` | `ByteSpan` | Caller | Буфер для чтения |
| **secure_file_write** | `fd` | `int` | Caller | File descriptor |
| | `data` | `ByteSpan` | Caller | Данные для записи |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **secure_file_open** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `fd` | `int` | Caller | File descriptor |
| **secure_file_read** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `bytes_read` | `size_t` | Caller | Количество прочитанных байт |
| **secure_file_write` | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `bytes_written` | `size_t` | Caller | Количество записанных байт |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Файл не существует** – возвращается `ERR_FILE_NOT_FOUND`.
- [x] **Нет прав** – возвращается `ERR_ACCESS_DENIED`.
- [x] **Неверный ключ** – возвращается `ERR_DECRYPTION_FAILED`.
- [x] **Поврежденные данные** – возвращается `ERR_CORRUPTED_DATA`.
- [ ] **Диск заполнен** – возвращается `ERR_DISK_FULL`.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Открытие файла с шифрованием.
- [ ] Чтение/запись зашифрованных данных.
- [ ] Обработка неверного ключа.
- [ ] Обработка поврежденных данных.
- [ ] Performance тесты (throughput).
- [ ] Cross-platform тесты.

---

## 🔗 ЗАВИСИМОСТИ

- **`file_lock.cpp`** – блокировка файлов.
- **`file_permissions.cpp`** – права доступа.
- **`crypto_module`** – AES-256-GCM шифрование.
- **`secure_io_api.h`** – API для I/O операций.
- POSIX: `open`, `read`, `write`, `close`.
- Windows: `CreateFile`, `ReadFile`, `WriteFile`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Secure open | 🟢 Готово | С ключом шифрования |
| Secure read | 🟢 Готово | С дешифрованием |
| Secure write | 🟢 Готово | С шифрованием |
| Integrity check | 🟢 Готово | GCM tag verification |
| Cross-platform | 🟢 Готово | Windows, Linux, macOS |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово