# 📁 secure_io_api.h

## 🎯 НАЗНАЧЕНИЕ  
Публичный API модуля безопасного ввода/вывода и затирания данных.  
- Безопасное удаление файлов (wipe) по методикам Гутманн, DoD 5220.22-M.  
- Защита от cold-boot атак: шифрование ключей в RAM, запрет swap.  
- Безопасный ввод PIN-кодов (scramble pad, защита от keyloggers).  
- Временные файлы с автоматическим удалением.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **secure_wipe_file** | `path` | `std::string` | Caller | Путь к файлу |
| | `passes` | `uint32_t` | Caller | Количество проходов (по умолч. 35 для Гутманн) |
| **secure_wipe_memory** | `ptr` | `void*` | Caller | Указатель на память |
| | `size` | `size_t` | Caller | Размер в байтах |
| **lock_memory** | `ptr` | `const void*` | Caller | Указатель на память |
| | `size` | `size_t` | Caller | Размер в байтах |
| **disable_swap** | — | — | Caller | Запрет выгрузки в swap |
| **create_secure_temp** | `prefix` | `std::string` | Caller | Префикс имени |
| **scramble_pin_input** | `prompt` | `std::string` | GUI | Подсказка для PIN |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **secure_wipe_file** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **secure_wipe_memory** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **lock_memory** | `result` | `ErrorCode` | Caller | `SUCCESS` или `ERR_MLOCK_FAILED` |
| **disable_swap** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **create_secure_temp` | `path` | `std::string` | Caller | Путь к временному файлу |
| **scramble_pin_input` | `pin` | `std::string` | GUI | Введенный PIN |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Недостаточно прав** – `secure_wipe_file` возвращает `ERR_ACCESS_DENIED`.
- [x] **mlock() не доступен** – `lock_memory` возвращает `ERR_MLOCK_FAILED`.
- [x] **Swap не отключен** – `disable_swap` возвращает предупреждение.
- [x] **SSD/NVMe** – wear leveling может игнорировать overwrite.
- [x] **Файловая система** – journaling может оставить копии в journal.
- [ ] **Временные файлы** – удаление при аварийном завершении.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Wipe файла (Гутманн, DoD, простой overwrite).
- [ ] Wipe памяти (volatile, secure allocator).
- [ ] mlock/munlock.
- [ ] Отключение swap.
- [ ] Создание/удаление временных файлов.
- [ ] Scramble pad ввод PIN.

---

## 🔗 ЗАВИСИМОСТИ

- **`crypto_module`** – AES-256 для wipe.
- **`memory_ops/`** – SecureAllocator, anti-cold-boot.
- **`file_ops/`** – безопасные файловые операции.
- **`wipe/`** – алгоритмы затирания (Гутманн, DoD).

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Wipe файлов | 🟢 Готово | Гутманн, DoD, simple |
| Wipe памяти | 🟢 Готово | SecureAllocator |
| mlock | 🟢 Готово | Защита от swap |
| Временные файлы | 🟢 Готово | Автоудаление |
| Scramble pad | 🟢 Готово | Защита от keyloggers |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово