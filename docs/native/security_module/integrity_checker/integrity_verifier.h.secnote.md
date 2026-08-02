# 📁 integrity_verifier.h

## 🎯 НАЗНАЧЕНИЕ  
Заголовочный файл для проверки целостности исполняемых файлов.  
- Поддерживает PE (Windows), ELF (Linux), Mach-O (macOS).  
- Проверяет хеши, цифровые подписи, импортируемые функции.  
- Используется в anti-debug защите для обнаружения модификаций.  
- Runtime integrity — проверка в памяти во время выполнения.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **verify_pe** | `path` | `std::string` | Caller | Путь к PE файлу |
| **verify_elf** | `path` | `std::string` | Caller | Путь к ELF файлу |
| **verify_macho** | `path` | `std::string` | Caller | Путь к Mach-O файлу |
| **verify_runtime** | `base_addr` | `uintptr_t` | Caller | Базовый адрес в памяти |
| | `size` | `size_t` | Caller | Размер кода |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **verify_pe** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `hash` | `ByteArray` | Caller | SHA-256 хеш |
| **verify_elf** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `hash` | `ByteArray` | Caller | SHA-256 хеш |
| **verify_macho** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `hash` | `ByteArray` | Caller | SHA-256 хеш |
| **verify_runtime** | `valid` | `bool` | Caller | `true` если целостность OK |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Файл не найден** – возвращается `ERR_FILE_NOT_FOUND`.
- [x] **Неверный формат** – возвращается `ERR_INVALID_FORMAT`.
- [x] **Подпись невалидна** – возвращается `ERR_SIGNATURE_INVALID`.
- [x] **Модификация кода** – runtime integrity обнаруживает изменения.
- [ ] **Self-modifying code** – ложные срабатывания.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Проверка PE файла (Windows).
- [ ] Проверка ELF файла (Linux).
- [ ] Проверка Mach-O файла (macOS).
- [ ] Runtime integrity — модификация памяти.
- [ ] Обработка ошибок (файл не найден, неверный формат).

---

## 🔗 ЗАВИСИМОСТИ

- **`crypto_module`** – SHA-256, SHA-1.
- **`security_module`** – anti-debug, secure_input.
- Системные API: `ImageDirectoryEntryToData` (PE), `dl_iterate_phdr` (ELF), `mach-o` loader.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| PE integrity | 🟢 Готово | Windows |
| ELF integrity | 🟢 Готово | Linux |
| Mach-O integrity | 🟢 Готово | macOS |
| Runtime integrity | 🟢 Готово | In-memory check |
| Digital signatures | 🟢 Готово | Authenticode, GPG |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово