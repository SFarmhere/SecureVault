# 📁 task_exception.cpp

## 🎯 НАЗНАЧЕНИЕ  
Обнаружение отладчиков через обработку исключений (Windows).  
- Устанавливает обработчик исключений и проверяет, не был ли процесс отлажен.  
- Детектирует отладчики, которые перехватывают исключения (SEH chain checking).  
- Используется в anti-debug защите для Windows.  
- Обнаруживает как ring3, так и ring0 отладчики.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `process_id` | `DWORD` | Caller | PID процесса (по умолч. 0 = текущий) |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Данные | Тип | Куда | Описание |
|--------|-----|------|----------|
| `detected` | `bool` | Caller | `true` если отладчик обнаружен |
| `exception_count` | `uint32_t` | Caller | Количество перехваченных исключений |
| `error` | `ErrorCode` | Caller | Код ошибки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **SEH chain modified** – обработчик исключений был изменен отладчиком.
- [x] **EXCEPTION_DEBUG_EVENT** – процесс находится под отладчиком.
- [x] **UnhandledExceptionFilter** – перехвачен отладчиком.
- [x] **Vectored handlers** – проверка vectored exception handling.
- [ ] **Anti-anti-debug** – обход через restoring SEH.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Запуск под x64dbg → detected = true.
- [ ] Запуск без отладчика → detected = false.
- [ ] Проверка SEH chain.
- [ ] Проверка vectored handlers.
- [ ] Обработка исключений в разных потоках.

---

## 🔗 ЗАВИСИМОСТИ

- **`integrity_checker/`** – проверка целостности PE файла.
- **`ntglobalflag.cpp`** – дополнительная проверка NtGlobalFlag.
- **`error_codes.h`** – `ErrorCode`.
- Windows API: `SetUnhandledExceptionFilter`, `AddVectoredExceptionHandler`, `IsDebuggerPresent`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| SEH chain checking | 🟢 Готово | Windows 7+ |
| EXCEPTION_DEBUG_EVENT | 🟢 Готово | Детекция |
| Vectored handlers | 🟢 Готово | Проверка |
| Anti-anti-debug | 🟡 Известно | Обход возможен |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово