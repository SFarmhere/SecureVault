# 📁 ntglobalflag.cpp

## 🎯 НАЗНАЧЕНИЕ  
Обнаружение отладчиков на Windows через проверку `NtGlobalFlag` в PEB.  
- Анализирует Process Environment Block (PEB) на наличие флагов отладки.  
- Детектирует x64dbg, OllyDbg, WinDbg и другие отладчики.  
- Используется в anti-debug защите для Windows.  
- Обнаруживает как пользовательские, так и kernel-mode отладчики.

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
| `flags` | `uint32_t` | Caller | Значение NtGlobalFlag |
| `error` | `ErrorCode` | Caller | Код ошибки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **NtGlobalFlag != 0** – флаги отладки установлены, отладчик обнаружен.
- [x] **BeingDebugged flag** – PEB->BeingDebugged == 1.
- [x] **Heap flags** – PEB->ProcessHeap->Flags проверяются.
- [x] **Kernel debugger** – `KPROCESS` флаги (Windows 10+).
- [ ] **Anti-anti-debug** – некоторые программы обходят эту проверку.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Запуск под x64dbg → detected = true.
- [ ] Запуск без отладчика → detected = false.
- [ ] Запуск под WinDbg → detected = true.
- [ ] Проверка NtGlobalFlag флагов (0x70, 0x40000000).

---

## 🔗 ЗАВИСИМОСТИ

- **`integrity_checker/`** – проверка целостности PE файла.
- **`error_codes.h`** – `ErrorCode`.
- Windows API: `NtQueryInformationProcess`, `ReadProcessMemory`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| NtGlobalFlag detection | 🟢 Готово | Windows 7+ |
| BeingDebugged | 🟢 Готово | PEB флаг |
| Heap flags | 🟢 Готово | ProcessHeap |
| Kernel debugger | 🟢 Готово | KPROCESS флаги |
| Anti-anti-debug | 🟡 Известно | Обход возможен |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово