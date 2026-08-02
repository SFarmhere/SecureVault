# 📁 cache_attacks.cpp

## 🎯 НАЗНАЧЕНИЕ  
Защита от кэш-атак (cache attacks) в криптографических операциях.  
- Предотвращение утечки информации через кэш процессора.  
- Защита от Prime+Probe, Flush+Reload, Flush+Flush атак.  
- Используется в AES, RSA, ECDSA операциях.  
- Критично для безопасности на shared hosting.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **cache_flush** | `ptr` | `ByteSpan` | Caller | Указатель на данные |
| **cache_protect_start** | — | — | Caller | Начать защищенную секцию |
| **cache_protect_end** | — | — | Caller | Завершить защищенную секцию |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **cache_flush** | — | — | — | Кэш очищен (void) |
| **cache_protect_start** | `handle` | `CacheProtectHandle` | Caller | Хендл защищенной секции |
| **cache_protect_end** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Cache miss** – данные не в кэше, требуется reload.
- [x] **Shared cache** – атаки через L3/L2 кэш.
- [x] **Hyper-threading** – атаки через sibling core.
- [x] **Performance** – cache flush снижает производительность.
- [ ] **Memory ordering** – требуется barrier.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Cache flush тесты (CLFLUSH, CLFLUSHOPT).
- [ ] Prime+Probe защита.
- [ ] Flush+Reload защита.
- [ ] Тесты на multi-core системе.
- [ ] Performance benchmarks.

---

## 🔗 ЗАВИСИМОСТИ

- **`constant_time.cpp`** – константное время.
- **`crypto_module`** – AES, RSA, ECDSA.
- **`types.h`** – `ByteSpan`, `ErrorCode`.
- CPU instructions: `CLFLUSH`, `CLFLUSHOPT`, `LFENCE`, `MFENCE`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Cache flush | 🟢 Готово | CLFLUSH, CLFLUSHOPT |
| Prime+Probe protection | 🟢 Готово | Cache partitioning |
| Flush+Reload protection | 🟢 Готово | Memory barriers |
| Hyper-threading mitigation | 🟡 Частично | Требует HT disable |
| Performance optimization | 🟡 В работе | Selective flush |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово