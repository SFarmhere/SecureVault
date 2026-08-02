# 📁 constant_time.cpp

## 🎯 НАЗНАЧЕНИЕ  
Реализация константного времени (constant-time) операций для защиты от timing атак.  
- Гарантирует, что время выполнения не зависит от секретных данных.  
- Защита от timing attacks на AES, RSA, ECDSA.  
- Используется во всех криптографических операциях.  
- Критично для безопасности в сетевых протоколах.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **constant_time_eq** | `a` | `ByteSpan` | Caller | Первое значение |
| | `b` | `ByteSpan` | Caller | Второе значение |
| **constant_time_select** | `condition` | `bool` | Caller | Условие выбора |
| | `true_val` | `ByteSpan` | Caller | Значение если true |
| | `false_val` | `ByteSpan` | Caller | Значение если false |
| **constant_time_swap** | `a` | `ByteSpan` | Caller | Первое значение |
| | `b` | `ByteSpan` | Caller | Второе значение |
| | `condition` | `bool` | Caller | Условие обмена |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **constant_time_eq** | `result` | `bool` | Caller | `true` если равны |
| **constant_time_select** | `result` | `ByteArray` | Caller | Выбранное значение |
| **constant_time_swap** | — | — | Caller | Значения обменяны (in-place) |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Разные длины** – возвращается `false` для `constant_time_eq`.
- [x] **Timing leak** – время не зависит от данных.
- [x] **Compiler optimization** – предотвращение оптимизаций компилятором.
- [x] **CPU speculation** – защита от Spectre/Meltdown.
- [ ] **Cache attacks** – требуется дополнительная защита.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Тест на равенство (equal/not equal).
- [ ] Тест на выбор (select true/false).
- [ ] Тест на обмен (swap/no swap).
- [ ] Timing тесты (статистическое измерение времени).
- [ ] Compiler optimization tests (разные уровни оптимизации).

---

## 🔗 ЗАВИСИМОСТИ

- **`crypto_module`** – AES, RSA, ECDSA.
- **`types.h`** – `ByteSpan`, `ByteArray`.
- Используется в: `aes256_gcm.h`, `rsa.h`, `kyber1024.h`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| constant_time_eq | 🟢 Готово | O(n) сравнение |
| constant_time_select | 🟢 Готово | Conditional move |
| constant_time_swap | 🟢 Готово | XOR swap |
| Compiler barriers | 🟢 Готово | volatile, asm |
| Spectre mitigation | 🟢 Готово | LFENCE, speculation barriers |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово