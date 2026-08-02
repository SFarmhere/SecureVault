# 📁 power_analysis.cpp

## 🎯 НАЗНАЧЕНИЕ  
Защита от атак по потреблению мощности (power analysis).  
- Предотвращение утечки информации через анализ питания.  
- Защита от Simple Power Analysis (SPA) и Differential Power Analysis (DPA).  
- Используется в AES, RSA, ECDSA операциях на токенах.  
- Критично для безопасности аппаратных токенов.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **power_mask_start** | `operation` | `CryptoOp` | Caller | Тип операции |
| **power_mask_end** | `handle` | `PowerMaskHandle` | Caller | Хендл маскировки |
| **randomize_timing** | `base_delay` | `uint32_t` | Caller | Базовая задержка |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **power_mask_start** | `handle` | `PowerMaskHandle` | Caller | Хендл маскировки |
| **power_mask_end** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **randomize_timing` | — | — | — | Задержка применена (void) |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **SPA attack** – простой анализ мощности.
- [x] **DPA attack** – дифференциальный анализ мощности.
- [x] **EM leakage** – электромагнитное излучение.
- [x] **Performance** – маскировка снижает скорость.
- [ ] **Hardware countermeasures** – требуется поддержка токена.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] SPA защита тесты.
- [ ] DPA защита тесты.
- [ ] Timing randomization тесты.
- [ ] Power consumption анализ.
- [ ] EM leakage тесты.

---

## 🔗 ЗАВИСИМОСТИ

- **`constant_time.cpp`** – константное время.
- **`cache_attacks.cpp`** – защита от кэш-атак.
- **`crypto_module`** – AES, RSA, ECDSA.
- **`types.h`** – `ByteSpan`, `ErrorCode`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| SPA protection | 🟢 Готово | Power masking |
| DPA protection | 🟢 Готово | Randomization |
| Timing randomization | 🟢 Готово | Jitter |
| EM leakage mitigation | 🟡 Частично | Требует Faraday cage |
| Hardware countermeasures | 🟡 В работе | Token support |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово