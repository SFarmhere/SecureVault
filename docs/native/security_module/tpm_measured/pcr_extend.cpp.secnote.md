# 📁 pcr_extend.cpp

## 🎯 НАЗНАЧЕНИЕ  
Реализация операций TPM 2.0: расширение PCR (Platform Configuration Registers).  
- Измерение целостности компонентов системы (boot chain, kernel, modules).  
- Подпись PCR значений для attestation.  
- Используется в TPM measured boot для гарантии неизменности системы.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **pcr_extend** | `pcr_index` | `uint32_t` | Caller | Индекс PCR (0-23) |
| | `digest` | `ByteSpan` | Integrity checker | Хеш для расширения |
| **pcr_read** | `pcr_index` | `uint32_t` | Caller | Индекс PCR |
| **pcr_reset** | `pcr_index` | `uint32_t` | Caller | Индекс PCR |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **pcr_extend** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **pcr_read** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `pcr_value` | `std::array<uint8_t, 32>` | Caller | Значение PCR (SHA-256) |
| **pcr_reset** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **TPM не доступен** – возвращается `ERR_TPM_NOT_FOUND`.
- [x] **Некорректный индекс** – возвращается `ERR_INVALID_PCR_INDEX`.
- [x] **Нет прав** – возвращается `ERR_TPM_AUTH_FAILED`.
- [x] **Атака на загрузчик** – PCR 0-7 измеряют boot chain.
- [ ] **Replay attack** – PCR значения можно перезаписать при перезагрузке.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] PCR extend с известным хешем.
- [ ] PCR read после extend.
- [ ] PCR reset.
- [ ] Обработка ошибок (TPM не найден, нет прав).
- [ ] Интеграционные тесты с реальным TPM.

---

## 🔗 ЗАВИСИМОСТИ

- **`tpm_measured/`** – модуль TPM.
- **`integrity_checker/`** – хеширование файлов.
- **`crypto_module`** – SHA-256, SHA-1.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| PCR extend | 🟢 Готово | SHA-1, SHA-256 |
| PCR read | 🟢 Готово | Все индексы |
| PCR reset | 🟢 Готово | Сброс значений |
| Attestation | 🟢 Готово | Подпись PCR |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово