# 📁 tpm_manifest.json

## 🎯 НАЗНАЧЕНИЕ  
Манифест TPM 2.0 для измерения целостности системы.  
- Определяет PCR индексы и алгоритмы хеширования.  
- Описывает политики доступа к sealed secrets.  
- Конфигурация для TPM measured boot.  
- Используется для attestation и integrity verification.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Поле | Тип | Откуда | Описание |
|------|-----|--------|----------|
| `pcr_map` | `object` | Config | Маппинг PCR индексов |
| `hash_algorithms` | `array` | Config | SHA-1, SHA-256, SHA-384 |
| `policies` | `array` | Config | Политики доступа |
| `sealed_secrets` | `array` | Config | Запечатанные секреты |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Данные | Тип | Куда | Описание |
|--------|-----|------|----------|
| Манифест | `JSON` | TPM | Конфигурация TPM |
| PCR selection | `TPMS_PCR_SELECTION` | TPM | Выбранные PCR |
| Policy digest | `TPMS_POLICYDIGEST` | TPM | Хеш политики |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неверный PCR индекс** – возвращается `ERR_INVALID_PCR_INDEX`.
- [x] **Неподдерживаемый алгоритм** – возвращается `ERR_UNSUPPORTED_HASH`.
- [x] **Политика нарушена** – возвращается `ERR_POLICY_VIOLATION`.
- [x] **TPM не инициализирован** – возвращается `ERR_TPM_NOT_READY`.
- [ ] **Manifest устарел** – требуется обновление после изменений.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Загрузка корректного манифеста.
- [ ] Валидация PCR selection.
- [ ] Проверка политик доступа.
- [ ] Обработка ошибок (неверный индекс, алгоритм).
- [ ] Интеграционные тесты с TPM 2.0.

---

## 🔗 ЗАВИСИМОСТИ

- **`tpm_measured/`** – PCR extend, sealed secrets.
- **`crypto_module`** – SHA-1, SHA-256, SHA-384.
- **`security_module`** – integrity checker, anti-debug.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| PCR mapping | 🟢 Готово | Индексы 0-23 |
| Hash algorithms | 🟢 Готово | SHA-1, SHA-256, SHA-384 |
| Policy configuration | 🟢 Готово | N-of-M PCR |
| Sealed secrets | 🟢 Готово | TPM NV indices |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово