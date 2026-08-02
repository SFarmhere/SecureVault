# 📁 acpi_check.cpp

## 🎯 НАЗНАЧЕНИЕ  
Проверка ACPI (Advanced Configuration and Power Interface) для защиты от DMA атак.  
- Валидация ACPI таблиц (DSDT, SSDT, MADT).  
- Обнаружение поддельных ACPI таблиц.  
- Проверка IOMMU поддержки через ACPI.  
- Используется в DMA protection для гарантии целостности firmware.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **validate_acpi_tables** | — | — | Caller | Проверить все ACPI таблицы |
| **check_iommu_support** | — | — | Caller | Проверить IOMMU поддержку |
| **verify_dsdt** | `dsdt_ptr` | `uintptr_t` | Firmware | Указатель на DSDT |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **validate_acpi_tables** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `valid` | `bool` | Caller | `true` если таблицы валидны |
| **check_iommu_support** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `iommu_present` | `bool` | Caller | `true` если IOMMU доступен |
| **verify_dsdt** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `checksum_valid` | `bool` | Caller | `true` если checksum OK |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **ACPI не поддерживается** – возвращается `ERR_NOT_SUPPORTED`.
- [x] **Неверный checksum** – таблица может быть подделана.
- [x] **IOMMU не найден** – DMA protection ограничен.
- [x] **Устаревший BIOS** – ACPI версия < 2.0.
- [ ] **Malicious firmware** – ACPI таблицы могут быть модифицированы.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Валидация корректных ACPI таблиц.
- [ ] Обнаружение поврежденных таблиц.
- [ ] Проверка IOMMU поддержки.
- [ ] Проверка DSDT checksum.
- [ ] Тесты на разных BIOS/UEFI.

---

## 🔗 ЗАВИСИМОСТИ

- **`dma_protection/`** – IOMMU, Thunderbolt, Kernel DMA Guard.
- **`integrity_checker/`** – проверка целостности firmware.
- Системные API: `AcpiGetTable` (ACPI), `/sys/firmware/acpi` (Linux), `GetSystemFirmwareTable` (Windows).

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| ACPI table validation | 🟢 Готово | DSDT, SSDT, MADT |
| Checksum verification | 🟢 Готово | CRC32, checksum |
| IOMMU detection | 🟢 Готово | AMD-Vi, Intel VT-d |
| Firmware integrity | 🟢 Готово | Подпись таблиц |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово