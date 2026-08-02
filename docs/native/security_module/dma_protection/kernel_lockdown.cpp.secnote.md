# 📁 kernel_lockdown.cpp

## 🎯 НАЗНАЧЕНИЕ  
Реализация kernel lockdown для защиты от DMA атак.  
- Включение Kernel DMA Protection на Windows 10+.  
- Проверка и включение IOMMU в Linux (Intel VT-d, AMD-Vi).  
- Блокировка прямого доступа к памяти от устройств.  
- Используется в `dma_protection` для защиты от Thunderbolt/USB DMA.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **enable_kernel_dma_protection** | — | — | Caller | Включить защиту |
| **is_dma_protection_enabled** | — | — | Caller | Проверить статус |
| **set_iommu_policy** | `policy` | `IommuPolicy` | Caller | Политика IOMMU |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **enable_kernel_dma_protection** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **is_dma_protection_enabled** | `enabled` | `bool` | Caller | `true` если защита активна |
| **set_iommu_policy** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Нет прав** – возвращается `ERR_ACCESS_DENIED` (требует admin/root).
- [x] **Не поддерживается** – возвращается `ERR_NOT_SUPPORTED` (старое железо/ОС).
- [x] **IOMMU уже включен** – возвращается предупреждение.
- [x] **Совместимость** – некоторые устройства могут перестать работать.
- [ ] **Performance** – IOMMU может снизить производительность.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Включение kernel DMA protection на Windows 10+.
- [ ] Включение IOMMU на Linux (Intel VT-d, AMD-Vi).
- [ ] Проверка статуса защиты.
- [ ] Установка политики IOMMU.
- [ ] Обработка ошибок (нет прав, не поддерживается).

---

## 🔗 ЗАВИСИМОСТИ

- **`dma_protection/`** – Thunderbolt, ACPI check.
- **`security_module`** – anti-debug, integrity checker.
- Windows API: `SetKernelDmaProtection`, `DeviceIoControl`.
- Linux: `/sys/kernel/iommu`, `intel_iommu=on`, `amd_iommu=on`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Windows Kernel DMA Guard | 🟢 Готово | Windows 10 1809+ |
| Linux IOMMU | 🟢 Готово | Intel VT-d, AMD-Vi |
| Policy management | 🟢 Готово | Strict/Relaxed |
| Compatibility check | 🟢 Готово | Device whitelist |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово