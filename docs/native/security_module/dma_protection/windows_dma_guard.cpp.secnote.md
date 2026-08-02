# 📁 windows_dma_guard.cpp

## 🎯 НАЗНАЧЕНИЕ  
Реализация Windows DMA Guard для защиты от DMA атак.  
- Включение Kernel DMA Protection на Windows 10 1809+.  
- Блокировка неавторизованных Thunderbolt/USB устройств.  
- Интеграция с Secure Boot и Windows Defender.  
- Используется в `dma_protection` для защиты от Cold Boot атак через DMA.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **enable_dma_guard** | — | — | Caller | Включить защиту |
| **is_dma_guard_enabled** | — | — | Caller | Проверить статус |
| **get_dma_devices** | — | — | Caller | Получить список DMA устройств |
| **block_dma_device** | `device_id` | `uint32_t` | Caller | ID устройства для блокировки |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **enable_dma_guard** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **is_dma_guard_enabled** | `enabled` | `bool` | Caller | `true` если защита активна |
| **get_dma_devices** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `devices` | `std::vector<DmaDevice>` | Caller | Список DMA устройств |
| **block_dma_device** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Нет прав** – возвращается `ERR_ACCESS_DENIED` (требует admin).
- [x] **Не поддерживается** – возвращается `ERR_NOT_SUPPORTED` (Windows < 10 1809).
- [x] **Устройство уже заблокировано** – возвращается `ERR_ALREADY_BLOCKED`.
- [x] **Secure Boot отключен** – DMA Guard может не работать.
- [ ] **Legacy devices** – старые устройства могут не поддерживаться.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Включение DMA Guard на Windows 10 1809+.
- [ ] Проверка статуса защиты.
- [ ] Получение списка DMA устройств.
- [ ] Блокировка устройства.
- [ ] Обработка ошибок (нет прав, не поддерживается).

---

## 🔗 ЗАВИСИМОСТИ

- **`dma_protection/`** – Thunderbolt, ACPI check, Kernel Lockdown.
- **`security_module`** – anti-debug, integrity checker.
- Windows API: `SetKernelDmaProtection`, `DeviceIoControl`, `SetupAPI`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| DMA Guard enable | 🟢 Готово | Windows 10 1809+ |
| Device enumeration | 🟢 Готово | Список DMA устройств |
| Device blocking | 🟢 Готово | Блокировка недоверенных |
| Secure Boot integration | 🟢 Готово | Проверка статуса |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово