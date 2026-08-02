# 📁 thunderbolt_policy.cpp

## 🎯 НАЗНАЧЕНИЕ  
Управление политиками безопасности Thunderbolt для защиты от DMA атак.  
- Проверка и установка security level (none, user, secure).  
- Обнаружение подключенных Thunderbolt устройств.  
- Блокировка недоверенных устройств.  
- Интеграция с Windows DMA Guard и Linux IOMMU.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **get_thunderbolt_devices** | — | — | Caller | Получить список устройств |
| **set_security_level** | `level` | `TbSecurityLevel` | Caller | Уровень безопасности |
| **block_device** | `device_id` | `uint64_t` | Caller | ID устройства для блокировки |
| **is_device_trusted** | `device_id` | `uint64_t` | Caller | ID устройства |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **get_thunderbolt_devices** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `devices` | `std::vector<TbDevice>` | Caller | Список устройств |
| **set_security_level** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **block_device** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| **is_device_trusted** | `trusted` | `bool` | Caller | `true` если устройство доверенное |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Thunderbolt не поддерживается** – возвращается `ERR_NOT_SUPPORTED`.
- [x] **Нет прав** – возвращается `ERR_ACCESS_DENIED`.
- [x] **Устройство уже заблокировано** – возвращается `ERR_ALREADY_BLOCKED`.
- [x] **Firmware outdated** – некоторые функции недоступны.
- [ ] **Hotplug** – устройство извлечено во время операции.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Получение списка Thunderbolt устройств.
- [ ] Установка security level (none, user, secure).
- [ ] Блокировка устройства.
- [ ] Проверка доверенного устройства.
- [ ] Обработка ошибок (нет прав, не поддерживается).

---

## 🔗 ЗАВИСИМОСТИ

- **`dma_protection/`** – IOMMU, Kernel DMA Guard.
- **`security_module`** – anti-debug, integrity checker.
- Системные API: `IOThunderboltController` (macOS), `tb.h` (Linux), `SetupAPI` (Windows).

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Device enumeration | 🟢 Готово | Список устройств |
| Security levels | 🟢 Готово | none, user, secure |
| Device blocking | 🟢 Готово | Блокировка недоверенных |
| Windows DMA Guard | 🟢 Готово | Интеграция |
| Linux IOMMU | 🟢 Готово | Интеграция |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово