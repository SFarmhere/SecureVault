# 📁 slot_manager.h

## 🎯 НАЗНАЧЕНИЕ  
Заголовочный файл для `SlotManager` — синглтона, управляющего слотами PKCS#11 токенов.  
- Обнаружение токенов, хотплаг (Linux/macOS/Windows).  
- Отслеживание состояния слотов и сессий.  
- Уведомление подписчиков о событиях (вставка/извлечение токена, ошибки).  
- Статистика и диагностика.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **Initialize** | — | — | Система | Инициализирует хотплаг, запускает watchdog |
| **Shutdown** | — | — | Система | Останавливает потоки, освобождает ресурсы |
| **RegisterModule** | `library_path` | `const std::string&` | Вызывающий код | Путь к PKCS#11 библиотеке |
| **UnregisterModule** | `library_path` | `const std::string&` | Вызывающий код | Путь к библиотеке |
| **GetAllSlots** | — | — | — | — |
| **GetSlotInfo** | `slot_id` | `SlotId` | Вызывающий код | ID слота |
| **FindSlotByUSB** | `vid`, `pid`, `serial` | `uint16_t`, `uint16_t`, `const std::string&` | Вызывающий код | USB VID/PID и серийный номер |
| **UpdateSlotState** | `slot_id`, `state` | `SlotId`, `SlotState` | SessionManager | Новое состояние слота |
| **IncrementSessionCount** | `slot_id` | `SlotId` | SessionManager | ID слота |
| **DecrementSessionCount** | `slot_id` | `SlotId` | SessionManager | ID слота |
| **ReportError** | `slot_id` | `SlotId` | SessionManager | ID слота |
| **Subscribe** | `callback` | `SlotEventCallback` | GUI / Python | Callback для событий |
| **Unsubscribe** | `subscription_id` | `int` | GUI / Python | ID подписки |
| **GetStatistics** | — | — | — | — |
| **ForceRescan** | — | — | — | — |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **GetInstance** | `SlotManager&` | `SlotManager&` | Вызывающий код | Ссылка на синглтон |
| **Initialize** | `ok` | `bool` | Система | `true` если успешно |
| **GetAllSlots** | `slots` | `std::vector<SlotInfoEx>` | Вызывающий код | Список слотов |
| **GetSlotInfo** | `info` | `std::unique_ptr<SlotInfoEx>` | Вызывающий код | Инфо или `nullptr` |
| **FindSlotByUSB** | `slot_id` | `SlotId` | Вызывающий код | ID слота или `-1` |
| **UpdateSlotState** | `ok` | `bool` | SessionManager | `true` если успешно |
| **Subscribe** | `id` | `int` | GUI / Python | ID подписки |
| **Unsubscribe** | `ok` | `bool` | GUI / Python | `true` если успешно |
| **GetStatistics** | `stats` | `std::string` | Вызывающий код | JSON-строка со статистикой |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Повторная инициализация** – `Initialize` идемпотентен.
- [x] **Слот не найден** – `GetSlotInfo` возвращает `nullptr`, `FindSlotByUSB` возвращает `-1`.
- [x] **Ошибка токена** – `ReportError` увеличивает счётчик, при `MAX_ERROR_COUNT` переводит в `ERROR`.
- [x] **Thread-safety** – все методы используют `recursive_mutex`.
- [ ] **Hotplug на Windows** – использует WMI/SetupAPI (частично реализовано).
- [ ] **Утечка подписчиков** – `Unsubscribe` по индексу может сместить ID других подписчиков.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] `GetInstance` возвращает один и тот же объект.
- [ ] `RegisterModule` / `UnregisterModule` – изменение списка модулей.
- [ ] `GetAllSlots` после инициализации.
- [ ] `FindSlotByUSB` с существующим и несуществующим VID/PID.
- [ ] `UpdateSlotState` – уведомление подписчиков.
- [ ] `GetStatistics` – корректный JSON.

---

## 🔗 ЗАВИСИМОСТИ

- **`session_types.h`** – `SlotId`, `SlotState`, `SlotEventType`.
- **`token_types.h`** – `TokenType`, `TokenInfo`.
- Стандартные библиотеки: `<string>`, `<vector>`, `<map>`, `<functional>`, `<memory>`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Singleton | 🟢 Готово | Thread-safe (C++11) |
| Hotplug | 🟡 Частично | Linux/macOS реализованы |
| Уведомления | 🟢 Готово | Callback-based |
| Статистика | 🟢 Готово | JSON-вывод |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово
