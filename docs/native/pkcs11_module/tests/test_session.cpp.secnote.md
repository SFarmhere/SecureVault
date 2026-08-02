```markdown
# 📁 test_session.cpp

## 🎯 НАЗНАЧЕНИЕ
**Модульные тесты для SessionManager с использованием Google Test и Google Mock.**
Проверяют:
- ✅ Корректность открытия/закрытия сессий
- ✅ Работу пула сессий и переиспользование
- ✅ Многопоточный доступ
- ✅ RAII обертку SessionGuard
- ✅ Таймауты и автоматическую очистку
- ✅ Обработку ошибок
- ✅ Инвалидацию слотов
- ✅ Производительность

## 🏗️ АРХИТЕКТУРА ТЕСТОВ

```
┌─────────────────────────────────────────────────────────┐
│                    test_session.cpp                     │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────┐                                    │
│  │  MockTokenModule│  ← ITokenModule mock              │
│  │  - OpenSession  │    с реальной реализацией        │
│  │  - CloseSession │    по умолчанию                  │
│  │  - SignRsa      │                                    │
│  └─────────────────┘                                    │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────┐   │
│  │              ТЕСТЫ (9 suites)                  │   │
│  ├─────────────────────────────────────────────────┤   │
│  │ 1. OpenClose              │  6. ErrorHandling  │   │
│  │ 2. SessionPool            │  7. InvalidateSlot │   │
│  │ 3. ConcurrentAccess       │  8. Performance    │   │
│  │ 4. SessionGuard           │                     │   │
│  │ 5. Timeout                │                     │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## 📥 ВХОДНЫЕ ДАННЫЕ (ОТКУДА)

| Данные | Откуда | Назначение |
|--------|--------|------------|
| `MockTokenModule` | Тестовый мок | Эмуляция токена |
| `slot_id = 0/1` | Тестовые данные | ID слотов |
| `pin = "12345678"` | Тестовые данные | Тестовый PIN |
| `TokenType::RUTOKEN` | Тестовые данные | Тип токена |
| 10 потоков | `std::async` | Нагрузка |
| 1000 итераций | Тестовый цикл | Производительность |

## 📤 ВЫХОДНЫЕ ДАННЫЕ (КУДА)

| Данные | Куда | Формат |
|--------|------|--------|
| Результаты тестов | stdout | Google Test |
| Статистика | std::cout | JSON-like |
| Время выполнения | std::cout | мкс/мс |
| PASS/FAIL | Консоль | Цветной вывод |

## ✅ ЧТО ТЕСТИРУЕТСЯ

### 1. **Базовое открытие/закрытие** ✅
```cpp
TEST(SessionManagerTest, OpenClose)
// Проверяет:
// - OpenSession возвращает ID > 0
// - CloseSession не падает
// - Сессия удаляется из контекста
```

### 2. **Пул сессий** ✅
```cpp
TEST(SessionManagerTest, SessionPool)
// Проверяет:
// - Максимум 5 реальных сессий (MAX_IDLE_SESSIONS_PER_SLOT)
// - Переиспользование IDLE сессий
// - Уникальность external_id
```

### 3. **Многопоточный доступ** ✅
```cpp
TEST(SessionManagerTest, ConcurrentAccess)
// Проверяет:
// - 10 потоков, 100 операций = 1000 успехов
// - Нет состояния гонки
// - Worker thread справляется
```

### 4. **RAII SessionGuard** ✅
```cpp
TEST(SessionManagerTest, SessionGuard)
// Проверяет:
// - OpenSession вызывается в конструкторе
// - CloseSession вызывается в деструкторе
// - ExecuteOperation работает
```

### 5. **Таймауты** ✅
```cpp
TEST(SessionManagerTest, Timeout)
// Проверяет:
// - IDLE сессия удаляется после SESSION_TIMEOUT
// - PeriodicCleanup() работает
```

### 6. **Обработка ошибок** ✅
```cpp
TEST(SessionManagerTest, ErrorHandling)
// Проверяет:
// - error_count увеличивается при ошибках
// - После 3 ошибок → state = ERROR
// - Следующая операция → ERR_SESSION_ERROR
```

### 7. **Инвалидация слотов** ✅
```cpp
TEST(SessionManagerTest, InvalidateSlot)
// Проверяет:
// - InvalidateSlotSessions() → все сессии слота EXPIRED
// - Другие слоты не затронуты
```

### 8. **Производительность** ✅
```cpp
TEST(SessionManagerTest, Performance)
// Проверяет:
// - 1000 операций < 1 секунды
// - Среднее время < 1 мс
```

## 🚨 КРИТИЧЕСКИЕ ПРОБЛЕМЫ (FIX NOW!)

### 🔴 P1: **ABI-несовместимость с `pkcs11_api.h`**

```cpp
// Сейчас:
int OpenSession(unsigned long slot_id, const std::string& pin)
void CloseSession(int session_id)
bool IsSessionValid(int session_id) const

// Должно быть (из pkcs11_api.h):
SessionId OpenSession(SlotId slot_id, const std::string& pin)
void CloseSession(SessionId session_id)
bool IsSessionValid(SessionId session_id) const
```

**Тесты используют старые сигнатуры!** ❌

### 🔴 P2: **MockTokenModule НЕ СООТВЕТСТВУЕТ ITokenModule**

```cpp
// MockTokenModule:
int OpenSession(unsigned long slot_id, const std::string& pin)

// ITokenModule (должен быть):
SessionId OpenSession(SlotId slot_id, const std::string& pin)
```

### 🔴 P3: **Тесты ЗАВИСЯТ от реализации SessionManager**

```cpp
// Тест Timeout делает:
ctx->last_used = ...  // ❌ Модифицирует private поле!
```

**Это хрупко и небезопасно!** Нужно использовать `protected` методы или дружественные тесты.

### 🔴 P4: **Нет проверки ошибок инициализации**
```cpp
// Ни один тест не проверяет:
- Initialize() с неверным путем
- OpenSession с неверным PIN
- OpenSession на пустом слоте
```

## 🟡 ПРОБЛЕМЫ СРЕДНЕЙ ВАЖНОСТИ

### 🟡 P5: **Нет тестов для граничных случаев**
```cpp
// Что не тестируется:
- MAX_IDLE_SESSIONS_PER_SLOT = 0 (отключение пула)
- SESSION_TIMEOUT = 0 (отключение таймаута)
- MAX_ERROR_COUNT = 0 (немедленная инвалидация)
- session_id переполнение ( > INT32_MAX )
```

### 🟡 P6: **Нет тестов для SessionManagerImpl**
```cpp
// Тестируется только фасад SessionManager
// Внутренняя имплементация не тестируется
```

### 🟡 P7: **Зависимость от реального времени**
```cpp
TEST(SessionManagerTest, Performance)
EXPECT_LT(avg_us, 1000);  // ❌ Флапает на CI под нагрузкой
```

**Решение:** Использовать `EXPECT_LE` с запасом или параметризовать порог.

### 🟡 P8: **Нет мока для `CK_SESSION_HANDLE`**
```cpp
// ExecuteOperation передает хендл в лямбду
// MockTokenModule его игнорирует (void)h
```

## 🧪 ПОКРЫТИЕ ТЕСТАМИ

| Компонент | Покрытие | Статус |
|-----------|----------|--------|
| `OpenSession()` | ✅ Полное | Есть тесты |
| `CloseSession()` | ✅ Полное | Есть тесты |
| `ExecuteOperation()` | ✅ Полное | Есть тесты |
| `GetSessionContext()` | 🟡 Частичное | Только в Timeout |
| `InvalidateSlotSessions()` | ✅ Полное | Есть тест |
| `PeriodicCleanup()` | ✅ Полное | Есть тест |
| `GetStatistics()` | 🟡 Частичное | Только вывод |
| **Ошибки инициализации** | ❌ Нет | **НЕТ ТЕСТОВ!** |
| **Граничные значения** | ❌ Нет | **НЕТ ТЕСТОВ!** |

## 🔗 ЗАВИСИМОСТИ

### Успешные
```cpp
#include <gtest/gtest.h>     // ✅ OK
#include <gmock/gmock.h>     // ✅ OK
#include <thread>           // ✅ OK
#include <chrono>          // ✅ OK
#include <future>          // ✅ OK
#include <atomic>          // ✅ OK
```

### Проблемные
```cpp
#include "../src/session/session_manager.cpp"
// 🔴 Включает .cpp, а не .h!
// Должно быть: #include "session_manager.h"
```

## 📊 МЕТРИКИ

| Метрика | Значение |
|---------|----------|
| Тест-сьютов | 8 |
| Ассертов | ~50 |
| Мок-методов | 15 |
| Потоков в тестах | До 10 |
| Время выполнения | ~500 мс |
| **Проблем** | **4 критические, 4 средние** |

## ✅ ЧТО РАБОТАЕТ ОТЛИЧНО

1. **MockTokenModule** — хорошая эмуляция токена
2. **ConcurrentAccess** — качественный многопоточный тест
3. **SessionGuard** — правильная RAII семантика
4. **ErrorHandling** — корректная логика счетчика ошибок
5. **InvalidateSlot** — правильная изоляция слотов

## 📝 ИСТОРИЯ ИЗМЕНЕНИЙ

| Дата | Автор | Изменение |
|------|-------|-----------|
| 2026-02-12 | @SFarmhere | Первая реализация |
| 2026-02-13 | @SFarmhere | **❗ КРИТИЧЕСКОЕ**: ABI-несовместимость |

## ✅ СТАТУС

**🟡 ТРЕБУЕТ ДОРАБОТКИ**

| Компонент | Статус | Комментарий |
|-----------|--------|-------------|
| Open/Close тесты | ✅ OK | Корректны |
| Пул сессий | ✅ OK | Проверен |
| Многопоточность | ✅ OK | Стабильно |
| SessionGuard | ✅ OK | RAII |
| Таймауты | ✅ OK | Работает |
| Ошибки | ✅ OK | error_count |
| Инвалидация | ✅ OK | По слотам |
| **ABI-совместимость** | 🔴 FAIL | Старые сигнатуры |
| **Мок-сигнатуры** | 🔴 FAIL | Не соответствуют API |
| **Private field access** | 🔴 FAIL | ctx->last_used |
| **Инициализация** | 🔴 FAIL | Нет тестов |
| **Граничные случаи** | 🟡 WARN | Нет coverage |
| **Performance flaky** | 🟡 WARN | Может падать на CI |

## 🎯 TODOs (ПО ПОРЯДКУ)

### 🔥 СРОЧНО (сегодня)
1. 🔄 Обновить сигнатуры `MockTokenModule`:
   ```cpp
   MOCK_METHOD(SessionId, OpenSession, (SlotId slot_id, const std::string& pin));
   MOCK_METHOD(void, CloseSession, (SessionId session_id));
   ```

2. 🔄 Исправить `#include`:
   ```cpp
   #include "session_manager.h"  // ✅
   // вместо
   #include "../src/session/session_manager.cpp"  // ❌
   ```

3. 🔄 Убрать прямой доступ к `ctx->last_used`:
   ```cpp
   // Добавить friend или protected метод
   void SetLastUsedForTesting(SessionId id, TimePoint time);
   ```

4. 🔄 Добавить тесты инициализации:
   ```cpp
   TEST(SessionManagerTest, Initialize_Fail_NoLibrary)
   TEST(SessionManagerTest, OpenSession_WrongPin)
   ```

### 📅 НА ЭТОЙ НЕДЕЛЕ
5. 🔄 Добавить тесты граничных значений
6. 🔄 Починить Performance тест (flaky)
7. 🔄 Добавить тесты для SessionManagerImpl

### 🎯 ПОТОМ
8. 📝 Интеграционные тесты с реальными токенами
9. 📝 Тесты утечек памяти (Valgrind)
10. 📝 Coverage report (gcov)

## 💥 КЛЮЧЕВЫЕ ЗАМЕЧАНИЯ

### 1. **Тесты — зеркало API**
Если API меняется, тесты должны меняться первыми.  
Сейчас они **отстают** от `pkcs11_api.h`.

### 2. **Мок — контракт**
`MockTokenModule` должен точно соответствовать `ITokenModule`.  
Любое расхождение — **ложная уверенность**.

### 3. **Хрупкие тесты — зло**
Прямая модификация `private` полей делает тесты **неподдерживаемыми**.  
Любое изменение реализации сломает тесты.

### 4. **Нет тестов = нет уверенности**
`SessionManager` — критический компонент.  
Без тестов инициализации и ошибок — **риск регрессии**.

---

**⚠️ ВАЖНО**: 
1. **ABI-совместимость — БЛОКЕР!** Нужно исправить сигнатуры немедленно.
2. **Никаких #include .cpp!** Это грубая ошибка.
3. **Не лазить в private поля!** Это делает тесты хрупкими.

**Приоритет: ABI → мок → #include → private → новые тесты** 🔥
```