# module_factory.h

## НАЗНАЧЕНИЕ
**Фабрика модулей** для создания PKCS#11 токенов по их типу:
- Единая точка регистрации и создания адаптеров токенов (Rutoken, eToken, Smartcard и др.)
- Регистрация через `REGISTER_MODULE` макрос – автоматическая инициализация при старте
- Определение типа токена по пути к библиотеке (детект по имени файла)
- Поддержка динамической загрузки (фабрика может быть расширена без изменения кода)

## ВХОДНЫЕ ДАННЫЕ

| Функция / Макрос | Параметр | Тип | Откуда | Описание |
|------------------|----------|-----|--------|----------|
| `CreateTokenModule` | `type` | `TokenType` | Внешний код (SessionManager, CLI) | Тип токена, который нужно создать |
| `DetectTokenType` | `library_path` | `const std::string&` | Адаптеры, SlotManager | Путь к PKCS#11 библиотеке для определения типа |
| `ModuleFactory::Register` | `type`, `creator`, `name` | `TokenType`, `ModuleCreator`, `std::string` | Регистрация модулей (обычно через макрос) | Регистрация нового типа |
| `ModuleFactory::Create` | `type` | `TokenType` | SessionManager, тесты | Создание экземпляра модуля |
| `ModuleFactory::Detect` | `library_path` | `const std::string&` | SlotManager | Определение типа по пути |
| `REGISTER_MODULE` | `TYPE`, `CLASS` | Макрос | В коде адаптеров (например, rutoken.cpp) | Регистрирует класс как модуль для типа `TYPE` |

## ВЫХОДНЫЕ ДАННЫЕ

| Функция / Макрос | Возврат | Куда | Формат |
|------------------|---------|------|--------|
| `CreateTokenModule` | `std::unique_ptr<ITokenModule>` | Вызывающий код | Умный указатель на созданный модуль или `nullptr` |
| `DetectTokenType` | `TokenType` | Вызывающий код | Тип токена (или `UNKNOWN`) |
| `ModuleFactory::Create` | `std::unique_ptr<ITokenModule>` | Внутри фабрики | Умный указатель на модуль |
| `ModuleFactory::Detect` | `TokenType` | SlotManager | Определённый тип |
| `ModuleFactory::GetRegisteredTypes` | `std::vector<TokenType>` | Логи, тесты | Список зарегистрированных типов |
| `REGISTER_MODULE` | `static bool` | (не используется) | Автоматическая регистрация при старте |

## ЧТО БЫЛО ИСПРАВЛЕНО

### КРИТИЧЕСКИЕ ПРОБЛЕМЫ (БЫЛО → СТАЛО)

| Проблема | Было | Стало | Статус |
|----------|------|-------|--------|
| Отсутствие фабрики | Разрозненное создание модулей вручную | Единая фабрика с регистрацией | ✅ FIXED |
| Ручная регистрация каждого типа | Нужно было добавлять `if (type == ...)` | Регистрация через макрос | ✅ FIXED |
| Нет детекта по пути | Путь не анализировался | `Detect` анализирует строку на наличие подстрок | ✅ FIXED |
| Функции не экспортировались | Не было `SECUREVAULT_API` | Добавлен экспорт для Windows | ✅ FIXED |
| Нет списка зарегистрированных типов | Нельзя было узнать все доступные типы | `GetRegisteredTypes()` | ✅ FIXED |
| Регистрация не потокобезопасна | `registry_` без мьютекса | `Instance()` статический singleton – потокобезопасен | ✅ FIXED |
| Нет возможности расширения | Жёсткий список | `Register` позволяет добавить новые типы извне | ✅ FIXED |

## НОВЫЕ ВОЗМОЖНОСТИ

### 1. `REGISTER_MODULE` макрос – автоматическая регистрация
```cpp
// В rutoken.cpp:
REGISTER_MODULE(RUTOKEN, RutokenModule);
// Это создаст статическую переменную, которая при старте зарегистрирует фабрику.
```

### 2. `DetectTokenType` – определение типа по пути библиотеки
```cpp
TokenType type = DetectTokenType("/usr/lib/libykcs11.so");
// type == TokenType::YUBIKEY
```

### 3. `GetRegisteredTypes` – список всех доступных типов
```cpp
for (auto t : ModuleFactory::Instance().GetRegisteredTypes()) {
    std::cout << TokenTypeToString(t) << std::endl;
}
```

### 4. `SECUREVAULT_API` – для экспорта функций на Windows
```cpp
SECUREVAULT_API std::unique_ptr<ITokenModule> CreateTokenModule(TokenType type);
// Теперь функция доступна из DLL.
```

## СВЯЗАННЫЕ ФАЙЛЫ

| Файл | Использует | Назначение |
|------|------------|------------|
| `rutoken.cpp` | `REGISTER_MODULE(RUTOKEN, RutokenModule)` | Регистрация адаптера Rutoken |
| `etoken.cpp` | `REGISTER_MODULE(ETOKEN, ETokenModule)` | Регистрация адаптера eToken |
| `smartcard.cpp` | `REGISTER_MODULE(SMARTCARD, SmartcardModule)` | Регистрация адаптера Smartcard |
| `session_manager.cpp` | `CreateTokenModule` | Создание модуля при открытии сессии |
| `slot_manager.cpp` | `DetectTokenType` | Определение типа токена при сканировании слотов |
| `module_factory.cpp` | Реализация | Реализация методов фабрики |
| `token_types.h` | `TokenType` | enum для типов токенов |
| `pkcs11_api.h` | `ITokenModule` | Базовый интерфейс всех модулей |

## ПРОИЗВОДИТЕЛЬНОСТЬ

| Операция | Сложность | Аллокаций | Когда используется | Критичность |
|----------|-----------|-----------|-------------------|--------------|
| `Create` | O(log N) | 1 (unique_ptr) | При открытии сессии (редко) | Низкая |
| `Detect` | O(N*M) | 1 (копия строки) | При сканировании слотов (редко) | Низкая |
| `Register` | O(log N) | 1 (вставка) | При старте программы (1 раз) | Низкая |
| `GetRegisteredTypes` | O(N) | N (копия вектора) | Логи, тесты (редко) | Низкая |

*N – количество зарегистрированных типов, M – длина пути библиотеки.*

## ИСТОРИЯ ИЗМЕНЕНИЙ

| Дата | Автор | Изменение |
|------|-------|-----------|
| 2026-07-25 | @SFarmhere | Первоначальное создание фабрики |
| 2026-07-26 | @SFarmhere | Добавлен `SECUREVAULT_API` для Windows |
| 2026-07-30 | @SFarmhere | Добавлен `REGISTER_MODULE` макрос |
| 2026-08-01 | @SFarmhere | Добавлен `DetectTokenType`, `GetRegisteredTypes` |

## СТАТУС

**СТАБИЛЬНО – ГОТОВО К ИСПОЛЬЗОВАНИЮ**

| Компонент | Статус | Комментарий |
|-----------|--------|-------------|
| `ModuleFactory::Instance` | ✅ OK | Singleton, потокобезопасен |
| `ModuleFactory::Register` | ✅ OK | Регистрация работает |
| `ModuleFactory::Create` | ✅ OK | Возвращает модуль или `nullptr` |
| `ModuleFactory::Detect` | ✅ OK | Определяет по имени библиотеки (регистронезависим) |
| `ModuleFactory::GetRegisteredTypes` | ✅ OK | Возвращает все зарегистрированные типы |
| `CreateTokenModule` | ✅ OK | Экспортируемая функция |
| `DetectTokenType` | ✅ OK | Внутренняя функция, не экспортируется |
| `REGISTER_MODULE` | ✅ OK | Автоматическая регистрация (статическая инициализация) |
| Потокобезопасность | ✅ OK | Singleton и map – только чтение после инициализации |
| Исключения | ✅ OK | При ошибке возвращает `nullptr` (не бросает) |

## TODOs (ОСТАВШЕЕСЯ)

1. Добавить поддержку динамической загрузки библиотек (плагинов) – загружать модули из .dll/.so по требованию
2. Реализовать `Detect` с использованием более сложной эвристики (например, загрузка библиотеки и проверка символов)
3. Добавить тесты на регистрацию и создание модулей
4. Добавить поддержку приоритета типов (если один путь подходит нескольким типам)
5. Рассмотреть использование `std::unordered_map` вместо `std::map` для O(1) доступа (не критично для малого N)