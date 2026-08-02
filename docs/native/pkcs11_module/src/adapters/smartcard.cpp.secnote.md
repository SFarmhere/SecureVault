```markdown
# 📁 smartcard.cpp

## 🎯 НАЗНАЧЕНИЕ
Универсальный адаптер для работы с **любыми смарт-картами** через PC/SC API.
Эмулирует PKCS#11 интерфейс поверх APDU команд ISO 7816.
**Ключевой компонент для поддержки ГОСТ, CIPF и госсектора.**

## ✅ ПОДДЕРЖИВАЕМЫЕ КАРТЫ

| Тип карты | Производитель | ATR (маска) | APDU | Статус |
|-----------|---------------|-------------|------|--------|
| **ГОСТ Р 34.10-2012** | КриптоПро | `3B 7F 96 00 ...` | 256 | ✅ FULL |
| **Рутокен ЭЦП (PC/SC)** | Aktiv | `3B 7F 38 00 ...` | 4096 | ✅ FULL |
| **eToken PRO JavaCard** | SafeNet | `3B 95 96 81 ...` | 2048 | ✅ FULL |
| **Generic ISO 7816** | Unknown | `3B xx ...` | 256 | 🟡 PARTIAL |
| **MiFare DESFire** | NXP | - | 256 | 🟡 PARTIAL |
| **JaCarta** | Алиот | - | 2048 | 🟡 BETA |

## 📥 ВХОДНЫЕ ДАННЫЕ (ОТ КОГО)

### Инициализация и сессии
| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `library_path` | `const std::string&` | `SessionManager` | ❌ Игнорируется (PC/SC системный) |
| `slot_id` | `unsigned long` | `SessionManager` | Индекс читателя (0..N-1) |
| `pin` | `const std::string&` | `GUI/CLI` | PIN-код карты (4-8 символов) |
| `session_id` | `int` | `SessionManager` | Внутренний ID сессии |

### Управление ключами
| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `params` | `const RsaKeyParams&` | `KeyManager` | Параметры RSA (key_size, label) |
| `key_id` | `const std::string&` | `KeyManager` | FID файла (hex) |
| `session_id` | `int` | `SessionManager` | ID сессии |

### Криптографические операции
| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `data` | `const std::vector<uint8_t>&` | `Crypto` | Данные для подписи |
| `plaintext` | `const std::vector<uint8_t>&` | `Crypto` | Открытый текст |
| `ciphertext` | `const std::vector<uint8_t>&` | `Crypto` | Шифротекст |
| `signature` | `const std::vector<uint8_t>&` | `Crypto` | Подпись для проверки |
| `params` | `const RsaSignParams&` | `Crypto` | Параметры подписи |
| `params` | `const RsaEncryptParams&` | `Crypto` | Параметры шифрования |

## 📤 ВЫХОДНЫЕ ДАННЫЕ (КУДА)

| Данные | Тип | Куда | Условие |
|--------|-----|------|---------|
| `session_id` | `int` | `SessionManager` | >0 успех, -1 ошибка |
| `key_id` | `std::string` | `KeyManager` | `CARD_KEY_XXXX` |
| `signature` | `std::vector<uint8_t>` | `Crypto` | RAW подпись от карты |
| `ciphertext` | `std::vector<uint8_t>` | `Crypto` | Зашифрованные данные |
| `plaintext` | `std::vector<uint8_t>` | `Crypto` | Расшифрованные данные |
| `keys` | `std::vector<KeyInfo>` | `GUI/CLI` | Список ключей (FID 0x1000-0x100F) |
| `atr` | `std::string` | `SlotManager` | Hex строка ATR |
| `tokens` | `std::vector<TokenInfo>` | `GUI/CLI` | Список читателей с картами |
| `result` | `TokenResult` | Вызывающий код | Статус операции |

## 🔧 СИСТЕМНЫЕ ВЫЗОВЫ (КУДА СТУЧИТСЯ)

### PC/SC API
| Функция | Библиотека | Назначение | Ошибки |
|---------|------------|------------|--------|
| `SCardEstablishContext()` | `winscard.dll`/`libpcsclite.so` | Инициализация PC/SC | `SCARD_E_NO_SERVICE` |
| `SCardListReadersA()` | PC/SC | Список читателей | `SCARD_E_NO_READERS_AVAILABLE` |
| `SCardGetStatusChangeA()` | PC/SC | Статус карты | `SCARD_E_TIMEOUT` |
| `SCardConnectA()` | PC/SC | Подключение к карте | `SCARD_W_REMOVED_CARD` |
| `SCardStatusA()` | PC/SC | Получение ATR | `SCARD_E_INVALID_HANDLE` |
| `SCardTransmit()` | PC/SC | Отправка APDU | `SCARD_E_PROTO_MISMATCH` |
| `SCardDisconnect()` | PC/SC | Отключение | `SCARD_E_INVALID_VALUE` |
| `SCardReleaseContext()` | PC/SC | Завершение | - |

### ISO 7816 APDU
| Инструкция | Код | Назначение |
|------------|-----|------------|
| `SELECT FILE` | `0xA4` | Выбор DF/EF |
| `VERIFY PIN` | `0x20` | Проверка PIN |
| `CHANGE PIN` | `0x24` | Смена PIN |
| `GENERATE ASYMMETRIC` | `0x46` | Генерация RSA |
| `PERFORM SECURITY OP` | `0x2A` | Подпись/верификация |
| `READ BINARY` | `0xB0` | Чтение данных |
| `UPDATE BINARY` | `0xD6` | Запись данных |

## 🧠 АЛГОРИТМ РАБОТЫ

### 1. Инициализация PC/SC
```
Initialize()
    ↓
SCardEstablishContext() → pcsc_context_
    ↓
initialized_ = true
```

### 2. Открытие сессии
```
OpenSession(slot_id, pin)
    ↓
ListReaders() → читатели[slot_id]
    ↓
SCardConnect() → card_handle
    ↓
SCardStatus() → ATR
    ↓
DetectCardType() → atr_info
    ↓
SelectFile(0x3F00) → MF
    ↓
VerifyPIN() → аутентификация
    ↓
cards_[session_id] = ctx
    ↓
return session_id
```

### 3. Проверка PIN
```
VerifyPIN(ctx, pin)
    ↓
APDU: CLA=0x00, INS=0x20, P1=0x00, P2=0x00
    data = PIN + 0xFF padding
    ↓
SW=0x9000 → SUCCESS
SW=0x63Cx → ERR_PIN_INCORRECT (x = попытки)
SW=0x6983 → ERR_PIN_LOCKED
```

### 4. APDU транзакция
```
TransmitAPDU(ctx, cmd)
    ↓
Формирование APDU (CLA, INS, P1, P2, Lc, data, Le)
    ↓
SCardTransmit()
    ↓
Парсинг ответа (data + SW1 SW2)
    ↓
return APDUResponse
```

## 🚨 КРИТИЧЕСКИЕ ПРОБЛЕМЫ (FIX NOW!)

### 🔴 P1: **ABI-несовместимость с `pkcs11_api.h`**

| Сигнатура | Сейчас | Должно быть |
|-----------|--------|-------------|
| `OpenSession` | `int OpenSession(unsigned long slot_id, ...)` | `SessionId OpenSession(SlotId slot_id, ...)` |
| `CloseSession` | `void CloseSession(int session_id)` | `void CloseSession(SessionId session_id)` |
| `SignRsa` | `std::vector<uint8_t> SignRsa(int session_id, ...)` | `std::vector<uint8_t> SignRsa(SessionId session_id, ...)` |

### 🔴 P2: **VerifyPIN() возвращает TokenResult, но вызывается как bool**
```cpp
// Строка ~559:
TokenResult result = VerifyPIN(ctx.get(), pin);
if (result != TokenResult::SUCCESS) {  // ❌ СЕЙЧАС: if (!VerifyPIN(...))
    return -1;
}
```

### 🔴 P3: **Нет проверки поддержки PC/SC на Linux/macOS**
```cpp
// Не проверяется, запущен ли pcscd
// SCardEstablishContext() может вернуть SCARD_E_NO_SERVICE
```

### 🔴 P4: **std::stoul() без try-catch**
```cpp
// Строка ~750:
uint16_t fid = static_cast<uint16_t>(std::stoul(key_id));
// key_id может быть "CARD_KEY_1000" → throw invalid_argument!
```

## 🟡 ПРОБЛЕМЫ СРЕДНЕЙ ВАЖНОСТИ

### 🟡 P5: **APDU размеры hardcoded**
```cpp
cmd.le = 256;        // Почему 256?
cmd.le = 512;        // Почему 512?
```
**Решение:** Использовать `ctx->atr_info.max_apdu_size`

### 🟡 P6: **Хеширование заглушка**
```cpp
// Строка ~735: ВРЕМЕННАЯ ЗАГЛУШКА!
hash.resize(32);
memcpy(hash.data(), data.data(), std::min(data.size(), size_t(32)));
```
**Решение:** Интегрировать OpenSSL или токеновый хеш

### 🟡 P7: **Генерация key_id нестабильна**
```cpp
// Строка ~640:
ss << "CARD_KEY_" << std::hex << (0x1000 + session_id % 0x1000);
// Не уникально, не сохраняется между сессиями
```

### 🟡 P8: **Нет поддержки extended APDU**
```cpp
// cmd.le > 256 обрабатывается, но не тестировалось
```

## 🟢 НИЗКИЙ ПРИОРИТЕТ

### 🟢 P9: **Нет кэширования файловой системы**
`file_cache_` объявлен, но не используется

### 🟢 P10: **Нет логирования PC/SC ошибок**
```cpp
LONG rv = SCardTransmit(...);
if (rv != SCARD_S_SUCCESS) {
    return nullptr;  // ❌ Тишина!
}
```

## 🧪 ТЕСТИРОВАНИЕ

### Unit-тесты (mock PC/SC)
- [ ] `Initialize()` / `Finalize()` lifecycle
- [ ] `ListReaders()` с мок-читателями
- [ ] `OpenSession()` с валидным/невалидным slot_id
- [ ] `VerifyPIN()` правильный/неправильный PIN
- [ ] `SelectFile()` существующий/несуществующий FID
- [ ] `TransmitAPDU()` корректный/битый APDU
- [ ] `DetectCardType()` по ATR (все известные типы)

### Интеграционные тесты (реальное железо)
- [ ] ГОСТ Р 34.10-2012 (КриптоПро)
- [ ] Рутокен ЭЦП в PC/SC режиме
- [ ] eToken PRO JavaCard
- [ ] Generic ISO 7816 (тестовая карта)
- [ ] Извлечение карты во время операции

### Performance тесты
- [ ] APDU roundtrip latency (среднее 10-50 мс)
- [ ] Генерация RSA-2048 (5-10 сек)
- [ ] Подпись 1KB (100 итераций)

## 🔗 СВЯЗАННЫЕ ФАЙЛЫ

| Файл | Отношение | Назначение |
|------|-----------|------------|
| `include/pkcs11_api.h` | implements | Интерфейс ITokenModule |
| `include/token_types.h` | uses | TokenType, KeyInfo |
| `session/session_manager.cpp` | caller | Управление сессиями |
| `session/slot_manager.cpp` | caller | PC/SC хотплаг |
| `rutoken.cpp` | similar | PKCS#11 версия |
| `etoken.cpp` | similar | PKCS#11 версия |
| `helpers/pkcs11_helpers.h` | should use | BytesToHex для ATR |
| `tests/test_smartcard.cpp` | should be | Модульные тесты |

## 📊 ЗАВИСИМОСТИ

### Внешние (обязательные)
| Зависимость | Windows | Linux | macOS |
|------------|---------|-------|-------|
| PC/SC | `winscard.lib` | `libpcsclite-dev` | `PCSC.framework` |
| Заголовки | `winscard.h` | `PCSC/winscard.h` | `PCSC/winscard.h` |
| Сервис | Встроенный | `pcscd` | `com.apple.CryptoTokenKit` |

### Внутренние
| Компонент | Тип | Причина |
|-----------|-----|---------|
| `ITokenModule` | Inheritance | Базовый интерфейс |
| `TokenResult` | Return | Коды ошибок |
| `KeyInfo` | Structure | Информация о ключах |
| `RsaKeyParams` | Parameter | Параметры генерации |

## 📈 МЕТРИКИ КОДА

| Метрика | Значение |
|---------|----------|
| Строк кода | ~750 |
| Методов | 18 |
| APDU команд | 10+ |
| ATR паттернов | 4 |
| PC/SC функций | 8 |
| FIXME/TODO | 5 |
| `#ifdef` платформ | 2 |

## 🎯 ОСОБЕННОСТИ СМАРТ-КАРТ

### PIN-код
| Карта | Попыток | SW |
|-------|---------|----|
| ГОСТ | 3 | `0x63C0`-`0x63C3` |
| eToken | 5 | `0x63C0`-`0x63C5` |
| Generic | varies | `0x63Cx` |

### Файловая система
| FID | Назначение |
|-----|------------|
| `0x3F00` | Master File (MF) |
| `0x1000`-`0x100F` | Приватные ключи |
| `0x2000`-`0x200F` | Сертификаты |
| `0x0015` | PIN файл |

### APDU статусы
| SW | Значение | Действие |
|----|---------|----------|
| `0x9000` | Успех | Продолжать |
| `0x61XX` | Еще данные | Get Response |
| `0x63CX` | PIN неверен | X = попытки |
| `0x6982` | Безопасность | Требуется PIN |
| `0x6983` | PIN заблокирован | Требуется PUK |
| `0x6A82` | Файл не найден | Проверить FID |

## 📝 ИСТОРИЯ ИЗМЕНЕНИЙ

| Дата | Автор | Изменение |
|------|-------|-----------|
| 2026-02-12 | @SFarmhere | Первая реализация |
| 2026-02-12 | @SFarmhere | Добавлен KNOWN_ATRS |
| 2026-02-13 | @SFarmhere | **❗ КРИТИЧЕСКОЕ**: Ошибка вызова VerifyPIN |

## ✅ СТАТУС

**🔴 ТРЕБУЕТ НЕМЕДЛЕННОГО ИСПРАВЛЕНИЯ**

| Компонент | Статус | Комментарий |
|-----------|--------|-------------|
| PC/SC инициализация | ✅ OK | `SCardEstablishContext` |
| Список читателей | ✅ OK | `SCardListReaders` |
| Подключение к карте | ✅ OK | `SCardConnect` |
| Получение ATR | ✅ OK | `SCardStatus` |
| Детекция по ATR | ✅ OK | 4 известных паттерна |
| Transmit APDU | ✅ OK | T0/T1 протокол |
| Verify PIN | 🔴 FAIL | Ошибка вызова (bool vs TokenResult) |
| Select File | ✅ OK | Навигация по DF |
| **ABI-стабильность** | 🔴 FAIL | unsigned long, int сигнатуры |
| **Exception safety** | 🔴 FAIL | `std::stoul` без try-catch |
| **Хеширование** | 🟡 WARN | Заглушка, небезопасно |
| **PC/SC ошибки** | 🟡 WARN | Нет логирования |
| **Тесты** | ⚪ N/A | Не написаны |
| **Extended APDU** | ⚪ N/A | Не тестировалось |

## 🎯 TODOs (ПО ПОРЯДКУ)

### 🔥 СРОЧНО (сегодня)
1. 🔄 Исправить вызов `VerifyPIN` (строка 559)
   ```cpp
   // Было:
   if (!VerifyPIN(ctx.get(), pin)) {
   
   // Стало:
   if (VerifyPIN(ctx.get(), pin) != TokenResult::SUCCESS) {
   ```

2. 🔄 Обновить сигнатуры под `SessionId`/`SlotId`
3. 🔄 Добавить `try-catch` вокруг `std::stoul`

### 📅 НА ЭТОЙ НЕДЕЛЕ
4. 🔄 Добавить проверку `pcscd` на Linux
5. 🔄 Интегрировать OpenSSL для хеширования
6. 🔄 Реализовать кэширование файловой системы

### 🎯 ПОТОМ
7. 📝 Написать unit-тесты с мок-PC/SC
8. 📝 Добавить поддержку extended APDU
9. 📝 Логирование PC/SC ошибок

## 💥 КРИТИЧЕСКИЙ БЛОКЕР

**Файл НЕ КОМПИЛИРУЕТСЯ в текущем состоянии!**

```cpp
// ОШИБКА КОМПИЛЯЦИИ:
error: invalid conversion from 'TokenResult' to 'bool' [-fpermissive]
if (!VerifyPIN(ctx.get(), pin)) {
     ^~~~~~~~~~~~~~~~~~~~~~~
```

**Это нужно исправить ПЕРВЫМ ДЕЛОМ!** 🚨

---

**⚠️ ВНИМАНИЕ**: Этот файл требует **НЕМЕДЛЕННОГО** исправления ошибки вызова `VerifyPIN`.
Без этого он даже не скомпилируется! 🔥
```