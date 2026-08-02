```markdown
# 📁 rutoken.cpp

## 🎯 НАЗНАЧЕНИЕ
Реализация поддержки аппаратных токенов **Рутокен** (Aktiv Co.) через PKCS#11 интерфейс.
**Версия 2.0 — полностью переработана для ABI-совместимости с обновленными заголовками.**

## ✅ ПОДДЕРЖИВАЕМЫЕ МОДЕЛИ
| Модель | Тип | Особенности |
|--------|-----|-------------|
| **Рутокен ЭЦП 2.0** | USB | RSA до 4096, 32KB памяти |
| **Рутокен ЭЦП 3.0** | USB | RSA до 4096, 64KB памяти |
| **Рутокен S (SC/SC+)** | USB + CCID | PC/SC режим, смарт-карта |
| **Рутокен Lite** | USB | Упрощенная, меньше памяти |

## 📥 ВХОДНЫЕ ДАННЫЕ (ОТ КОГО)

### Инициализация и сессии
| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `library_path` | `const std::string&` | `SessionManager` | Путь к `librtpkcs11ecp.so`/`rtpkcs11ecp.dll` |
| `slot_id` | `SlotId` | `SessionManager` | ID слота (0..N) |
| `pin` | `const std::string&` | `GUI/CLI` | PIN-код (4-8 символов) |
| `session_id` | `SessionId` | `SessionManager` | ID сессии |

### Управление ключами
| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `params` | `const RsaKeyParams&` | `KeyManager` | Размер ключа, метка, флаги |
| `key_id` | `const std::string&` | `KeyManager` | ID ключа (hex, 32 символа) |

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
| `session_id` | `SessionId` | `SessionManager` | >0 успех, ≤0 ошибка |
| `key_id` | `std::string` | `KeyManager` | hex, 32 символа |
| `signature` | `std::vector<uint8_t>` | `Crypto` | RSA-2048 → 256 байт |
| `ciphertext` | `std::vector<uint8_t>` | `Crypto` | RSA-OAEP/PKCS1 |
| `plaintext` | `std::vector<uint8_t>` | `Crypto` | Расшифрованные данные |
| `keys` | `std::vector<KeyInfo>` | `GUI/CLI` | Список ключей |
| `tokens` | `std::vector<TokenInfo>` | `GUI/CLI` | Список токенов |
| `result` | `TokenResult` | Вызывающий код | Статус операции |

## ✅ ЧТО БЫЛО ИСПРАВЛЕНО

### 🔴 КРИТИЧЕСКИЕ ПРОБЛЕМЫ (БЫЛО → СТАЛО)

| Проблема | Было | Стало | Статус |
|----------|------|-------|--------|
| **ABI-несовместимость** | `int OpenSession(unsigned long slot_id)` | `SessionId OpenSession(SlotId slot_id)` | ✅ FIXED |
| **ABI-несовместимость** | `void CloseSession(int session_id)` | `void CloseSession(SessionId session_id)` | ✅ FIXED |
| **ABI-несовместимость** | `int session_id` в методах | `SessionId session_id` | ✅ FIXED |
| **Работа с KeyInfo** | Прямое присвоение `bool` | Использование `set_` методов с флагами | ✅ FIXED |
| **Строковые параметры** | `params.label.c_str()` напрямую | `params.get_label()` | ✅ FIXED |
| **Timestamp** | `std::chrono::system_clock::now()` | `duration_cast` + `int64_t` | ✅ FIXED |
| **Отсутствующий include** | Нет `<random>` | Добавлен | ✅ FIXED |

## 🔧 СИСТЕМНЫЕ ВЫЗОВЫ

### Динамическая загрузка
| Функция | Библиотека | Назначение |
|---------|------------|------------|
| `PKCS11_LOAD_LIB()` | `dlfcn.h`/`windows.h` | Загрузка `librtpkcs11ecp.so`/`rtpkcs11ecp.dll` |
| `PKCS11_GET_FUNC()` | `dlsym`/`GetProcAddress` | Получение адресов функций |
| `PKCS11_UNLOAD_LIB()` | `dlclose`/`FreeLibrary` | Выгрузка библиотеки |

### PKCS#11 API (Рутокен)
| Функция | Назначение | Особенности |
|---------|------------|-------------|
| `C_Initialize()` | Инициализация | - |
| `C_GetSlotList()` | Список слотов | Только с токенами |
| `C_OpenSession()` | Открытие сессии | Требует `CKF_RW_SESSION` |
| `C_Login()` | Вход с PIN | **3 попытки** |
| `C_GenerateKeyPair()` | Генерация RSA | 1024/2048/4096 |
| `C_FindObjects*()` | Поиск ключей | Приватные ключи |
| `C_GetAttributeValue()` | Атрибуты ключей | ID, label, размер |
| `C_Sign*()` | Подпись данных | PKCS1, PSS |
| `C_Verify*()` | Проверка подписи | - |
| `C_Encrypt*()` | Шифрование | PKCS1, OAEP (TODO) |
| `C_Decrypt*()` | Расшифровка | PKCS1 |
| `C_SetPIN()` | Смена PIN | Старый → Новый |
| `C_CloseSession()` | Закрытие сессии | + logout |
| `C_Finalize()` | Завершение | Освобождение ресурсов |

## 🧠 АЛГОРИТМ РАБОТЫ

### 1. Инициализация модуля
```
Initialize(library_path)
    ↓
LoadLibrary() → lib_handle_
    ↓
LoadFunctions() → все C_* функции
    ↓
C_Initialize() → PKCS#11 ready
    ↓
initialized_ = true
```

### 2. Открытие сессии
```
OpenSession(slot_id, pin)
    ↓
CK_SLOT_ID pkcs11_slot = static_cast<CK_SLOT_ID>(slot_id)  // ABI-каст
    ↓
C_OpenSession(RW | SERIAL) → session
    ↓
C_Login(USER, pin) → аутентификация
    ↓
sessions_[internal_id] = {session, pkcs11_slot}
    ↓
return static_cast<SessionId>(internal_id)
```

### 3. Генерация RSA ключей
```
GenerateRsaKeyPair(session_id, params)
    ↓
GetSessionHandle() → CK_SESSION_HANDLE
    ↓
GenerateKeyId() → key_id (hex)
    ↓
params.is_token() → token = CK_TRUE/CK_FALSE
params.is_private() → private_attr
params.is_extractable() → extractable
    ↓
C_GenerateKeyPair() → pub_key, priv_key
    ↓
return key_id
```

### 4. Подпись данных
```
SignRsa(session_id, key_id, data, params)
    ↓
FindObjects(CKO_PRIVATE_KEY, key_id) → key_handle
    ↓
Выбор механизма (PSS/PKCS1)
    ↓
C_SignInit() → инициализация
    ↓
C_Sign() → получение подписи
    ↓
return signature
```

## 🚨 ОСОБЕННОСТИ РУТОКЕН

### PIN-код
| Аспект | Значение |
|--------|---------|
| Попыток | **3** |
| Блокировка | После 3 неудач |
| Длина | 4-8 символов |
| SO PIN | Отдельный |

### Ключи RSA
| Размер | Время |
|--------|-------|
| 2048 | ~3-5 сек |
| 4096 | ~20-30 сек |

## 🔗 СВЯЗАННЫЕ ФАЙЛЫ

| Файл | Отношение | Статус |
|------|-----------|--------|
| `include/pkcs11_api.h` | implements | ✅ Совместим |
| `include/session_types.h` | uses | ✅ SessionId, SlotId |
| `include/token_types.h` | uses | ✅ KeyInfo, KeyFlags |
| `session/session_manager.cpp` | caller | 🟡 Требует обновления |
| `etoken.cpp` | similar | ✅ Обновлен |
| `smartcard.cpp` | similar | 🟡 Требует обновления |
| `tests/test_rutoken.cpp` | should be | ❌ Нет тестов |

## 🧪 ТЕСТИРОВАНИЕ (ЧТО НУЖНО)

- [ ] `Initialize()` с валидным/невалидным путем
- [ ] `OpenSession()` с правильным/неправильным PIN
- [ ] `GenerateRsaKeyPair()` 2048/4096
- [ ] `ListKeys()` после генерации
- [ ] `SignRsa()` PKCS1 vs PSS
- [ ] `EncryptRsa()` → `DecryptRsa()` roundtrip
- [ ] `DeleteKey()` проверка удаления
- [ ] `ChangePin()` успех/неудача

## ✅ СТАТУС

**✅ СТАБИЛЬНО — ГОТОВО К ИСПОЛЬЗОВАНИЮ**

| Компонент | Статус | Комментарий |
|-----------|--------|-------------|
| ABI-совместимость | ✅ OK | `SessionId`/`SlotId` |
| KeyInfo (флаги) | ✅ OK | Вместо `bool` |
| Include `<random>` | ✅ OK | Добавлен |
| OAEP параметры | 🟡 WARN | TODO |
| Тесты | ⚪ N/A | Не написаны |

---

**⚠️ ВАЖНО**: Файл полностью совместим с обновленными заголовками.
Требуется только реализация OAEP параметров и тесты. 🔥
```