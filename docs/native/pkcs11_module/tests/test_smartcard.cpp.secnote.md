# 📁 test_smartcard.cpp

## 🎯 НАЗНАЧЕНИЕ  
Модульные и интеграционные тесты для `SmartcardModule` — адаптера смарт-карт через PC/SC API.  
- Тестирование инициализации PC/SC, подключения к картам, отправки APDU.  
- Тестирование детекции типа карты по ATR.  
- Тестирование VerifyPIN, SelectFile, генерации ключей, подписи.  
- Использует мок-реализации PC/SC функций для изоляции от реального железа.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `mock_pcsc` | `MockPCSC` | Тестовый фреймворк | Мок-реализация PC/SC API |
| `slot_id` | `SlotId` | Тестовые данные | Индекс читателя (0..N-1) |
| `pin` | `std::string` | Тестовые данные | Тестовый PIN ("12345678") |
| `atr` | `std::vector<uint8_t>` | Тестовые данные | Тестовый ATR карты |
| `apdu` | `APDU` | Тестовые данные | Тестовая APDU-команда |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Данные | Тип | Куда | Описание |
|--------|-----|------|----------|
| Результат теста | `bool` / assertion | Google Test | `EXPECT_EQ`, `EXPECT_TRUE` |
| `TokenResult` | `TokenResult` | Тест | Проверка кодов ошибок |
| `APDUResponse` | `APDUResponse` | Тест | Проверка SW1/SW2 |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **PC/SC не доступен** – `SCardEstablishContext` возвращает `SCARD_E_NO_SERVICE`.
- [x] **Нет читателей** – `SCardListReaders` возвращает `SCARD_E_NO_READERS_AVAILABLE`.
- [x] **Карта извлечена** – `SCardConnect` возвращает `SCARD_W_REMOVED_CARD`.
- [x] **Неверный PIN** – APDU `VERIFY PIN` возвращает `SW=0x63C2` (2 попытки).
- [x] **Заблокированный PIN** – APDU `VERIFY PIN` возвращает `SW=0x6983`.
- [x] **Файл не найден** – APDU `SELECT FILE` возвращает `SW=0x6A82`.
- [ ] **Extended APDU** – не тестировалось.
- [ ] **Реальная карта** – интеграционные тесты (опционально).

---

## 🧪 ТЕСТЫ

- [x] `Initialize_Success` – успешная инициализация PC/SC.
- [x] `Initialize_NoService` – PC/SC сервис недоступен.
- [x] `ListReaders_Success` – список читателей.
- [x] `ListReaders_NoReaders` – нет читателей.
- [x] `OpenSession_Success` – подключение к карте.
- [x] `OpenSession_CardRemoved` – карта извлечена.
- [x] `DetectCardType_GOST` – детекция ГОСТ по ATR.
- [x] `DetectCardType_Rutoken` – детекция Рутокен по ATR.
- [x] `DetectCardType_eToken` – детекция eToken по ATR.
- [x] `DetectCardType_Unknown` – неизвестная карта.
- [x] `VerifyPIN_Success` – правильный PIN.
- [x] `VerifyPIN_WrongPin` – неверный PIN (SW=0x63Cx).
- [x] `VerifyPIN_Locked` – заблокированный PIN (SW=0x6983).
- [x] `SelectFile_Success` – выбор файла.
- [x] `SelectFile_NotFound` – файл не найден (SW=0x6A82).
- [x] `TransmitAPDU_Success` – успешная APDU-транзакция.
- [x] `TransmitAPDU_ProtocolMismatch` – несоответствие протокола.

---

## 🔗 ЗАВИСИМОСТИ

- **`smartcard.cpp`** – тестируемый адаптер.
- **`pkcs11_api.h`** – `ITokenModule`, `TokenResult`.
- **`token_types.h`** – `TokenType`, `KeyInfo`, `TokenInfo`.
- **`test_utils.h`** – `GenerateHexId`, `MakeTestKeyInfo`, `GenerateRandomBytes`.
- **Google Test** – фреймворк тестирования.
- **Google Mock** – мок-реализации PC/SC API.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Unit-тесты PC/SC | 🟢 Готово | Мок-реализации |
| Тесты детекции ATR | 🟢 Готово | 4 известных паттерна |
| Тесты APDU | 🟢 Готово | VERIFY, SELECT, TRANSMIT |
| Тесты PIN | 🟢 Готово | Успех, неверный, заблокирован |
| Интеграционные тесты | 🔴 Отсутствует | Требуют реальную карту |
| Extended APDU | 🔴 Отсутствует | Не тестировалось |

**Общий статус:** 🟢 Готово (unit-тесты).

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово