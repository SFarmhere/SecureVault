# 📁 test_utils.h

## 🎯 НАЗНАЧЕНИЕ  
Заголовочный файл с объявлениями вспомогательных функций для модульных тестов PKCS#11 модуля.  
- Генерация тестовых `KeyInfo`, `TokenInfo`, `CertificateInfo`.  
- Проверка соответствия структур.  
- Генерация случайных байт и hex-строк.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **GenerateHexId** | `bytes` | `size_t` (по умолч. 8) | Тесты | Количество байт для ID |
| **MakeTestKeyInfo** | `id` | `const std::string&` | Тесты | ID ключа |
| | `label` | `const std::string&` | Тесты | Метка |
| | `type` | `KeyType` (по умолч. RSA_PRIVATE) | Тесты | Тип ключа |
| | `bits` | `KeySizeBits` (по умолч. 2048) | Тесты | Размер |
| **MakeTestTokenInfo** | `type` | `TokenType` (по умолч. RUTOKEN) | Тесты | Тип токена |
| | `serial` | `const std::string&` (по умолч. "TEST-SERIAL-0001") | Тесты | Серийный номер |
| **MakeTestCertificate** | `id` | `const std::string&` | Тесты | ID сертификата |
| | `subject` | `const std::string&` (по умолч. "CN=Test") | Тесты | Subject DN |
| | `not_before_ms` | `int64_t` (по умолч. 0) | Тесты | Начало действия |
| | `not_after_ms` | `int64_t` (по умолч. 0) | Тесты | Окончание действия |
| **IsKeyInfoEqual** | `a`, `b` | `const KeyInfo&` | Тесты | Сравнение двух ключей |
| **IsTokenInfoEqual** | `a`, `b` | `const TokenInfo&` | Тесты | Сравнение двух токенов |
| **GenerateRandomBytes** | `size` | `size_t` | Тесты | Количество байт |
| **GenerateRandomHex** | `bytes` | `size_t` | Тесты | Количество байт |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **GenerateHexId** | `id` | `std::string` | Тесты | Hex-строка длины `bytes*2` |
| **MakeTestKeyInfo** | `info` | `KeyInfo` | Тесты | Заполненная структура |
| **MakeTestTokenInfo** | `info` | `TokenInfo` | Тесты | Заполненная структура |
| **MakeTestCertificate** | `info` | `CertificateInfo` | Тесты | Заполненная структура |
| **IsKeyInfoEqual** | `equal` | `bool` | Тесты | `true` если поля совпадают |
| **IsTokenInfoEqual** | `equal` | `bool` | Тесты | `true` если поля совпадают |
| **GenerateRandomBytes** | `data` | `std::vector<uint8_t>` | Тесты | Случайные байты |
| **GenerateRandomHex** | `hex` | `std::string` | Тесты | Hex-строка |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Пустой `id`/`label`** – `MakeTestKeyInfo` копирует пустые строки через `strncpy`.
- [x] **Нулевые временные поля** – `MakeTestCertificate` с нулевыми датами создаёт сертификат с `not_before_ms=0`, `not_after_ms=0`.
- [x] **Серийный номер** – `strncpy` обрезает при переполнении буфера.
- [ ] **Thread-safety** – функции не потокобезопасны.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] `GenerateHexId` – корректная длина и hex-символы.
- [ ] `MakeTestKeyInfo` – все поля заполнены.
- [ ] `MakeTestTokenInfo` – все поля заполнены.
- [ ] `MakeTestCertificate` – все поля заполнены.
- [ ] `IsKeyInfoEqual` – равные и неравные структуры.
- [ ] `IsTokenInfoEqual` – равные и неравные структуры.
- [ ] `GenerateRandomBytes` – непустой вектор нужного размера.
- [ ] `GenerateRandomHex` – корректная hex-строка.

---

## 🔗 ЗАВИСИМОСТИ

- **`token_types.h`** – `KeyInfo`, `TokenInfo`, `CertificateInfo`, `KeyType`, `TokenType`, `KeySizeBits`.
- Стандартные библиотеки: `<string>`, `<cstdint>`, `<vector>`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Объявления функций | 🟢 Готово | Полный набор |
| Генерация тестовых данных | 🟢 Готово | KeyInfo, TokenInfo, CertificateInfo |
| Проверка соответствия | 🟢 Готово | IsKeyInfoEqual, IsTokenInfoEqual |
| Потокобезопасность | 🔴 Отсутствует | Только для однопоточных тестов |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово
