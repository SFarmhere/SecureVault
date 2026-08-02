# 📁 test_token_detection.cpp

## 🎯 НАЗНАЧЕНИЕ  
Модульные тесты для `TokenDetector` — класса обнаружения и идентификации аппаратных токенов по пути к PKCS#11 библиотеке.  
- Тестирование `Detect`, `DetectDetailed`, `IsLikelyPkcs11Library`, `NormalizePath`, `GetStandardPaths`, `GetDefaultPath`.  
- Проверка кроссплатформенных путей (Windows `.dll`, Linux `.so`, macOS `.dylib`).  
- Проверка детекции всех поддерживаемых типов токенов.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Параметр | Тип | Откуда | Описание |
|----------|-----|--------|----------|
| `library_path` | `std::string` | Тестовые данные | Путь к PKCS#11 библиотеке |
| `type` | `TokenType` | Тестовые данные | Тип токена для `GetDefaultPath` |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Данные | Тип | Куда | Описание |
|--------|-----|------|----------|
| Результат теста | `bool` / assertion | Google Test | `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE` |
| `TokenType` | `TokenType` | Тест | Проверка детекции |
| `TokenDetectionInfo` | `TokenDetectionInfo` | Тест | Проверка типа, производителя, уверенности |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Пустой путь** – `Detect` возвращает `TokenType::UNKNOWN`.
- [x] **Несоответствующее расширение** – `IsLikelyPkcs11Library` возвращает `false`.
- [x] **Неизвестный токен** – `Detect` возвращает `UNKNOWN` с нулевой уверенностью.
- [x] **Разные регистры** – `NormalizePath` приводит к нижнему регистру.
- [ ] **Ложные срабатывания** – подстроки могут совпадать с другими путями.

---

## 🧪 ТЕСТЫ

- [x] `Detect_Rutoken_Windows` – детекция Рутокен по `rtpkcs11ecp.dll`.
- [x] `Detect_Rutoken_Linux` – детекция Рутокен по `librtpkcs11ecp.so`.
- [x] `Detect_eToken` – детекция eToken по `asepkcs.dll`.
- [x] `Detect_YubiKey` – детекция YubiKey по `libykcs11.so`.
- [x] `Detect_JaCarta` – детекция JaCarta.
- [x] `Detect_SmartCard` – детекция Smart Card.
- [x] `Detect_Unknown` – неизвестный путь возвращает `UNKNOWN`.
- [x] `Detect_EmptyPath` – пустой путь возвращает `UNKNOWN`.
- [x] `DetectDetailed_Success` – проверка типа, производителя, уверенности.
- [x] `IsLikelyPkcs11Library_Dll` – `.dll` возвращает `true`.
- [x] `IsLikelyPkcs11Library_So` – `.so` возвращает `true`.
- [x] `IsLikelyPkcs11Library_Dylib` – `.dylib` возвращает `true`.
- [x] `IsLikelyPkcs11Library_Invalid` – `.txt` возвращает `false`.
- [x] `NormalizePath_Lowercase` – путь в нижнем регистре.
- [x] `GetStandardPaths_NotEmpty` – стандартные пути не пустые.
- [x] `GetDefaultPath_Rutoken` – путь по умолчанию для Рутокен.

---

## 🔗 ЗАВИСИМОСТИ

- **`token_detector.h`** – тестируемые функции.
- **`token_types.h`** – `TokenType`, `TokenDetectionInfo`.
- **Google Test** – фреймворк тестирования.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Тесты детекции | 🟢 Готово | Все поддерживаемые типы |
| Тесты кроссплатформенности | 🟢 Готово | Windows/Linux/macOS |
| Тесты расширенной детекции | 🟢 Готово | `TokenDetectionInfo` |
| Тесты граничных случаев | 🟢 Готово | Пустой путь, неизвестный токен |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово