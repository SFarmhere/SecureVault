# 📁 token_detector.cpp

## 🎯 НАЗНАЧЕНИЕ  
Реализует обнаружение и идентификацию аппаратных токенов по пути к PKCS#11 библиотеке.

- `Detect` — определяет тип токена по подстрокам в пути (Рутокен, eToken, JaCarta, YubiKey, Smart Card).
- `DetectDetailed` — расширенная детекция с указанием производителя и уверенности.
- `IsLikelyPkcs11Library` — проверка расширения файла.
- `NormalizePath` — нормализация пути (lowercase, разделители).
- `GetStandardPaths` / `GetDefaultPath` — стандартные пути к библиотекам.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **Detect** | `library_path` | `const std::string&` | SlotManager, конфиг | Путь к PKCS#11 библиотеке |
| **DetectDetailed** | `library_path` | `const std::string&` | SlotManager | Путь к библиотеке |
| **IsLikelyPkcs11Library** | `path` | `const std::string&` | Вызывающий код | Любой путь |
| **NormalizePath** | `path` | `const std::string&` | Внутренний | Путь для нормализации |
| **GetDefaultPath** | `type` | `TokenType` | Вызывающий код | Тип токена |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **Detect** | `type` | `TokenType` | Вызывающий код | Тип токена или `UNKNOWN` |
| **DetectDetailed** | `info` | `TokenDetectionInfo` | Вызывающий код | Тип, производитель, уверенность |
| **IsLikelyPkcs11Library** | `ok` | `bool` | Вызывающий код | `true` если `.dll`/`.so`/`.dylib` |
| **NormalizePath** | `normalized` | `std::string` | Внутренний | Нормализованный путь |
| **GetStandardPaths** | `paths` | `std::vector<std::string>` | Вызывающий код | Стандартные пути |
| **GetDefaultPath** | `path` | `std::string` | Вызывающий код | Путь по умолчанию |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Пустой путь** – `Detect` возвращает `UNKNOWN`.
- [x] **Несоответствующее расширение** – `IsLikelyPkcs11Library` возвращает `false`.
- [x] **Неизвестный токен** – `Detect` возвращает `UNKNOWN` с нулевой уверенностью.
- [ ] **Ложные срабатывания** – подстроки могут совпадать с другими путями.
- [ ] **Кастомные токены** – требуют добавления в таблицу детекции.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] `Detect` для путей Рутокен, eToken, YubiKey, JaCarta, Smart Card.
- [ ] `Detect` для пустого и некорректного пути.
- [ ] `DetectDetailed` – проверка типа, производителя, уверенности.
- [ ] `IsLikelyPkcs11Library` для `.dll`, `.so`, `.dylib`.
- [ ] `NormalizePath` – lowercase и нормализация разделителей.
- [ ] `GetStandardPaths` и `GetDefaultPath`.

---

## 🔗 ЗАВИСИМОСТИ

- **`token_detector.h`** – объявления функций.
- **`token_types.h`** – `TokenType`, `TokenDetectionInfo`.
- Стандартные библиотеки: `<string>`, `<vector>`, `<algorithm>`, `<cctype>`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Реализация детекции | 🟢 Готово | Поддержка 7+ токенов |
| Кроссплатформенность | 🟢 Готово | Пути для Windows/Linux/macOS |
| Расширенная детекция | 🟢 Готово | `TokenDetectionInfo` |
| Поддержка кастомных токенов | 🟡 Частично | Требует правки таблицы |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово
