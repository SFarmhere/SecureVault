# 📁 format_v2.h

## 🎯 НАЗНАЧЕНИЕ  
Формат контейнера v2 со скрытыми контейнерами (plausible deniability).  
- Внешний контейнер выглядит как случайные данные.  
- Внутренний контейнер скрыт на псевдослучайном смещении.  
- Без пароля невозможно доказать существование скрытого контейнера.  
- Использует Argon2id для KDF, AES-256-GCM для шифрования.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **encrypt_hidden_header** | `header` | `const ContainerV2HiddenHeader&` | Caller | Заголовок для шифрования |
| | `password` | `const std::string&` | User | Внутренний пароль |
| | `output` | `ByteArray&` | Caller | Зашифрованный заголовок |
| **decrypt_hidden_header** | `encrypted_header` | `ByteSpan` | Container | Зашифрованный заголовок |
| | `password` | `const std::string&` | User | Внутренний пароль |
| | `header` | `ContainerV2HiddenHeader&` | Caller | Расшифрованный заголовок |
| **find_hidden_header** | `container_data` | `ByteSpan` | Container | Данные контейнера |
| | `password` | `const std::string&` | User | Внутренний пароль |
| | `header_offset` | `DataSize&` | Caller | Смещение заголовка |
| **generate_outer_padding** | `size` | `size_t` | Caller | Размер padding |
| | `output` | `ByteArray&` | Caller | Случайные байты |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **encrypt_hidden_header** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `output` | `ByteArray&` | Caller | Зашифрованный заголовок |
| **decrypt_hidden_header** | `result` | `ErrorCode` | Caller | `SUCCESS` или `TAG_MISMATCH` |
| | `header` | `ContainerV2HiddenHeader&` | Caller | Расшифрованный заголовок |
| **find_hidden_header** | `result` | `ErrorCode` | Caller | `SUCCESS` или `HIDDEN_CONTAINER_NOT_FOUND` |
| | `header_offset` | `DataSize&` | Caller | Смещение заголовка |
| **generate_outer_padding** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `output` | `ByteArray&` | Caller | Случайные байты |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Неверный пароль** – `decrypt_hidden_header` возвращает `TAG_MISMATCH`.
- [x] **Заголовок не найден** – `find_hidden_header` возвращает `HIDDEN_CONTAINER_NOT_FOUND`.
- [x] **Минимальный размер** – контейнер v2 минимум 64 MB.
- [x] **Внешний заголовок** – не содержит магических байт, выглядит как случайные данные.
- [x] **KDF Argon2id** – защита от brute-force.
- [ ] **Повреждение данных** – поведение при неполном файле.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Создание скрытого контейнера.
- [ ] Открытие с правильным паролем.
- [ ] Открытие с неверным паролем — `TAG_MISMATCH`.
- [ ] Поиск заголовка по паролю.
- [ ] Заголовок не найден при неверном пароле.
- [ ] Проверка plausible deniability — внешний контейнер неотличим от случайных данных.

---

## 🔗 ЗАВИСИМОСТИ

- **`crypto_module`** – AES-256-GCM для шифрования заголовка.
- **`common_types.h`** – `DataSize`, `ByteSpan`, `ByteArray`, `KdfAlgorithm`.
- **`error_codes.h`** – `ErrorCode`, `TAG_MISMATCH`, `HIDDEN_CONTAINER_NOT_FOUND`.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Формат v2 | 🟢 Готово | Скрытые контейнеры |
| Шифрование заголовка | 🟢 Готово | AES-256-GCM |
| KDF Argon2id | 🟢 Готово | Защита от brute-force |
| Plausible deniability | 🟢 Готово | Внешний контейнер = случайные данные |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: 🟢 Готово