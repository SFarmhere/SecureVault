# 📁 scramble_pad.cpp

## 🎯 НАЗНАЧЕНИЕ  
Реализация scramble pad для безопасного ввода PIN-кодов и паролей.  
- Защита от keyloggers и экранных шпионов.  
- Случайное расположение полей ввода на экране.  
- Шифрование ввода на уровне UI.  
- Используется для ввода PIN-кода токена и мастер-пароля.

---

## 📥 ВХОДНЫЕ ДАННЫЕ

| Функция | Параметр | Тип | Откуда | Описание |
|---------|----------|-----|--------|----------|
| **create_scramble_pad** | `prompt` | `std::string` | GUI | Подсказка для пользователя |
| | `length` | `uint32_t` | Caller | Длина ввода (PIN) |
| **get_input** | `pad_handle` | `ScramblePadHandle` | GUI | Хендл scramble pad |
| **destroy_scramble_pad** | `pad_handle` | `ScramblePadHandle` | GUI | Хендл для удаления |

---

## 📤 ВЫХОДНЫЕ ДАННЫЕ

| Функция | Возврат | Тип | Куда | Описание |
|---------|---------|-----|------|----------|
| **create_scramble_pad** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `pad_handle` | `ScramblePadHandle` | Caller | Хендл созданного pad |
| **get_input** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |
| | `input` | `std::string` | Caller | Введенный PIN/пароль |
| **destroy_scramble_pad** | `result` | `ErrorCode` | Caller | `SUCCESS` или код ошибки |

---

## 🚨 КРАЙНИЕ СЛУЧАИ

- [x] **Таймаут ввода** – возвращается `ERR_TIMEOUT`.
- [x] **Неверный PIN** – возвращается `ERR_WRONG_PIN` (после N попыток блокировка).
- [x] **Keylogger detected** – предупреждение, но продолжает работу.
- [x] **Скриншот** – scramble pad предотвращает захват.
- [ ] **Side-channel** – timing attacks на ввод.

---

## 🧪 ТЕСТЫ (планируемые)

- [ ] Создание scramble pad.
- [ ] Ввод правильного PIN.
- [ ] Ввод неверного PIN → `ERR_WRONG_PIN`.
- [ ] Таймаут ввода.
- [ ] Защита от keylogger (симуляция).
- [ ] Защита от скриншотов.

---

## 🔗 ЗАВИСИМОСТИ

- **`secure_io_module`** – безопасный ввод/вывод.
- **`crypto_module`** – шифрование ввода.
- **`security_module`** – anti-debug, secure_input.

---

## 📌 СТАТУС

| Элемент | Статус | Комментарий |
|---------|--------|-------------|
| Scramble pad UI | 🟢 Готово | Windows/Linux/macOS |
| Keylogger protection | 🟢 Готово | Random layout |
| Screenshot protection | 🟢 Готово | Secure window |
| Timeout | 🟢 Готово | Configurable |

**Общий статус:** 🟢 Готово.

---

⏰ Создано: 2026-08-02 12:00:00  
👤 Автор: @SFarmhere  
📌 Статус: � Готово