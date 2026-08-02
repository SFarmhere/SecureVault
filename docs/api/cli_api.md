# SecureVault CLI API Reference

Версия: **2.0** · Исполняемый файл: `securevault` · Python 3.11+

---

## Оглавление

- Общие сведения
- Глобальные параметры
- Команды
  - init
  - encrypt
  - decrypt
  - container
  - token
  - config
  - sync
  - audit
  - recovery
- Коды возврата
- Примеры

---

## Общие сведения

CLI предоставляет полный набор возможностей SecureVault: инициализацию,
шифрование, управление контейнерами, аппаратными токенами, синхронизацию,
аудит и восстановление доступа.

Синтаксис: `securevault <command> [subcommand] [options]`

Все команды, требующие аппаратного токена, принимают параметр `--token-serial`
и запрашивают PIN интерактивно (или через `--pin` в неинтерактивном режиме).
PIN никогда не логируется и не выводится в аргументы процесса.

---

## Глобальные параметры

| Параметр                  | Описание                                          |
|---------------------------|---------------------------------------------------|
| `-v, --verbose`           | Подробный вывод                                   |
| `-q, --quiet`             | Только ошибки                                     |
| `--config <path>`         | Путь к конфигурационному файлу                    |
| `--log-level <level>`     | `DEBUG`, `INFO`, `WARNING`, `ERROR`               |
| `--no-color`              | Отключить цветной вывод                            |
| `--token-serial <serial>` | Серийный номер аппаратного токена                 |
| `--pin <pin>`             | PIN токена (не рекомендуется; используйте интерактив) |

---

## Команды

### init

Инициализация SecureVault.

```bash
securevault init [--token] [--force] [--self-signed]
```

| Параметр      | Описание                                                    |
|---------------|-------------------------------------------------------------|
| `--token`     | Использовать аппаратный токен для генерации ключей          |
| `--force`     | Пересоздать конфигурацию (опасно)                           |
| `--self-signed` | Создать самоподписанный X.509 сертификат на токене        |

**Пример:**

```bash
# Инициализация с токеном
securevault init --token

# Инициализация без токена (программные ключи, не рекомендуется)
securevault init
```

### encrypt

Шифрование файла.

```bash
securevault encrypt <file> [--level LEVEL] [--container ID] [--output PATH] [--pqc] [--algorithm NAME]
```

| Параметр       | Описание                                                    |
|----------------|-------------------------------------------------------------|
| `<file>`       | Путь к файлу (обязательный)                                 |
| `--level`      | Уровень защиты: `ORIGINAL`, `INDIVIDUAL`, `CONTAINER`, `HYPER` (по умолчанию `INDIVIDUAL`) |
| `--container`  | ID контейнера (для `CONTAINER`/`HYPER`)                     |
| `--output`     | Путь выходного файла                                         |
| `--pqc`        | Включить пост-квантовую криптографию (Kyber1024)            |
| `--algorithm`  | Алгоритм: `AES-256-GCM` (по умолчанию), `ChaCha20-Poly1305` |

**Пример:**

```bash
securevault encrypt secret.pdf --level INDIVIDUAL --pqc --output secret.pdf.enc
```

### decrypt

Расшифровка файла.

```bash
securevault decrypt <file> [--level LEVEL] [--output PATH]
```

| Параметр  | Описание                                                    |
|-----------|-------------------------------------------------------------|
| `<file>`  | Путь к зашифрованному файлу (обязательный)                  |
| `--level` | Уровень защиты: `INDIVIDUAL`, `CONTAINER`, `HYPER`          |
| `--output`| Путь выходного файла                                         |

**Пример:**

```bash
securevault decrypt secret.pdf.enc --output secret.pdf
```

### container

Управление контейнерами.

```bash
securevault container <subcommand> [options]
```

#### Подкоманды

| Подкоманда | Описание                                                    |
|------------|-------------------------------------------------------------|
| `create`   | Создать контейнер                                            |
| `list`     | Список контейнеров                                           |
| `mount`    | Смонтировать контейнер как виртуальный диск                  |
| `unmount`  | Размонтировать контейнер                                     |
| `info`     | Информация о контейнере                                      |
| `delete`   | Удалить контейнер                                            |
| `repair`   | Восстановить контейнер после сбоя (WAL)                      |

**Пример: создать контейнер**

```bash
securevault container create work.ctn.enc --size 10G --level CONTAINER
```

**Пример: смонтировать**

```bash
securevault container mount work.ctn.enc --drive E:
```

**Пример: восстановить**

```bash
securevault container repair work.ctn.enc
```

### token

Управление аппаратными токенами.

```bash
securevault token <subcommand> [options]
```

#### Подкоманды

| Подкоманда     | Описание                                                    |
|----------------|-------------------------------------------------------------|
| `list`         | Список подключенных токенов                                  |
| `info`         | Информация о токене                                          |
| `genkey`       | Сгенерировать ключевую пару на токене                        |
| `import-cert`  | Импортировать X.509 сертификат                               |
| `delete-key`   | Удалить ключ с токена                                        |
| `test`         | Тест функциональности токена                                 |

**Пример: список токенов**

```bash
securevault token list
```

**Пример: генерация ключа**

```bash
securevault token genkey work-encryption --bits 4096
```

### config

Управление конфигурацией.

```bash
securevault config <subcommand> [options]
```

#### Подкоманды

| Подкоманда    | Описание                                                    |
|---------------|-------------------------------------------------------------|
| `get`         | Получить значение параметра                                  |
| `set`         | Установить значение параметра                                |
| `show`        | Показать текущую конфигурацию (маскирует секреты)           |
| `validate`    | Проверить конфигурацию на корректность                       |
| `export`      | Экспортировать конфигурацию (без секретов)                   |
| `import`      | Импортировать конфигурацию                                   |

**Пример:**

```bash
securevault config set cloud.provider ipfs
securevault config show
```

### sync

Синхронизация.

```bash
securevault sync <subcommand> [options]
```

#### Подкоманды

| Подкомандa | Описание                                                    |
|------------|-------------------------------------------------------------|
| `cloud`    | Синхронизация с облачным хранилищем                          |
| `mesh`     | P2P mesh-синхронизация                                       |
| `status`   | Статус синхронизации                                         |

**Пример: облачная синхронизация**

```bash
securevault sync cloud work.ctn.enc --provider gdrive --direction push
```

**Пример: mesh**

```bash
securevault sync mesh work.ctn.enc --peer 192.168.1.50:9000
```

### audit

Аудит и логи.

```bash
securevault audit <subcommand> [options]
```

#### Подкоманды

| Подкоманда  | Описание                                                    |
|-------------|-------------------------------------------------------------|
| `logs`      | Просмотр форензик-логов                                      |
| `verify`    | Проверить подписи логов (ECDSA)                              |
| `export`    | Экспорт логов для суда                                       |

**Пример:**

```bash
securevault audit logs --from 2026-08-01 --to 2026-08-02
```

### recovery

Восстановление доступа при потере токена (Shamir Secret Sharing).

```bash
securevault recovery <subcommand> [options]
```

#### Подкоманды

| Подкоманда     | Описание                                                    |
|----------------|-------------------------------------------------------------|
| `split`        | Разделить секрет на доли (например, 3-of-5)                 |
| `reconstruct`  | Восстановить секрет из долей                                |
| `shares`       | Список и статус долей                                        |

**Пример: разделение секрета**

```bash
securevault recovery split --total 5 --threshold 3
```

**Пример: восстановление**

```bash
securevault recovery reconstruct --shares share1.seal share2.seal share3.seal
```

---

## Коды возврата

| Код | Описание                                          |
|-----|---------------------------------------------------|
| 0   | Успех                                              |
| 1   | Общая ошибка                                       |
| 2   | Неверное использование команды                     |
| 3   | Аппаратный токен не найден                         |
| 4   | Ошибка аутентификации (PIN)                        |
| 5   | Токен заблокирован                                 |
| 6   | Ошибка криптографической операции                  |
| 7   | Ошибка контейнера (повреждение, недоступность)     |
| 8   | Нарушение политики безопасности                    |

---

## Примеры

### Полный сценарий

```bash
# 1. Инициализация
securevault init --token

# 2. Шифрование файла
securevault encrypt secret.pdf --level INDIVIDUAL --pqc

# 3. Создание контейнера
securevault container create work.ctn.enc --size 10G --level CONTAINER

# 4. Монтирование
securevault container mount work.ctn.enc --drive E:

# 5. Синхронизация
securevault sync cloud work.ctn.enc --provider mega --direction push
```

### Неинтерактивный PIN

```bash
# Внимание: PIN в аргументах виден в списке процессов.
# Используйте только в изолированных средах (CI/автоматизация).
securevault token list --pin "$SECUREVAULT_PIN"
```

---

Смежные разделы:

- [REST API](rest_api.md)
- [Native API](native_api.md)
- [gRPC API](grpc_api.md)
- [Руководство пользователя](../user/user_manual.md)
- [Быстрый старт](../user/quick_start.md)