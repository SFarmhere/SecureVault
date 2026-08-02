# SecureVault REST API Reference

Версия API: **v1** · Формат данных: **JSON** · Кодировка: **UTF-8**

Базовый URL: `https://<host>:8443/api/v1`

---

## Оглавление

- Общие сведения
- Аутентификация
- Ошибки
- Эндпоинты
  - Аутентификация
  - Ключи и токены
  - Шифрование
  - Контейнеры
  - Синхронизация
  - Аудит
- Скорость и лимиты
- Примеры

---

## Общие сведения

REST API предоставляет программный доступ к функциям SecureVault: шифрованию файлов,
управлению контейнерами, аппаратными токенами, синхронизацией и аудитом.

Все запросы, изменяющие состояние, должны использовать корректный HTTP-метод
(`POST`, `PUT`, `DELETE`). Идемпотентные операции — `GET`.

### Заголовки

| Заголовок            | Обязательный | Описание                          |
|----------------------|--------------|-----------------------------------|
| `Authorization`      | Да           | `Bearer <JWT>`                    |
| `Content-Type`       | Да           | `application/json`                |
| `X-Request-ID`       | Нет          | Идентификатор запроса для трассировки |
| `X-Client-Version`   | Нет          | Версия клиента (например, `2.0.0`) |

### Версионирование

Версия указывается в пути: `/api/v1/...`. Изменения, нарушающие обратную
совместимость, выпускаются только в новой мажорной версии.

---

## Аутентификация

Аутентификация выполняется через JWT Bearer-токен.

### POST /auth/token

Создание сессионного токена.

**Тело запроса:**

```json
{
  "username": "alice",
  "password": "secret",
  "token_serial": "AA-1234567890",
  "pin": "12345678"
}
```

| Поле          | Тип    | Обязательное | Описание                          |
|---------------|--------|--------------|-----------------------------------|
| `username`    | string | Да           | Имя пользователя                 |
| `password`    | string | Да           | Пароль                            |
| `token_serial`| string | Да           | Серийный номер аппаратного токена |
| `pin`         | string | Да           | PIN токена                        |

**Ответ `200`:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "user": {
    "id": "u_1a2b3c4d",
    "username": "alice",
    "roles": ["admin", "crypto_operator"]
  }
}
```

**Ошибки:**

| Код | Описание                          |
|-----|-----------------------------------|
| 401 | Неверные учетные данные или PIN   |
| 403 | Токен заблокирован                |
| 423 | Токен временно заблокирован (попыток > 5) |

### POST /auth/refresh

Обновление истёкшего токена.

**Тело запроса:**

```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIs..."
}
```

**Ответ `200`:** новые `access_token` и `refresh_token`.

### POST /auth/revoke

Отзыв текущего токена. Тело не требуется.

**Ответ `204`** без тела.

---

## Ошибки

Все ошибки возвращаются в едином формате:

```json
{
  "error": {
    "code": "TOKEN_LOCKED",
    "message": "Token is locked after 5 failed PIN attempts",
    "request_id": "3f2a1b4c-9d8e-4f5a-8b7c-6d5e4f3a2b1c",
    "details": {
      "retry_after_seconds": 300
    }
  }
}
```

### Коды ошибок

| HTTP | Код                  | Описание                                  |
|------|----------------------|-------------------------------------------|
| 400  | `VALIDATION_ERROR`   | Некорректное тело запроса                 |
| 401  | `UNAUTHORIZED`       | Отсутствует или невалидный токен          |
| 403  | `FORBIDDEN`          | Недостаточно прав                         |
| 404  | `NOT_FOUND`          | Ресурс не найден                          |
| 409  | `CONFLICT`           | Конфликт состояния (например, контейнер занят) |
| 422  | `CRYPTO_ERROR`       | Ошибка криптографической операции         |
| 423  | `TOKEN_LOCKED`       | Токен заблокирован                        |
| 429  | `RATE_LIMITED`       | Превышен лимит запросов                   |
| 500  | `INTERNAL`           | Внутренняя ошибка сервера                 |

---

## Эндпоинты

### Ключи и токены

#### GET /tokens

Список доступных аппаратных токенов.

**Ответ `200`:**

```json
{
  "tokens": [
    {
      "serial": "AA-1234567890",
      "manufacturer": "Aktiv Co.",
      "model": "Rutoken S",
      "status": "connected",
      "algorithms": ["RSA-2048", "RSA-4096", "AES-256"],
      "certificates": ["CN=Alice, O=SecureCorp"]
    }
  ]
}
```

#### POST /tokens/{serial}/generate-key

Генерация асимметричной ключевой пары на токене (ключ не покидает аппаратное устройство).

| Параметр | Тип    | Обязательный | Описание              |
|----------|--------|--------------|-----------------------|
| `type`   | string | Да           | `"RSA"`               |
| `bits`   | int    | Нет          | 2048 (по умолчанию) / 4096 |
| `label`  | string | Да           | Метка ключа           |
| `pin`    | string | Да           | PIN токена            |

**Ответ `201`:**

```json
{
  "key_id": "k_9f8e7d6c",
  "label": "work-encryption",
  "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
  "on_token": true
}
```

#### DELETE /tokens/{serial}/keys/{key_id}

Удаление ключа с токена. Требует `pin` в теле запроса.

**Ответ `204`.**

---

### Шифрование

#### POST /encrypt

Шифрование файла.

**Тело запроса (multipart/form-data):**

| Поле            | Тип      | Обязательное | Описание                          |
|-----------------|----------|--------------|-----------------------------------|
| `file`          | file     | Да           | Файл для шифрования               |
| `level`         | string   | Да           | `ORIGINAL`, `INDIVIDUAL`, `CONTAINER`, `HYPER` |
| `container_id`  | string   | Нет          | ID контейнера (для CONTAINER/HYPER) |
| `key_id`        | string   | Нет          | ID ключа на токене                |
| `algorithm`     | string   | Нет          | `AES-256-GCM` (по умолчанию)      |
| `post_quantum`  | boolean  | Нет          | Включить Kyber1024 (`true`/`false`) |

**Ответ `201`:**

```json
{
  "job_id": "j_5a4b3c2d",
  "status": "queued",
  "output_name": "secret.pdf.enc",
  "cipher": "AES-256-GCM",
  "checksum_sha256": "9f86d081884c7d659a2feaa0c55ad015..."
}
```

Шифрование выполняется асинхронно. Статус отслеживается через `GET /jobs/{job_id}`.

#### GET /jobs/{job_id}

Статус фоновой операции.

**Ответ `200`:**

```json
{
  "job_id": "j_5a4b3c2d",
  "status": "completed",
  "progress": 1.0,
  "result": {
    "output_id": "f_a1b2c3d4",
    "output_name": "secret.pdf.enc",
    "size_bytes": 241664
  }
}
```

#### POST /decrypt

Расшифровка файла. Аналог `/encrypt`, поля: `file`, `level`, `key_id`, `pin`.

---

### Контейнеры

#### POST /containers

Создание виртуального контейнера.

| Поле          | Тип    | Обязательное | Описание                          |
|---------------|--------|--------------|-----------------------------------|
| `name`        | string | Да           | Имя контейнера                    |
| `size`        | string | Да           | Размер, например `"10G"`, `"500M"` |
| `level`       | string | Да           | `CONTAINER` или `HYPER`           |
| `key_id`      | string | Да           | Ключ на токене                    |
| `passphrase`  | string | Нет          | Дополнительная парольная фраза    |
| `hidden`      | boolean| Нет          | Плаusible deniability (скрытый)   |

**Ответ `201`:**

```json
{
  "container_id": "c_b2a1c0d9",
  "name": "work.ctn.enc",
  "size_bytes": 10737418240,
  "mounted": false,
  "format": "v2"
}
```

#### GET /containers

Список контейнеров.

**Ответ `200`:**

```json
{
  "containers": [
    {
      "container_id": "c_b2a1c0d9",
      "name": "work.ctn.enc",
      "size_bytes": 10737418240,
      "level": "CONTAINER",
      "mounted": false,
      "deduplication": true,
      "wal_enabled": true
    }
  ]
}
```

#### POST /containers/{container_id}/mount

Монтирование контейнера как виртуального диска.

| Поле   | Тип    | Обязательный | Описание   |
|--------|--------|--------------|------------|
| `pin`  | string | Да           | PIN токена |
| `path` | string | Нет          | Точка монтирования (для Linux/macOS) |

**Ответ `200`:**

```json
{
  "container_id": "c_b2a1c0d9",
  "mounted": true,
  "drive_letter": "E:",
  "mount_path": "E:/"
}
```

#### POST /containers/{container_id}/unmount

Размонтирование контейнера. Тело не требуется.

**Ответ `204`.**

#### DELETE /containers/{container_id}

Удаление контейнера. Требует `shred` (boolean) для криптографического затирания.

---

### Синхронизация

#### POST /sync/cloud

Запуск синхронизации с облачным хранилищем.

| Поле        | Тип    | Обязательный | Описание                          |
|-------------|--------|--------------|-----------------------------------|
| `provider`  | string | Да           | `gdrive`, `dropbox`, `mega`, `yandex`, `ipfs` |
| `container_id` | string | Да       | ID контейнера                     |
| `direction` | string | Да           | `push`, `pull`, `both`            |

**Ответ `202`:**

```json
{
  "sync_id": "s_c9d8e7f6",
  "provider": "gdrive",
  "status": "in_progress"
}
```

#### POST /sync/mesh

Запуск P2P mesh-синхронизации с пирами.

| Поле         | Тип    | Обязательный | Описание                          |
|--------------|--------|--------------|-----------------------------------|
| `container_id` | string | Да        | ID контейнера                     |
| `peers`      | array  | Нет          | Список peer-адресов               |

---

### Аудит

#### GET /audit/logs

Получение форензик-логов (требует роль `auditor`).

| Параметр запроса | Тип    | Описание                          |
|------------------|--------|-----------------------------------|
| `from`           | string | Начало периода (ISO-8601)         |
| `to`             | string | Конец периода (ISO-8601)          |
| `event_type`     | string | Фильтр по типу события            |
| `page`           | int    | Номер страницы (по умолчанию 1)   |
| `per_page`       | int    | Размер страницы (по умолчанию 50) |

**Ответ `200`:**

```json
{
  "logs": [
    {
      "id": "7f3e9c2a",
      "timestamp": "2026-08-02T08:15:30Z",
      "event_type": "container.mount",
      "actor": "alice",
      "container_id": "c_b2a1c0d9",
      "signature": "MEUCIQDGXKY...",
      "verified": true
    }
  ],
  "page": 1,
  "total": 342
}
```

---

## Скорость и лимиты

| Параметр            | Значение            |
|---------------------|---------------------|
| Скорость (по умолчанию) | 100 запросов/минуту |
| Скорость для аудита | 20 запросов/минуту  |
| Максимальный размер файла | 50 ГБ         |
| Максимальный размер контейнера | 2 ТБ     |

При превышении лимита возвращается `429`. Заголовок `Retry-After` указывает время ожидания в секундах.

---

## Примеры

### cURL: шифрование файла

```bash
curl -X POST https://localhost:8443/api/v1/encrypt \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@secret.pdf" \
  -F "level=INDIVIDUAL" \
  -F "key_id=k_9f8e7d6c"
```

### Python: получение токена

```python
import requests

resp = requests.post(
    "https://localhost:8443/api/v1/auth/token",
    json={
        "username": "alice",
        "password": "secret",
        "token_serial": "AA-1234567890",
        "pin": "12345678",
    },
    verify=False,  # В продакшене используйте CA
)
token = resp.json()["access_token"]

enc_resp = requests.post(
    "https://localhost:8443/api/v1/encrypt",
    headers={"Authorization": f"Bearer {token}"},
    files={"file": open("secret.pdf", "rb")},
    data={"level": "CONTAINER", "container_id": "c_b2a1c0d9"},
)
print(enc_resp.json())
```

---

Смежные разделы:

- [CLI API](cli_api.md)
- [Native API](native_api.md)
- [gRPC API](grpc_api.md)
- [Архитектура системы](../architecture/system_overview.md)