# SecureVault gRPC API Reference

Протокол: **gRPC** · Сериализация: **Protocol Buffers (proto3)** · Версия: **v1**

---

## Оглавление

- Общие сведения
- Определение сервисов
  - VaultService
  - TokenService
  - ContainerService
  - SyncService
  - AuditService
- Аутентификация и TLS
- Коды ошибок
- Примеры
  - Go
  - Python

---

## Общие сведения

gRPC API предоставляет высокопроизводительный бинарный доступ к SecureVault.
Используется для серверных интеграций, где важна пропускная способность
и низкая задержка (в отличие от REST).

Целевой порт: `50051` (TLS).

Пакет: `securevault.v1`

### Потоковые операции

| Тип            | Описание                                              |
|----------------|-------------------------------------------------------|
| Unary          | Запрос-ответ, например, создание ключа                |
| Server-streaming | Сервер отправляет несколько ответов (прогресс шифрования) |
| Client-streaming | Клиент отправляет несколько запросов (загрузка файла)  |
| Bidirectional  | Двунаправленный поток                                  |

---

## Определение сервисов

### VaultService

#### `EncryptFile`

```
rpc EncryptFile(stream FileChunk) returns (stream EncryptProgress);
```

Шифрование файла. Клиент отправляет файл частями, сервер возвращает прогресс.

**FileChunk:**

```proto
message FileChunk {
  string file_name = 1;
  uint32 level = 2;          // 0=ORIGINAL, 1=INDIVIDUAL, 2=CONTAINER, 3=HYPER
  string key_id = 3;
  string container_id = 4;
  bool post_quantum = 5;
  bytes data = 6;
  uint64 offset = 7;
  bool is_last = 8;
}
```

**EncryptProgress:**

```proto
message EncryptProgress {
  double progress = 1;       // 0.0 - 1.0
  string job_id = 2;
  EncryptStatus status = 3;  // QUEUED, IN_PROGRESS, COMPLETED, FAILED
  string output_name = 4;
  string checksum_sha256 = 5;
}
```

#### `DecryptFile`

```
rpc DecryptFile(stream FileChunk) returns (stream DecryptProgress);
```

Обратная операция для расшифровки.

#### `GetJobStatus`

```
rpc GetJobStatus(JobRequest) returns (JobStatus);
```

**JobRequest:**

```proto
message JobRequest {
  string job_id = 1;
}
```

**JobStatus:**

```proto
message JobStatus {
  string job_id = 1;
  EncryptStatus status = 2;
  double progress = 3;
  string error_message = 4;
  map<string, string> result = 5;
}
```

---

### TokenService

#### `ListTokens`

```
rpc ListTokens(Empty) returns (TokenList);
```

**TokenList:**

```proto
message TokenList {
  repeated TokenInfo tokens = 1;
}

message TokenInfo {
  string serial = 1;
  string manufacturer = 2;
  string model = 3;
  TokenStatus status = 4;
  repeated string algorithms = 5;
}
```

#### `GenerateKey`

```
rpc GenerateKey(GenerateKeyRequest) returns (KeyInfo);
```

**GenerateKeyRequest:**

```proto
message GenerateKeyRequest {
  string token_serial = 1;
  string label = 2;
  uint32 bits = 3;           // 2048 (default) or 4096
  string pin = 4;
}
```

**KeyInfo:**

```proto
message KeyInfo {
  string key_id = 1;
  string label = 2;
  string public_key_pem = 3;
  bool on_token = 4;
}
```

#### `DeleteKey`

```
rpc DeleteKey(DeleteKeyRequest) returns (Empty);
```

**DeleteKeyRequest:**

```proto
message DeleteKeyRequest {
  string token_serial = 1;
  string key_id = 2;
  string pin = 3;
}
```

---

### ContainerService

#### `CreateContainer`

```
rpc CreateContainer(CreateContainerRequest) returns (ContainerInfo);
```

**CreateContainerRequest:**

```proto
message CreateContainerRequest {
  string name = 1;
  uint64 size_bytes = 2;
  uint32 level = 3;          // 2=CONTAINER, 3=HYPER
  string key_id = 4;
  string pin = 5;
  bool hidden = 6;           // plausible deniability
}
```

**ContainerInfo:**

```proto
message ContainerInfo {
  string container_id = 1;
  string name = 2;
  uint64 size_bytes = 3;
  uint32 level = 4;
  bool mounted = 5;
  string format = 6;         // "v1" or "v2"
}
```

#### `MountContainer`

```
rpc MountContainer(MountRequest) returns (MountResponse);
```

**MountRequest:**

```proto
message MountRequest {
  string container_id = 1;
  string pin = 2;
  string mount_path = 3;     // optional
}
```

**MountResponse:**

```proto
message MountResponse {
  string container_id = 1;
  string mount_path = 2;
  string drive_letter = 3;
}
```

#### `UnmountContainer`

```
rpc UnmountContainer(ContainerRef) returns (Empty);
```

**ContainerRef:**

```proto
message ContainerRef {
  string container_id = 1;
}
```

#### `RepairContainer`

```
rpc RepairContainer(ContainerRef) returns (RepairResponse);
```

**RepairResponse:**

```proto
message RepairResponse {
  string container_id = 1;
  bool recovered = 2;
  uint64 recovered_blocks = 3;
  string wal_state = 4;
}
```

---

### SyncService

#### `SyncCloud`

```
rpc SyncCloud(SyncCloudRequest) returns (SyncInfo);
```

**SyncCloudRequest:**

```proto
message SyncCloudRequest {
  string container_id = 1;
  string provider = 2;       // gdrive, dropbox, mega, yandex, ipfs
  SyncDirection direction = 3;  // PUSH, PULL, BOTH
}
```

#### `SyncMesh`

```
rpc SyncMesh(stream SyncPeer) returns (stream SyncEvent);
```

Двунаправленный поток для P2P mesh-синхронизации.

---

### AuditService

#### `GetLogs`

```
rpc GetLogs(LogQuery) returns (LogList);
```

**LogQuery:**

```proto
message LogQuery {
  string from_iso = 1;
  string to_iso = 2;
  string event_type = 3;
  uint32 page = 4;
  uint32 per_page = 5;
}
```

**LogList:**

```proto
message LogList {
  repeated AuditLogEntry logs = 1;
  uint32 page = 2;
  uint64 total = 3;
}

message AuditLogEntry {
  string id = 1;
  string timestamp = 2;      // RFC 3339
  string event_type = 3;
  string actor = 4;
  string container_id = 5;
  bytes signature = 6;       // ECDSA
  bool signature_valid = 7;
}
```

#### `VerifyLogSignature`

```
rpc VerifyLogSignature(LogRef) returns (VerificationResult);
```

**LogRef:**

```proto
message LogRef {
  string log_id = 1;
}
```

**VerificationResult:**

```proto
message VerificationResult {
  string log_id = 1;
  bool valid = 2;
  string message = 3;
}
```

---

## Аутентификация и TLS

gRPC API требует взаимную TLS (mTLS) аутентификацию.

| Параметр             | Значение                          |
|----------------------|-----------------------------------|
| Протокол             | TLS 1.3                           |
| Сертификат клиента   | Обязательный (mTLS)               |
| Передача ключей      | Только на стороне сервера         |
| Аутентификация поверх | JWT Bearer в `authorization` metadata |

### Metadata

```proto
metadata:
  authorization: "Bearer <jwt>"
  x-request-id: "3f2a1b4c-..."
```

---

## Коды ошибок

| gRPC код        | Число | Описание                            |
|-----------------|-------|-------------------------------------|
| OK              | 0     | Успех                               |
| INVALID_ARGUMENT | 3     | Некорректный аргумент               |
| NOT_FOUND       | 5     | Ресурс не найден                    |
| PERMISSION_DENIED | 7   | Недостаточно прав                   |
| RESOURCE_EXHAUSTED | 8   | Превышен лимит (429 аналог)         |
| FAILED_PRECONDITION | 9  | Неверное состояние                  |
| ABORTED         | 10    | Конфликт (например, контейнер занят)|
| UNAUTHENTICATED | 16    | Отсутствует/невалидный токен        |
| UNAVAILABLE     | 14    | Сервис недоступен                   |

Ошибки также включают детали в status details (`google.rpc.Status`).

---

## Примеры

### Go

```go
package main

import (
    "context"
    "log"

    vault "github.com/SFarmhere/SecureVault/gen/securevault/v1"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
)

func main() {
    creds := credentials.NewTLS(&tls.Config{})
    conn, err := grpc.Dial("securevault.example.com:50051",
        grpc.WithTransportCredentials(creds))
    if err != nil {
        log.Fatal(err)
    }
    defer conn.Close()

    client := vault.NewTokenServiceClient(conn)
    tokens, err := client.ListTokens(context.Background(), &vault.Empty{})
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Tokens: %+v\n", tokens.Tokens)
}
```

### Python

```python
import grpc
import securevault_v1_pb2 as pb
import securevault_v1_pb2_grpc as stub

channel = grpc.secure_channel(
    "securevault.example.com:50051",
    grpc.ssl_channel_credentials(),
)
client = stub.ContainerServiceStub(channel)

response = client.CreateContainer(
    pb.CreateContainerRequest(
        name="work.ctn.enc",
        size_bytes=10 * 1024**3,
        level=2,  # CONTAINER
        key_id="k_9f8e7d6c",
    )
)
print(response.container_id)
```

---

Смежные разделы:

- [REST API](rest_api.md)
- [CLI API](cli_api.md)
- [Native API](native_api.md)
- [Архитектура системы](../architecture/system_overview.md)
- [Гайд для разработчиков](../developer/api_development.md)