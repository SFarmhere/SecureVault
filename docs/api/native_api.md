# SecureVault Native API Reference

Язык: **C++17** · Заголовки: **C API / pybind11 bindings** · Версия: **2.0**

---

## Оглавление

- Общие сведения
- Модули нативного ядра
- C API
  - Инициализация
  - Криптография
  - Контейнеры
  - Безопасный ввод
  - Безопасное затирание
- pybind11 bindings
- Сборка и линковка
- Обработка ошибок
- Примеры

---

## Общие сведения

Native API — это ядро SecureVault на C++17, предоставляющее низкоуровневые
криптографические примитивы, управление контейнерами, аппаратными токенами
и безопасные операции ввода-вывода. API обёрнуто в C ABI для стабильности
и доступно из Python через pybind11 bindings.

Требования: C++17, OpenSSL 3.1+, CMake 3.20+.

---

## Модули нативного ядра

| Модуль          | Заголовок                 | Описание                                              |
|-----------------|---------------------------|-------------------------------------------------------|
| Crypto          | `crypto_module/include/crypto_api.h` | AES-256-GCM, RSA, Kyber1024, ChaCha20-Poly1305 |
| Container       | `container_module/include/container_api.h` | Контейнеры v1/v2, дедупликация, WAL, скрытые контейнеры |
| PKCS#11         | `pkcs11_module/include/`  | Рутокен, eToken, смарт-карты, FIDO2                   |
| Secure IO       | `secure_io_module/include/` | Криптографическое затирание (Гутманн, DoD), SecureAllocator |
| Security        | `security_module/`        | Anti-debug, Integrity, DMA, TPM, Secure Input          |

---

## C API

### Инициализация

#### `sv_init`

```c
int sv_init(const char* config_path, uint32_t flags);
```

Инициализирует ядро SecureVault. Должен быть вызван один раз перед
использованием остальных функций.

| Параметр      | Описание                                                |
|---------------|---------------------------------------------------------|
| `config_path` | Путь к конфигурационному файлу (может быть `NULL`)      |
| `flags`       | Битовая маска: `SV_FLAG_ENABLE_FUZZING`, `SV_FLAG_FIPS` |

**Возврат:** `0` при успехе, иначе код ошибки.

#### `sv_shutdown`

```c
void sv_shutdown(void);
```

Корректно завершает работу ядра, затирая все секретные данные в памяти.

#### `sv_version`

```c
const char* sv_version(void);
```

Возвращает строку версии ядра (например, `"2.0.0"`).

---

### Криптография

#### `sv_encrypt_file`

```c
int sv_encrypt_file(
    const char* input_path,
    const char* output_path,
    const char* key_id,
    const char* pin,
    uint32_t level,
    int post_quantum
);
```

Шифрует файл.

| Параметр       | Описание                                                    |
|----------------|-------------------------------------------------------------|
| `input_path`   | Путь входного файла                                          |
| `output_path`  | Путь выходного файла                                         |
| `key_id`       | ID ключа на токене                                          |
| `pin`          | PIN токена                                                   |
| `level`        | `SV_LEVEL_ORIGINAL`, `SV_LEVEL_INDIVIDUAL`, `SV_LEVEL_CONTAINER`, `SV_LEVEL_HYPER` |
| `post_quantum` | `1` — включить Kyber1024, `0` — выключить                    |

**Возврат:** `0` при успехе, иначе код ошибки.

#### `sv_decrypt_file`

```c
int sv_decrypt_file(
    const char* input_path,
    const char* output_path,
    const char* key_id,
    const char* pin,
    uint32_t level
);
```

Расшифровывает файл. Параметры аналогичны `sv_encrypt_file`.

#### `sv_generate_key`

```c
int sv_generate_key(
    const char* token_serial,
    const char* label,
    uint32_t bits,
    const char* pin,
    char* public_key_pem,
    size_t* pem_size
);
```

Генерирует ключевую пару RSA на аппаратном токене. Приватный ключ не покидает
токен; публичный ключ возвращается в PEM-формате.

---

### Контейнеры

#### `sv_container_create`

```c
int sv_container_create(
    const char* path,
    uint64_t size_bytes,
    uint32_t level,
    const char* key_id,
    const char* pin,
    char* container_id,
    size_t* id_size
);
```

Создаёт виртуальный зашифрованный контейнер.

| Параметр       | Описание                                                    |
|----------------|-------------------------------------------------------------|
| `path`         | Путь к файлу контейнера                                     |
| `size_bytes`   | Размер контейнера в байтах                                   |
| `level`        | `SV_LEVEL_CONTAINER` или `SV_LEVEL_HYPER`                    |
| `key_id`       | ID ключа на токене                                          |
| `pin`          | PIN токена                                                   |
| `container_id` | Буфер для возвращаемого ID контейнера                       |
| `id_size`      | Вход/выход — размер буфера                                  |

#### `sv_container_mount`

```c
int sv_container_mount(
    const char* container_id,
    const char* pin,
    char* mount_path,
    size_t* path_size
);
```

Монтирует контейнер как виртуальный диск.

#### `sv_container_unmount`

```c
int sv_container_unmount(const char* container_id);
```

Размонтирует контейнер.

#### `sv_container_repair`

```c
int sv_container_repair(const char* container_id);
```

Восстанавливает контейнер после сбоя, используя Write-Ahead Log (WAL).

---

### Безопасный ввод

#### `sv_secure_pin_entry`

```c
int sv_secure_pin_entry(
    char* pin_buffer,
    size_t buffer_size,
    uint32_t flags
);
```

Защищённый ввод PIN с scramble-pad клавиатурой. Ввод защищён от
клавиатурных шпионов и перехвата. Входные символы маскируются.

| Параметр     | Описание                                              |
|--------------|-------------------------------------------------------|
| `pin_buffer` | Буфер для PIN                                       |
| `buffer_size`| Размер буфера                                        |
| `flags`      | `SV_INPUT_MASKED`, `SV_INPUT_CONFIRM`               |

**Возврат:** `0` при успехе, `SV_ERR_CANCELLED` при отмене.

---

### Безопасное затирание

#### `sv_secure_wipe`

```c
int sv_secure_wipe(
    const char* path,
    uint32_t passes,
    uint32_t method
);
```

Криптографически затирает файл.

| Параметр  | Описание                                                    |
|-----------|-------------------------------------------------------------|
| `path`    | Путь к файлу                                                 |
| `passes`  | Количество проходов (по умолчанию рекомендуется 3)           |
| `method`  | `SV_WIPE_GUTMANN`, `SV_WIPE_DOD_5220`, `SV_WIPE_FAST`        |

#### `sv_zeroize_memory`

```c
void sv_zeroize_memory(void* ptr, size_t len);
```

Безопасно затирает блок памяти (устойчив к оптимизации компилятора).

#### `sv_secure_allocator`

```c
void* sv_secure_alloc(size_t size);
void sv_secure_free(void* ptr);
```

Выделяют память, защищённую от выгрузки в swap (mlock) и от cold-boot атак.

---

### Управление токенами

#### `sv_token_list`

```c
int sv_token_list(char** out_json, size_t* out_size);
```

Возвращает JSON-список подключенных аппаратных токенов.

```json
[
  {
    "serial": "AA-1234567890",
    "manufacturer": "Aktiv Co.",
    "model": "Rutoken S",
    "algorithms": ["RSA-2048", "RSA-4096", "AES-256"]
  }
]
```

#### `sv_token_test`

```c
int sv_token_test(const char* token_serial, const char* pin);
```

Проверяет функциональность токена (self-test).

---

## Обработка ошибок

Все функции возвращают `uint32_t` код. Общий формат:

| Код | Макрос                          | Описание                            |
|-----|---------------------------------|-------------------------------------|
| 0   | `SV_OK`                         | Успех                               |
| 1   | `SV_ERR_GENERIC`                | Общая ошибка                        |
| 2   | `SV_ERR_INVALID_ARGUMENT`        | Некорректный аргумент               |
| 3   | `SV_ERR_TOKEN_NOT_FOUND`         | Токен не найден                     |
| 4   | `SV_ERR_PIN_INCORRECT`           | Неверный PIN                        |
| 5   | `SV_ERR_TOKEN_LOCKED`            | Токен заблокирован                  |
| 6   | `SV_ERR_CRYPTO`                  | Криптографическая ошибка            |
| 7   | `SV_ERR_CONTAINER_CORRUPTED`     | Контейнер повреждён                 |
| 8   | `SV_ERR_INTEGRITY_CHECK_FAILED`  | Проверка целостности не пройдена    |
| 9   | `SV_ERR_DEBUGGER_DETECTED`       | Обнаружен отладчик                  |
| 10  | `SV_ERR_SIDE_CHANNEL_RISK`       | Обнаружен риск side-channel атаки   |
| 11  | `SV_ERR_CANCELLED`               | Операция отменена пользователем     |

---

## pybind11 bindings

Нативный API доступен из Python. Заголовок: `native/shared/pybind11_bindings`.

```python
import securevault_native as sv

# Инициализация
sv.init("/etc/securevault/config.yaml", 0)

# Шифрование
rc = sv.encrypt_file(
    "secret.pdf",
    "secret.pdf.enc",
    key_id="k_9f8e7d6c",
    pin=os.environ["PIN"],
    level=sv.Level.INDIVIDUAL,
    post_quantum=True,
)
if rc != 0:
    raise RuntimeError(f"Encryption failed: {rc}")

# Управление контейнером
cid = sv.container_create("work.ctn.enc", 10 * 1024**3, sv.Level.CONTAINER, "k_9f8e7d6c", pin)
sv.container_mount(cid, pin)

sv.shutdown()
```

---

## Сборка и линковка

### CMake

```cmake
find_package(SecureVault REQUIRED)
target_link_libraries(my_app PRIVATE SecureVault::crypto SecureVault::container)
```

### pkg-config

```bash
pkg-config --cflags --libs securevault
```

Результат: `-I/usr/include/securevault -lsecurevault_crypto -lsecurevault_container`

---

## Примеры

### C: инициализация и версия

```c
#include <securevault/crypto_api.h>
#include <stdio.h>

int main(void) {
    if (sv_init("/etc/securevault/config.yaml", 0) != 0) {
        fprintf(stderr, "Init failed\n");
        return 1;
    }
    printf("SecureVault v%s\n", sv_version());
    sv_shutdown();
    return 0;
}
```

### C: шифрование с контейнером

```c
#include <securevault/container_api.h>
#include <securevault/crypto_api.h>

int main(void) {
    sv_init(NULL, 0);

    char cid[64];
    size_t cid_size = sizeof(cid);
    sv_container_create("work.ctn.enc", 10ULL * 1024 * 1024 * 1024,
                        SV_LEVEL_CONTAINER, "k_9f8e7d6c", "12345678", cid, &cid_size);

    sv_encrypt_file("secret.pdf", "secret.pdf.enc", "k_9f8e7d6c", "12345678",
                    SV_LEVEL_CONTAINER, 1);

    sv_shutdown();
    return 0;
}
```

---

Смежные разделы:

- [REST API](rest_api.md)
- [CLI API](cli_api.md)
- [gRPC API](grpc_api.md)
- [Архитектура ядра](../architecture/system_overview.md)
- [Сборка из исходников](../developer/building.md)