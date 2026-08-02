# SecureVault

Многоуровневая система криптографической защиты файлов с аппаратной поддержкой ключей (HSM / USB Token)

![build](https://img.shields.io/badge/build-passing-brightgreen)
![security](https://img.shields.io/badge/security-hardened-blue)
![license](https://img.shields.io/badge/license-GNU%20GPL%20v3-blue)
![fuzzing](https://img.shields.io/badge/fuzzing-active-orange)
![pqc](https://img.shields.io/badge/pqc-kyber1024-purple)

---

## Оглавление

- О проекте
- Ключевые возможности
- Архитектура
- Уровни защиты
- Безопасность
- Быстрый старт
- Сборка
- Тестирование
- Документация
- Дорожная карта
- Лицензия

---

## О проекте

SecureVault -- это автономная, кроссплатформенная система шифрования с аппаратной защитой ключей на USB-токенах (Рутокен, eToken, JaCarta). Проект реализует адаптивную 4-уровневую модель безопасности, систему виртуальных зашифрованных контейнеров с дедупликацией, криптографическое затирание данных и мультиоблачную синхронизацию со сквозным шифрованием.

Уникальность: Приватный ключ никогда не покидает токен. Все операции с ключом выполняются на аппаратном уровне.

---

## Ключевые возможности

### Аппаратная криптография

- PKCS#11, полная поддержка Рутокен, eToken, смарт-карт
- Генерация RSA-2048/4096 на токене
- X.509 сертификаты (самоподписанные или PKI)
- Аппаратное ускорение AES (если поддерживается токеном)

### 4 уровня защиты данных

| Уровень | Описание | Шифрование | Контейнеры |
|---------|----------|------------|------------|
| ORIGINAL | Без шифрования (публичные данные) | Нет | Нет |
| INDIVIDUAL | Каждый файл зашифрован отдельно | AES-256 | Нет |
| CONTAINER | Контейнер с незашифрованными файлами | AES-256 + RSA | Да |
| HYPER | Контейнер с предварительно зашифрованными файлами | Double AES | Да (скрытые) |

### Безопасность корпоративного уровня

- Anti-debug/integrity -- обнаружение отладчиков, проверка целостности PE/ELF/Mach-O
- Anti-cold-boot -- шифрование ключей в RAM, запрет выгрузки в swap
- DMA protection -- защита от PCIe/Thunderbolt атак (IOMMU, Kernel DMA Guard)
- Side-channel resistance -- константное время, очистка кэша, Spectre mitigation
- TPM 2.0 -- измерение целостности PCR, распечатывание ключей
- Plausible deniability -- скрытые контейнеры (format_v2)

### Продвинутое управление контейнерами

- Дедупликация блоков на лету (CDC)
- WAL (Write-Ahead Log) -- восстановление после сбоев
- Автоматическая сборка мусора
- Монтирование как виртуальные диски

### Облако и синхронизация

- Сквозное шифрование перед отправкой
- Google Drive, Dropbox, Mega, Yandex Disk
- IPFS/Filecoin -- децентрализованное хранение
- Mesh-синхронизация (P2P, WebRTC) -- без интернета

### Отказоустойчивость

- Shamir Secret Sharing (3-of-5) -- восстановление доступа при потере токена
- Оффлайн-аудит (SQLite) + репликация в PostgreSQL
- Криптографическая подпись логов (ECDSA)
- Forensic logs -- доказательная база для суда

---

## Архитектура

<table>
<tr>
<th>NATIVE (C++)</th>
<th>PYTHON (Core)</th>
<th>WEB (Vue 3)</th>
</tr>
<tr>
<td>
<ul>
<li>PKCS#11</li>
<li>Container</li>
<li>Crypto</li>
<li>Secure IO</li>
<li>Anti‑debug</li>
<li>TPM</li>
<li>Fuzzing</li>
</ul>
</td>
<td>
<ul>
<li>Encryption</li>
<li>Container</li>
<li>Cloud Sync</li>
<li>Policy Engine</li>
<li>Audit</li>
<li>Shamir Secret Sharing</li>
<li>P2P Sync</li>
</ul>
</td>
<td>
<ul>
<li>File Manager</li>
<li>Token Control</li>
<li>Settings</li>
<li>Real‑time Updates</li>
</ul>
</td>
</tr>
</table>

### Полная структура репозитория

```bash
SecureVault/
├── native/                    # Ядро системы (C++17)
│   ├── crypto_module/        #    AES, RSA, Kyber1024, ChaCha20
│   │   ├── include/cipher_suites/ # Пост-квантовая криптография
│   │   └── src/side_channel/      # Защита от timing/cache атак
│   ├── container_module/     #    Контейнеры v1/v2, дедупликация, WAL
│   ├── pkcs11_module/        #    Рутокен, eToken, смарт-карты
│   ├── secure_io_module/     #    Безопасное затирание (Гутманн, DoD)
│   │   └── src/memory_ops/   #    Anti-cold-boot, SecureAllocator
│   └── security_module/      #    Anti-debug, Integrity, DMA, TPM
│       ├── anti_debug/       #    ptrace, NtGlobalFlag, Task Exception
│       ├── dma_protection/   #    IOMMU, Thunderbolt, Kernel Lockdown
│       ├── integrity_checker/#    Проверка PE/ELF/Mach-O
│       ├── secure_input/     #    Защищенный ввод PIN (scramble pad)
│       └── tpm_measured/     #    PCR extend, sealed secrets
│
├── python/                   # Бэкенд и CLI (Python 3.11+)
│   ├── src/securevault/
│   │   ├── core/            #    Бизнес-логика
│   │   ├── security/        #    TPM measured boot, Shamir
│   │   ├── audit/           #    SQLite, forensic logger, blockchain
│   │   ├── sync/            #    Mesh-синхронизация (P2P)
│   │   └── cli/             #    Интерфейс командной строки
│   └── tests/               #    Unit, integration, performance
│
├── web/                      # Веб-интерфейс (Vue 3 + Vite)
│   ├── frontend/            #    SPA (Pinia, Vue Router)
│   └── backend/             #    FastAPI для веб-версии
│
├── deployment/               # Инфраструктура
│   ├── docker/              #    Dockerfile (app, db, web)
│   ├── kubernetes/          #    Манифесты для k8s
│   ├── ansible/             #    Плейбуки
│   ├── terraform/           #    IaC (AWS, GCP, Azure)
│   └── installer/           #    NSIS (Windows), deb/rpm, dmg
│
├── docs/                     # Документация
│   ├── architecture/        #    BIOS Security, TPM measured boot
│   └── api/                 #    REST, gRPC, CLI, Native
│
├── integration/              # Интеграционное тестирование
│   ├── blockchain_storage/  #    IPFS, Filecoin, ENS
│   └── test_data/           #    Короткие/большие/битые файлы
│
├── shared_resources/         # Сертификаты, конфиги, локали
│   └── certificates/        #    SecureBoot: PK, KEK
│
└── third_party/             # Зависимости (vendored)
    ├── openssl/             #    Статическая линковка
    └── pkcs11/              #    Нативные библиотеки
```

---

## Безопасность корпоративного уровня

### Защита от физических атак

| Атака | Метод защиты | Статус |
|-------|-------------|--------|
| Cold Boot | Anti-cold-boot: шифрование ключей в RAM, mlock | Готово |
| DMA (Thunderbolt/PCIe) | IOMMU, Kernel DMA Guard, ACPI check | Готово |
| Evil Maid | TPM PCR измерение, Secure Boot | Готово |
| Keylogger | Secure input: scramble pad, собственный Edit | Готово |

### Защита от программных атак

| Атака | Метод защиты | Статус |
|-------|-------------|--------|
| Debugger (gdb, x64dbg) | ptrace, NtGlobalFlag, TLS callback | Готово |
| DLL Injection | Проверка загруженных модулей | Готово |
| API Hooking | Проверка первых байтов функций | В работе |
| Spectre/Meltdown | LFENCE, CPUID, очистка кэша | Готово |
| Timing attacks | Константное время | Готово |

### Защита данных

| Риск | Решение | Статус |
|------|---------|--------|
| Потеря токена | Shamir Secret Sharing (3-of-5) | Готово |
| Принуждение к открытию | Plausible deniability (скрытые контейнеры) | Готово |
| Квантовый компьютер | Kyber1024 (post-quantum) | Готово |
| Повреждение контейнера | WAL + контрольные точки | Готово |

---

## Быстрый старт

### Windows

```powershell
# Установка через winget
winget install SecureVault

# Или скачать installer с релизов
.\SecureVault-2.0.0-win64.exe
```

### Linux

```bash
# Сборка из исходников (см. раздел "Сборка из исходников")
git clone https://github.com/SFarmhere/SecureVault.git
cd SecureVault
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release -j$(nproc)
```

### macOS

```bash
# Сборка из исходников (см. раздел "Сборка из исходников")
git clone https://github.com/SFarmhere/SecureVault.git
cd SecureVault
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build . --config Release -j$(nproc)
```

### Первый запуск

```bash
# 1. Вставьте токен
# 2. Запустите мастер инициализации
securevault init --token

# 3. Зашифруйте файл
securevault encrypt secret.pdf --level INDIVIDUAL

# 4. Создайте контейнер
securevault container create work.ctn.enc --size 10G
```

---

## Сборка из исходников

### Требования

- C++: GCC 11+ / Clang 14+ / MSVC 2022
- CMake: 3.20+
- Python: 3.11+
- Node.js: 18+ (только для web)
- OpenSSL: 3.1+ (vendored)

### Linux / macOS

```bash
git clone https://github.com/SFarmhere/SecureVault.git
cd SecureVault

# Сборка нативного ядра
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DSECUREVAULT_ENABLE_FUZZING=ON
cmake --build . --config Release -j$(nproc)

# Установка Python модуля
cd ../python
pip install -e .
```

### Windows

```powershell
git clone https://github.com/SFarmhere/SecureVault.git
cd SecureVault

# Visual Studio 2022 Developer PowerShell
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release

# Python
cd python
pip install -e .
```

---

## Тестирование

### Нативное ядро

```bash
cd build
ctest -C Release --output-on-failure

# Fuzzing
cmake --build . --target fuzz_container_header
./bin/fuzz_container_header -max_total_time=300
```

### Python

```bash
cd python
pytest tests/unit
pytest tests/integration
pytest tests/security/test_vulnerabilities.py

# Бенчмарки
pytest tests/performance/benchmark_encryption.py
```

### Безопасность

```bash
# Статический анализ
bandit -r src/securevault
cppcheck --enable=all native/

# Динамический анализ (Valgrind)
valgrind --leak-check=full ./build/bin/securevault-cli
```

---

## Документация

| Раздел | Ссылка |
|--------|--------|
| Пользовательская | user/quick_start.md |
| API Reference | api/rest_api.md |
| Архитектура | architecture/system_overview.md |
| Безопасность | SECURITY.md |
| BIOS/UEFI | architecture/uefi_secure_boot.md |
| TPM | architecture/tpm_measured_boot.md |

---

## Дорожная карта

### Реализовано (v2.0)

- Полная PKCS#11 поддержка (Рутокен, eToken)
- 4 уровня защиты + скрытые контейнеры
- Anti-debug / Integrity checker
- Anti-cold-boot / Secure allocator
- DMA protection (IOMMU, Thunderbolt)
- TPM measured boot + PCR sealing
- Post-quantum: Kyber1024
- Дедупликация контейнеров
- WAL + автоматическое восстановление
- Shamir Secret Sharing (recovery)
- Mesh-синхронизация (P2P)
- IPFS / Filecoin интеграция
- Forensic logger (подпись логов)

### В разработке (v2.1)

- FIDO2/WebAuthn поддержка
- YubiKey PIV модуль
- GPU-ускорение шифрования
- SEV-SNP / TDX доверенное исполнение
- Формальная верификация (Frama-C)

### План (v3.0)

- Сертификация ФСТЭК/ФСБ (ГОСТ)
- Hardware Security Module (HSM) облачная версия
- Zero-Knowledge Proofs для аудита

---

## Лицензия

GNU General Public License v3.0. Полный текст в LICENSE.

```
Copyright 2026 SecureVault Contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
```

### Зависимости

- OpenSSL -- Apache 2.0
- PCSC-Lite -- BSD
- Catch2 -- BSL-1.0
- pybind11 -- BSD

---

## Участие

Мы открыты к контрибуциям! См.:

- CONTRIBUTING.md
- CODE_OF_CONDUCT.md
- SECURITY.md

Важно: Все изменения в криптографии проходят аудит двумя мейнтейнерами.

---

## Поддержка

- Документация
- GitHub Issues
- Discord
- GitHub Issues (для отчетов об уязвимостях)

---

## Цифровой след проекта

```
Криптографических модулей:     14
Написано тестов:              ~450
Fuzzing CPU часов:            >5000
Подавлено уязвимостей:        12 (все закрыты)
Пост-квантовых ключей:        Kyber1024 готов
Поддерживаемых токенов:       7 (Рутокен, eToken, JaCarta и др.)
```

---

SecureVault -- защита, которой можно доверять.
