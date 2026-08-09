# ============================================================================
# SecureVault - Native Core Build System
# Версия: 2.0.0
# (c) 2026 SecureVault Contributors
# Лицензия: GNU GPL v3
#
# НАЗНАЧЕНИЕ:
#   Корневой CMake-файл для сборки всех нативных модулей SecureVault.
#   Объединяет 7 модулей в единую библиотеку libsecurevault_native:
#     - crypto_module:     AES, RSA, Kyber1024, ChaCha20, ГОСТ, ECC
#     - container_module:  Контейнеры v1/v2, дедупликация, WAL, сжатие
#     - pkcs11_module:     Рутокен, eToken, смарт-карты (PKCS#11)
#     - fido2_module:      FIDO2/WebAuthn, YubiKey PIV, Nitrokey
#     - secure_io_module:  Безопасное затирание, SecureAllocator, file_ops
#     - security_module:   Anti-debug, Integrity, DMA, TPM, Shamir, TDX/SEV
#     - shared:            Общие типы, конфигурация, логирование, платформа
#
# ВХОДНЫЕ ПАРАМЕТРЫ:
#   - SECUREVAULT_BUILD_SHARED:     ON/OFF (по умолчанию ON)
#   - SECUREVAULT_ENABLE_TESTING:   ON/OFF (по умолчанию OFF)
#   - SECUREVAULT_ENABLE_FUZZING:   ON/OFF (по умолчанию OFF)
#   - SECUREVAULT_ENABLE_PCSC:      ON/OFF (по умолчанию ON)
#   - SECUREVAULT_ENABLE_TPM:       ON/OFF (по умолчанию ON)
#   - SECUREVAULT_ENABLE_GPU:       ON/OFF (по умолчанию OFF)
#   - SECUREVAULT_ENABLE_GOST:      ON/OFF (по умолчанию ON)
#   - SECUREVAULT_INSTALL:          ON/OFF (по умолчанию ON)
#   - SECUREVAULT_USE_VENDORED_OPENSSL: ON/OFF (по умолчанию OFF)
#
# ВЫХОДНЫЕ ДАННЫЕ:
#   - libsecurevault_native.so/.dylib/.dll  - разделяемая библиотека
#   - libsecurevault_native_static.a/.lib   - статическая библиотека
#   - securevault_native-config.cmake       - конфигурация для find_package
#   - Цели для тестирования (если включено)
# ============================================================================

cmake_minimum_required(VERSION 3.20)
project(securevault_native
        VERSION 2.0.0
        DESCRIPTION "SecureVault Native Core - Multi-layer cryptographic protection system with HSM/USB Token support"
        LANGUAGES CXX C
)

# ============================================================================
# ОПЦИИ СБОРКИ
# ============================================================================

option(SECUREVAULT_BUILD_SHARED     "Build shared library" ON)
option(SECUREVAULT_ENABLE_TESTING   "Build tests" OFF)
option(SECUREVAULT_ENABLE_FUZZING   "Build fuzz targets" OFF)
option(SECUREVAULT_ENABLE_PCSC      "Enable PC/SC smart card support" ON)
option(SECUREVAULT_ENABLE_TPM       "Enable TPM 2.0 support" ON)
option(SECUREVAULT_ENABLE_GPU       "Enable GPU acceleration (CUDA/OpenCL/Vulkan)" OFF)
option(SECUREVAULT_ENABLE_GOST      "Enable GOST cryptography" ON)
option(SECUREVAULT_INSTALL          "Install library" ON)
option(SECUREVAULT_USE_VENDORED_OPENSSL "Use vendored OpenSSL" OFF)

# ============================================================================
# КОМПИЛЯТОР И ФЛАГИ
# ============================================================================

# Требуем C++17 минимум
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Экспорт всех символов на Windows
if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# Флаги компиляции в зависимости от платформы
if(MSVC)
    # MSVC (Visual Studio)
    add_compile_options(/W4 /WX)
    add_compile_options(/utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    add_definitions(-D_SCL_SECURE_NO_WARNINGS)
    add_definitions(-DNOMINMAX)
    add_definitions(-DWIN32_LEAN_AND_MEAN)

    # Release оптимизации
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /Oi /GL /Gw")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG")

    # Debug флаги
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /Od /RTC1")

    # Безопасность: /GUARD:CF (Control Flow Guard)
    add_link_options(/GUARD:CF)

    # Spectre mitigation
    add_compile_options(/Qspectre)

elseif(APPLE)
    # Apple Clang (macOS)
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    add_compile_options(-Wshadow -Wnon-virtual-dtor -Wold-style-cast)
    add_compile_options(-Wcast-align -Wunused -Woverloaded-virtual)
    add_compile_options(-Wconversion -Wsign-conversion)
    add_compile_options(-fstack-protector-strong)
    add_compile_options(-D_FORTIFY_SOURCE=2)

    # Release
    add_compile_options($<$<CONFIG:Release>:-O3 -DNDEBUG>)

    # Debug
    add_compile_options($<$<CONFIG:Debug>:-O0 -g -fsanitize=address -fno-omit-frame-pointer>)
    add_link_options($<$<CONFIG:Debug>:-fsanitize=address>)

    set(CMAKE_MACOSX_RPATH ON)

elseif(UNIX)
    # GCC/Clang (Linux)
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    add_compile_options(-Wshadow -Wnon-virtual-dtor -Wold-style-cast)
    add_compile_options(-Wcast-align -Wunused -Woverloaded-virtual)
    add_compile_options(-Wconversion -Wsign-conversion)
    add_compile_options(-fstack-protector-strong)
    add_compile_options(-D_FORTIFY_SOURCE=2)

    # Release
    add_compile_options($<$<CONFIG:Release>:-O3 -DNDEBUG>)

    # Debug
    add_compile_options($<$<CONFIG:Debug>:-O0 -g -fsanitize=address -fno-omit-frame-pointer>)
    add_link_options($<$<CONFIG:Debug>:-fsanitize=address>)

    # Position Independent Code для shared library
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

# ============================================================================
# ПЛАТФОРМО-ЗАВИСИМЫЕ МАКРОСЫ
# ============================================================================

if(WIN32)
    add_definitions(-DSECUREVAULT_PLATFORM_WINDOWS)
elseif(APPLE)
    add_definitions(-DSECUREVAULT_PLATFORM_MACOS)
elseif(UNIX)
    add_definitions(-DSECUREVAULT_PLATFORM_LINUX)
endif()

# ============================================================================
# ПОИСК ЗАВИСИМОСТЕЙ
# ============================================================================

# Threads (обязательно)
find_package(Threads REQUIRED)

# OpenSSL (обязательно)
if(SECUREVAULT_USE_VENDORED_OPENSSL)
    # Используем vendored OpenSSL из third_party/
    set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/../third_party/openssl")
    find_package(OpenSSL REQUIRED)
else()
    find_package(OpenSSL REQUIRED)
endif()

# PC/SC для смарт-карт (опционально)
if(SECUREVAULT_ENABLE_PCSC)
    if(WIN32)
        set(PCSC_LIBRARIES "winscard.lib")
        set(PCSC_FOUND ON)
        add_definitions(-DSECUREVAULT_ENABLE_PCSC)
    elseif(APPLE)
        find_library(PCSC_FRAMEWORK PCSC)
        if(PCSC_FRAMEWORK)
            set(PCSC_LIBRARIES ${PCSC_FRAMEWORK})
            # Framework headers (pcsclite.h, winscard.h, etc.) live in the
            # Headers subdirectory of the framework bundle.
            set(PCSC_INCLUDE_DIRS "${PCSC_FRAMEWORK}/Headers")
            set(PCSC_FOUND ON)
            add_definitions(-DSECUREVAULT_ENABLE_PCSC)
        endif()
    elseif(UNIX)
        find_package(PkgConfig QUIET)
        if(PkgConfig_FOUND)
            pkg_check_modules(PCSC QUIET libpcsclite)
            if(PCSC_FOUND)
                add_definitions(-DSECUREVAULT_ENABLE_PCSC)
            endif()
        endif()
    endif()

    if(NOT PCSC_FOUND)
        message(WARNING "PC/SC not found - smart card support will be disabled")
    endif()
endif()

# TPM 2.0 (опционально)
if(SECUREVAULT_ENABLE_TPM)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(TPM2 QUIET tss2-esys tss2-rc tss2-mu)
        if(TPM2_FOUND)
            add_definitions(-DSECUREVAULT_ENABLE_TPM)
        else()
            message(WARNING "TPM 2.0 TSS not found - TPM support will be disabled")
        endif()
    endif()
endif()

# ============================================================================
# ОБЩИЕ ЗАГОЛОВКИ (SHARED)
# ============================================================================

set(SECUREVAULT_SHARED_INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/include"
)

set(SECUREVAULT_SHARED_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/include/common_types.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/include/config.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/include/error_codes.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/include/logging.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/include/platform.h"
)

# ============================================================================
# ПОДКЛЮЧЕНИЕ МОДУЛЕЙ
# ============================================================================

# Каждый модуль добавляет свои исходники и заголовки в соответствующие списки.
# Модули могут зависеть друг от друга:
#   crypto_module <- container_module, pkcs11_module
#   shared <- все модули
#   secure_io_module <- container_module
#   security_module <- crypto_module, shared

# Список всех исходников нативной библиотеки
set(SECUREVAULT_NATIVE_SOURCES "")

# Список всех заголовков для установки
set(SECUREVAULT_NATIVE_PUBLIC_HEADERS "")

# Список include директорий модулей
set(SECUREVAULT_MODULE_INCLUDE_DIRS
    "${SECUREVAULT_SHARED_INCLUDE_DIR}"
)

# --------------------------------------------------------------------------
# Модуль: shared (общие типы, конфигурация, логирование)
# --------------------------------------------------------------------------
# Зависимости: нет
# Зависимые: все модули
# --------------------------------------------------------------------------

list(APPEND SECUREVAULT_MODULE_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/include"
)

list(APPEND SECUREVAULT_NATIVE_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/src/config.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/src/logging.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/shared/src/platform.cpp"
)

# --------------------------------------------------------------------------
# Модуль: crypto_module (AES, RSA, Kyber1024, ChaCha20, ECC, ГОСТ, KDF)
# --------------------------------------------------------------------------
# Зависимости: shared, OpenSSL
# Зависимые: container_module, pkcs11_module, security_module
# --------------------------------------------------------------------------

list(APPEND SECUREVAULT_MODULE_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/cipher_suites"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/gost"
)

list(APPEND SECUREVAULT_NATIVE_SOURCES
    # AES
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/aes/aes_core.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/aes/aes_key.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/aes/aes_modes.cpp"

    # RSA
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/rsa/rsa_core.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/rsa/rsa_key.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/rsa/rsa_sign.cpp"

    # ECC
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/ecc/ecc_p256.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/ecc/ecc_p384.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/ecc/ecc_p521.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/ecc/ecdh_key_exchange.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/ecc/ecdsa_sign.cpp"

    # KDF
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/kdf/argon2id.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/kdf/pbkdf2_hmac.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/kdf/scrypt.cpp"

    # Side-channel protection
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/side_channel/cache_attacks.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/side_channel/constant_time.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/side_channel/power_analysis.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/side_channel/spectre_mitigation.cpp"

    # Cipher suites (ChaCha20-Poly1305, Kyber1024)
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/cipher_suites/chacha20_poly1305.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/cipher_suites/kyber1024.cpp"

    # Main crypto API
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/crypto_api.cpp"
)

# ГОСТ (опционально)
if(SECUREVAULT_ENABLE_GOST)
    list(APPEND SECUREVAULT_NATIVE_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/gost/gost_34.10_2012.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/gost/gost_34.11_2012.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/gost/gost_34.12_2015.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/gost/gost_34.13_2015.cpp"
    )
    add_definitions(-DSECUREVAULT_ENABLE_GOST)
endif()

# GPU acceleration (опционально)
if(SECUREVAULT_ENABLE_GPU)
    # OpenCL
    list(APPEND SECUREVAULT_NATIVE_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/gpu_acceleration/opencl_aes.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/gpu_acceleration/vulkan_compute.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/gpu_acceleration/workload_distributor.cpp"
    )
    add_definitions(-DSECUREVAULT_ENABLE_GPU)

    # CUDA (если найден)
    find_package(CUDA QUIET)
    if(CUDA_FOUND)
        list(APPEND SECUREVAULT_NATIVE_SOURCES
            "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/src/gpu_acceleration/cuda_aes.cu"
        )
        enable_language(CUDA)
        add_definitions(-DSECUREVAULT_ENABLE_CUDA)
    endif()
endif()

# Публичные заголовки crypto_module
list(APPEND SECUREVAULT_NATIVE_PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/crypto_api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/crypto_suite.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/crypto_agility.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/algorithm_negotiation.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/types.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/aes.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/rsa.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/cipher_suites/aes256_gcm.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/cipher_suites/chacha20_poly1305.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/include/cipher_suites/kyber1024.h"
)

# --------------------------------------------------------------------------
# Модуль: container_module (контейнеры v1/v2, дедупликация, WAL, сжатие)
# --------------------------------------------------------------------------
# Зависимости: crypto_module, secure_io_module, shared
# Зависимые: нет
# --------------------------------------------------------------------------

list(APPEND SECUREVAULT_MODULE_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/compression"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/encryption"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/format_v1"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/format_v2"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/migration"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/validation"
)

list(APPEND SECUREVAULT_NATIVE_SOURCES
    # Compression
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/compression/compression_lz4.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/compression/compression_zstd.cpp"

    # Deduplication
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/deduplication/chunking.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/deduplication/gc_collector.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/deduplication/manifest_store.cpp"

    # Encryption
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/encryption/container_aes_256_gcm.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/encryption/container_key_derivation.cpp"

    # Format v1
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/format_v1/container_v1_reader.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/format_v1/container_v1_writer.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/format_v1/container_v1_validation.cpp"

    # Format v2 (plausible deniability)
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/format_v2/deniable_encryption.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/format_v2/hidden_container.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/format_v2/plausible_deniability.cpp"

    # Journal (WAL)
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/journal/checkpoint.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/journal/fsync_guard.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/journal/recovery.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/journal/write_ahead_log.cpp"

    # Migration
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/migration/upgrade_tool.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/migration/v1_to_v2_converter.cpp"

    # Validation
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/validation/format_validator.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/validation/integrity_check.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/src/validation/signature_verify.cpp"
)

# Публичные заголовки container_module
list(APPEND SECUREVAULT_NATIVE_PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/include/container_api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/include/format_v1.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/include/format_v2.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/include/metadata.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/include/deniable_encryption.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/include/hidden_container.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/container_module/include/plausible_deniability.h"
)

# --------------------------------------------------------------------------
# Модуль: pkcs11_module (Рутокен, eToken, смарт-карты)
# --------------------------------------------------------------------------
# Зависимости: crypto_module, shared, PC/SC
# Зависимые: нет
# --------------------------------------------------------------------------

list(APPEND SECUREVAULT_MODULE_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/adapters"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/session"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/key_operations"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/token_detection"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/certificate_ops"
)

list(APPEND SECUREVAULT_NATIVE_SOURCES
    # Adapters
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/adapters/rutoken.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/adapters/etoken.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/adapters/smartcard.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/adapters/module_factory.cpp"

    # Session management
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/session/session_manager.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/session/slot_manager.cpp"

    # Key operations
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/key_operations/key_generation.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/key_operations/key_management.cpp"

    # Token detection
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/token_detection/token_detector.cpp"

    # Certificate operations
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/certificate_ops/certificate_import.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/certificate_ops/certificate_export.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/src/certificate_ops/x509_parse.cpp"
)

# Публичные заголовки pkcs11_module
list(APPEND SECUREVAULT_NATIVE_PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/include/pkcs11_api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/include/session_types.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/include/token_types.h"
)

# --------------------------------------------------------------------------
# Модуль: fido2_module (FIDO2/WebAuthn, YubiKey PIV, Nitrokey)
# --------------------------------------------------------------------------
# Зависимости: shared
# Зависимые: нет
# --------------------------------------------------------------------------

list(APPEND SECUREVAULT_MODULE_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/include"
)

list(APPEND SECUREVAULT_NATIVE_SOURCES
    # FIDO2/CTAP
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/src/ctap_hid.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/src/ctap_ble.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/src/fido2_authenticator.cpp"

    # WebAuthn
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/src/webauthn_assertion.cpp"

    # Adapters
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/adapters/yubikey_piv.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/adapters/nitrokey.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/adapters/solo_key.cpp"
)

# Публичные заголовки fido2_module
list(APPEND SECUREVAULT_NATIVE_PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/include/fido2_api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/include/ctap.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/include/webauthn.h"
)

# --------------------------------------------------------------------------
# Модуль: secure_io_module (безопасное затирание, SecureAllocator, file_ops)
# --------------------------------------------------------------------------
# Зависимости: shared
# Зависимые: container_module
# --------------------------------------------------------------------------

list(APPEND SECUREVAULT_MODULE_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/include"
)

list(APPEND SECUREVAULT_NATIVE_SOURCES
    # File operations
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/file_ops/secure_file.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/file_ops/file_lock.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/file_ops/file_permissions.cpp"

    # Memory operations (anti-cold-boot)
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/memory_ops/anti_cold_boot.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/memory_ops/memory_protection.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/memory_ops/secure_allocator.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/memory_ops/secure_memory.cpp"

    # Secure wipe
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/wipe/file_wipe.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/wipe/memory_wipe.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/src/wipe/wipe_algorithms.cpp"
)

# Публичные заголовки secure_io_module
list(APPEND SECUREVAULT_NATIVE_PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/include/secure_io_api.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/include/file_ops.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/include/wipe.h"
)

# --------------------------------------------------------------------------
# Модуль: security_module (Anti-debug, Integrity, DMA, TPM, Shamir, TDX/SEV)
# --------------------------------------------------------------------------
# Зависимости: crypto_module, shared
# Зависимые: нет
# --------------------------------------------------------------------------

list(APPEND SECUREVAULT_MODULE_INCLUDE_DIRS
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/integrity_checker"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/shamir_secret_sharing/include"
)

list(APPEND SECUREVAULT_NATIVE_SOURCES
    # Anti-debug
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/anti_debug/ntglobalflag.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/anti_debug/ptrace_detection.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/anti_debug/task_exception.cpp"

    # DMA protection
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/dma_protection/acpi_check.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/dma_protection/kernel_lockdown.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/dma_protection/thunderbolt_policy.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/dma_protection/windows_dma_guard.cpp"

    # Integrity checker
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/integrity_checker/pe_integrity.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/integrity_checker/elf_integrity.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/integrity_checker/macho_integrity.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/integrity_checker/runtime_integrity.cpp"

    # Secure input
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/secure_input/scramble_pad.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/secure_input/pin_entropy_checker.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/secure_input/keyboard_layout.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/secure_input/secure_edit_win.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/secure_input/secure_input_linux.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/secure_input/secure_input_macos.cpp"

    # Shamir Secret Sharing
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/shamir_secret_sharing/src/split_secret.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/shamir_secret_sharing/src/combine_shares.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/shamir_secret_sharing/src/polynomial.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/shamir_secret_sharing/src/gf256_arithmetic.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/shamir_secret_sharing/src/verification.cpp"

    # TPM measured boot
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/tpm_measured/pcr_extend.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/tpm_measured/tpm_sealed_secret.cpp"

    # TDX/SEV trusted execution
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/tdx_sev/intel_tdx.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/tdx_sev/amd_sev.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/tdx_sev/attestation_report.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/tdx_sev/secure_guest_policy.cpp"
)

# Публичные заголовки security_module
list(APPEND SECUREVAULT_NATIVE_PUBLIC_HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/integrity_checker/integrity_verifier.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/security_module/shamir_secret_sharing/include/shamir.h"
)

# ============================================================================
# СОЗДАНИЕ БИБЛИОТЕКИ
# ============================================================================

if(SECUREVAULT_BUILD_SHARED)
    add_library(securevault_native SHARED
        ${SECUREVAULT_NATIVE_SOURCES}
        ${SECUREVAULT_NATIVE_PUBLIC_HEADERS}
        ${SECUREVAULT_SHARED_HEADERS}
    )
else()
    add_library(securevault_native STATIC
        ${SECUREVAULT_NATIVE_SOURCES}
        ${SECUREVAULT_NATIVE_PUBLIC_HEADERS}
        ${SECUREVAULT_SHARED_HEADERS}
    )
endif()

# Версионирование
set_target_properties(securevault_native PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    OUTPUT_NAME "securevault_native"
    PUBLIC_HEADER "${SECUREVAULT_NATIVE_PUBLIC_HEADERS}"
)

# Include директории
target_include_directories(securevault_native
    PUBLIC
    $<BUILD_INTERFACE:${SECUREVAULT_MODULE_INCLUDE_DIRS}>
    $<INSTALL_INTERFACE:include/securevault>
    PRIVATE
    ${SECUREVAULT_MODULE_INCLUDE_DIRS}
)

# Линковка зависимостей
target_link_libraries(securevault_native
    PUBLIC
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    PRIVATE
)

# PC/SC
if(PCSC_FOUND)
    target_link_libraries(securevault_native PRIVATE ${PCSC_LIBRARIES})
    target_include_directories(securevault_native PRIVATE ${PCSC_INCLUDE_DIRS})
    target_compile_definitions(securevault_native PRIVATE SECUREVAULT_ENABLE_PCSC)
endif()

# TPM 2.0
if(TPM2_FOUND)
    target_link_libraries(securevault_native PRIVATE ${TPM2_LIBRARIES})
    target_include_directories(securevault_native PRIVATE ${TPM2_INCLUDE_DIRS})
    target_compile_definitions(securevault_native PRIVATE SECUREVAULT_ENABLE_TPM)
endif()

# Платформозависимые библиотеки
if(WIN32)
    target_link_libraries(securevault_native PRIVATE
        setupapi.lib
        cfgmgr32.lib
        bcrypt.lib
    )
endif()

# Определения экспорта/импорта для DLL
if(WIN32)
    target_compile_definitions(securevault_native
        PUBLIC
        SECUREVAULT_NATIVE_EXPORTS
        $<$<NOT:$<BOOL:${SECUREVAULT_BUILD_SHARED}>>:SECUREVAULT_NATIVE_STATIC>
    )
endif()

# ============================================================================
# УСТАНОВКА
# ============================================================================

if(SECUREVAULT_INSTALL)
    include(GNUInstallDirs)

    # Установка библиотеки
    install(TARGETS securevault_native
        EXPORT SecureVaultNativeTargets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/securevault
    )

    # Установка shared заголовков
    install(FILES ${SECUREVAULT_SHARED_HEADERS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/securevault/shared
    )

    # Экспорт конфигурации
    install(EXPORT SecureVaultNativeTargets
        FILE SecureVaultNativeTargets.cmake
        NAMESPACE SecureVault::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SecureVault
    )

    # Создание конфигурационного файла для find_package
    include(CMakePackageConfigHelpers)
    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/SecureVaultNativeConfigVersion.cmake"
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )

    configure_package_config_file(
        "${CMAKE_CURRENT_SOURCE_DIR}/shared/cmake/SecureVaultNativeConfig.cmake.in"
        "${CMAKE_CURRENT_BINARY_DIR}/SecureVaultNativeConfig.cmake"
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SecureVault
    )

    install(FILES
        "${CMAKE_CURRENT_BINARY_DIR}/SecureVaultNativeConfig.cmake"
        "${CMAKE_CURRENT_BINARY_DIR}/SecureVaultNativeConfigVersion.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/SecureVault
    )
endif()

# ============================================================================
# ТЕСТИРОВАНИЕ
# ============================================================================

if(SECUREVAULT_ENABLE_TESTING)
    enable_testing()

    # Подключаем Catch2
    include(FetchContent)
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.4.0
    )
    FetchContent_MakeAvailable(Catch2)

    # Функция для добавления теста
    function(add_securevault_test TEST_NAME TEST_SOURCE)
        add_executable(${TEST_NAME} ${TEST_SOURCE})
        target_link_libraries(${TEST_NAME}
            PRIVATE
            securevault_native
            Catch2::Catch2WithMain
        )
        target_include_directories(${TEST_NAME}
            PRIVATE
            ${SECUREVAULT_MODULE_INCLUDE_DIRS}
        )
        add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})
    endfunction()

    # Тесты crypto_module
    add_securevault_test(test_aes
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/tests/test_aes.cpp"
    )
    add_securevault_test(test_rsa
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/tests/test_rsa.cpp"
    )
    add_securevault_test(test_kdf
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/tests/test_kdf.cpp"
    )
    add_securevault_test(test_random
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/tests/test_random.cpp"
    )
    add_securevault_test(test_chacha20_poly1305
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/tests/test_chacha20_poly1305.cpp"
    )
    add_securevault_test(test_kyber1024
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto_module/tests/test_kyber1024.cpp"
    )

    # Тесты container_module
    add_securevault_test(test_container_v1
        "${CMAKE_CURRENT_SOURCE_DIR}/container_module/tests/test_container_v1.cpp"
    )
    add_securevault_test(test_container_v2
        "${CMAKE_CURRENT_SOURCE_DIR}/container_module/tests/test_container_v2.cpp"
    )
    add_securevault_test(test_format_v2
        "${CMAKE_CURRENT_SOURCE_DIR}/container_module/tests/test_format_v2.cpp"
    )

    # Тесты pkcs11_module
    add_securevault_test(test_session_manager
        "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/tests/test_session.cpp"
    )
    add_securevault_test(test_key_operations
        "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/tests/test_key_operations.cpp"
    )
    add_securevault_test(test_token_detection
        "${CMAKE_CURRENT_SOURCE_DIR}/pkcs11_module/tests/test_token_detection.cpp"
    )

    # Тесты secure_io_module
    add_securevault_test(test_file_wipe
        "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/tests/test_file_wipe.cpp"
    )
    add_securevault_test(test_memory_ops
        "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/tests/test_memory_ops.cpp"
    )
    add_securevault_test(test_secure_file
        "${CMAKE_CURRENT_SOURCE_DIR}/secure_io_module/tests/test_secure_file.cpp"
    )

    # Тесты fido2_module
    add_securevault_test(test_ctap
        "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/tests/test_ctap.cpp"
    )
    add_securevault_test(test_webauthn
        "${CMAKE_CURRENT_SOURCE_DIR}/fido2_module/tests/test_webauthn.cpp"
    )

    # Тесты security_module (Shamir)
    add_securevault_test(test_shamir
        "${CMAKE_CURRENT_SOURCE_DIR}/security_module/shamir_secret_sharing/tests/test_shamir.cpp"
    )
endif()

# ============================================================================
# FUZZING
# ============================================================================

if(SECUREVAULT_ENABLE_FUZZING)
    # Функция для добавления fuzz-цели
    function(add_securevault_fuzz FUZZ_NAME FUZZ_SOURCE)
        add_executable(fuzz_${FUZZ_NAME} ${FUZZ_SOURCE})
        target_link_libraries(fuzz_${FUZZ_NAME}
            PRIVATE
            securevault_native
        )
        target_include_directories(fuzz_${FUZZ_NAME}
            PRIVATE
            ${SECUREVAULT_MODULE_INCLUDE_DIRS}
        )
    endfunction()

    # Fuzz цели container_module
    add_securevault_fuzz(container_header
        "${CMAKE_CURRENT_SOURCE_DIR}/container_module/fuzz/fuzz_container_header.cpp"
    )
    add_securevault_fuzz(compression
        "${CMAKE_CURRENT_SOURCE_DIR}/container_module/fuzz/fuzz_compression.cpp"
    )
endif()

# ============================================================================
# ЦЕЛИ ДЛЯ РАЗРАБОТКИ
# ============================================================================

# Форматирование кода (clang-format)
add_custom_target(format
    COMMAND clang-format -i -style=file
        ${SECUREVAULT_NATIVE_SOURCES}
        ${SECUREVAULT_NATIVE_PUBLIC_HEADERS}
        ${SECUREVAULT_SHARED_HEADERS}
    COMMENT "Formatting source code with clang-format"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# Статический анализ (clang-tidy)
add_custom_target(tidy
    COMMAND clang-tidy
        ${SECUREVAULT_NATIVE_SOURCES}
        -checks=*,-cert-err58-cpp,-fuchsia-*,-google-*,-zircon-*
        -- -std=c++17
    COMMENT "Running clang-tidy static analysis"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

# ============================================================================
# ИНФОРМАЦИЯ О СБОРКЕ
# ============================================================================

message(STATUS "========================================")
message(STATUS "SecureVault Native Core Configuration:")
message(STATUS "  Version:           ${PROJECT_VERSION}")
message(STATUS "  Build shared:      ${SECUREVAULT_BUILD_SHARED}")
message(STATUS "  Build tests:       ${SECUREVAULT_ENABLE_TESTING}")
message(STATUS "  Build fuzzing:     ${SECUREVAULT_ENABLE_FUZZING}")
message(STATUS "  PC/SC support:     ${PCSC_FOUND}")
message(STATUS "  TPM 2.0 support:   ${TPM2_FOUND}")
message(STATUS "  GPU acceleration:  ${SECUREVAULT_ENABLE_GPU}")
message(STATUS "  GOST crypto:       ${SECUREVAULT_ENABLE_GOST}")
message(STATUS "  Install:           ${SECUREVAULT_INSTALL}")
message(STATUS "  C++ standard:      ${CMAKE_CXX_STANDARD}")
message(STATUS "  Compiler:          ${CMAKE_CXX_COMPILER_ID}")
message(STATUS "  Source files:      ${SECUREVAULT_NATIVE_SOURCES}")
message(STATUS "  Public headers:    ${SECUREVAULT_NATIVE_PUBLIC_HEADERS}")
message(STATUS "========================================")
