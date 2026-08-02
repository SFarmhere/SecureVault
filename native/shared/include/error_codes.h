// ============================================================================
// SecureVault - Error Code Definitions
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Centralized error code definitions for all native modules.
//   Error codes are organized by module with clear ranges:
//     0x0000 - 0x0FFF: General errors
//     0x1000 - 0x1FFF: Crypto module errors
//     0x2000 - 0x2FFF: Container module errors
//     0x3000 - 0x3FFF: PKCS#11 module errors
//     0x4000 - 0x4FFF: Secure I/O module errors
//     0x5000 - 0x5FFF: Security module errors
//     0x6000 - 0x6FFF: FIDO2 module errors
//     0x7000 - 0x7FFF: Configuration errors
//     0x8000 - 0xFFFF: Reserved for future use
//
//   Each error code maps to a human-readable message via error_code_to_string().
// ============================================================================

#ifndef SECUREVAULT_ERROR_CODES_H
#define SECUREVAULT_ERROR_CODES_H

#include <cstdint>
#include <string_view>

namespace securevault {

// ============================================================================
// GENERAL ERROR CODES (0x0000 - 0x0FFF)
// ============================================================================

enum class ErrorCode : int32_t {
    // ---- Success ----
    SUCCESS                     = 0x0000,

    // ---- General errors ----
    UNKNOWN_ERROR               = 0x0001,
    NOT_IMPLEMENTED             = 0x0002,
    INVALID_ARGUMENT            = 0x0003,
    INVALID_STATE               = 0x0004,
    OUT_OF_MEMORY               = 0x0005,
    BUFFER_TOO_SMALL            = 0x0006,
    NULL_POINTER                = 0x0007,
    OPERATION_TIMEOUT           = 0x0008,
    OPERATION_CANCELLED         = 0x0009,
    NOT_INITIALIZED             = 0x000A,
    ALREADY_INITIALIZED         = 0x000B,
    VERSION_MISMATCH            = 0x000C,
    PLATFORM_NOT_SUPPORTED      = 0x000D,
    FEATURE_DISABLED            = 0x000E,
    RESOURCE_BUSY               = 0x000F,
    ACCESS_DENIED               = 0x0010,
    PERMISSION_DENIED           = 0x0011,
    INVALID_HANDLE              = 0x0012,
    INVALID_SESSION             = 0x0013,
    SESSION_EXPIRED             = 0x0014,
    THREAD_SAFETY_VIOLATION     = 0x0015,
    INTERNAL_INCONSISTENCY      = 0x0016,

    // ---- I/O errors ----
    IO_ERROR                    = 0x0100,
    FILE_NOT_FOUND              = 0x0101,
    FILE_ACCESS_DENIED          = 0x0102,
    FILE_LOCKED                 = 0x0103,
    FILE_CORRUPTED              = 0x0104,
    FILE_TOO_LARGE              = 0x0105,
    DISK_FULL                   = 0x0106,
    DIRECTORY_NOT_FOUND         = 0x0107,
    PATH_TOO_LONG               = 0x0108,

    // ---- Network errors ----
    NETWORK_ERROR               = 0x0200,
    CONNECTION_FAILED           = 0x0201,
    CONNECTION_TIMEOUT          = 0x0202,
    CONNECTION_RESET            = 0x0203,
    DNS_RESOLUTION_FAILED       = 0x0204,
    PROTOCOL_ERROR              = 0x0205,
    TLS_HANDSHAKE_FAILED        = 0x0206,
    TLS_CERTIFICATE_INVALID     = 0x0207,

    // ---- Serialization errors ----
    SERIALIZATION_ERROR         = 0x0300,
    DESERIALIZATION_ERROR       = 0x0301,
    INVALID_FORMAT              = 0x0302,
    DATA_CORRUPTED              = 0x0303,
    CHECKSUM_MISMATCH           = 0x0304,
    SIGNATURE_INVALID           = 0x0305,

    // ---- Crypto operation errors ----
    ENCRYPTION_FAILED           = 0x0400,
    DECRYPTION_FAILED           = 0x0401,
    AUTHENTICATION_FAILED       = 0x0402,
    TAG_MISMATCH                = 0x0403,
    IV_LENGTH_INVALID           = 0x0404,
    PADDING_INVALID             = 0x0405,
    CIPHER_NOT_INITIALIZED      = 0x0406,
    CIPHER_ALREADY_FINALIZED    = 0x0407,
    DATA_TOO_LARGE              = 0x0408,
    KEY_EXPAND_FAILED           = 0x0409,
};

// ============================================================================
// CRYPTO MODULE ERROR CODES (0x1000 - 0x1FFF)
// ============================================================================

enum class CryptoError : int32_t {
    // ---- Base ----
    CRYPTO_BASE                 = 0x1000,

    // ---- Key errors ----
    KEY_GENERATION_FAILED       = 0x1001,
    KEY_IMPORT_FAILED           = 0x1002,
    KEY_EXPORT_FAILED           = 0x1003,
    KEY_SIZE_INVALID            = 0x1004,
    KEY_TYPE_UNSUPPORTED        = 0x1005,
    KEY_NOT_FOUND               = 0x1006,
    KEY_ALREADY_EXISTS          = 0x1007,
    KEY_DESTROY_FAILED          = 0x1008,
    KEY_DERIVATION_FAILED       = 0x1009,
    KEY_WRAP_FAILED             = 0x100A,
    KEY_UNWRAP_FAILED           = 0x100B,

    // ---- Encryption/Decryption errors ----
    ENCRYPTION_FAILED           = 0x1100,
    DECRYPTION_FAILED           = 0x1101,
    AUTHENTICATION_FAILED       = 0x1102,
    TAG_MISMATCH                = 0x1103,
    IV_LENGTH_INVALID           = 0x1104,
    PADDING_INVALID             = 0x1105,
    CIPHER_NOT_INITIALIZED      = 0x1106,
    CIPHER_ALREADY_FINALIZED    = 0x1107,
    DATA_TOO_LARGE              = 0x1108,

    // ---- Hash errors ----
    HASH_FAILED                 = 0x1200,
    HASH_ALGORITHM_UNSUPPORTED  = 0x1201,
    HMAC_FAILED                 = 0x1202,
    HMAC_VERIFICATION_FAILED    = 0x1203,

    // ---- Signature errors ----
    SIGNING_FAILED              = 0x1300,
    VERIFICATION_FAILED         = 0x1301,
    SIGNATURE_EXPIRED           = 0x1302,
    CERTIFICATE_CHAIN_INVALID   = 0x1303,
    CERTIFICATE_EXPIRED         = 0x1304,
    CERTIFICATE_REVOKED         = 0x1305,

    // ---- KDF errors ----
    KDF_FAILED                  = 0x1400,
    KDF_PARAMETERS_INVALID      = 0x1401,
    KDF_MEMORY_TOO_HIGH         = 0x1402,
    KDF_TIME_TOO_HIGH           = 0x1403,
    KDF_SALT_INVALID            = 0x1404,

    // ---- Post-quantum errors ----
    KYBER_KEYGEN_FAILED         = 0x1500,
    KYBER_ENCAPSULATE_FAILED    = 0x1501,
    KYBER_DECAPSULATE_FAILED    = 0x1502,
    KYBER_CIPHERTEXT_INVALID    = 0x1503,

    // ---- ECC errors ----
    ECC_KEYGEN_FAILED           = 0x1600,
    ECC_CURVE_UNSUPPORTED       = 0x1601,
    ECDH_FAILED                 = 0x1602,
    ECDSA_SIGN_FAILED           = 0x1603,
    ECDSA_VERIFY_FAILED         = 0x1604,
    POINT_NOT_ON_CURVE          = 0x1605,

    // ---- GOST errors ----
    GOST_KEYGEN_FAILED          = 0x1700,
    GOST_SIGN_FAILED            = 0x1701,
    GOST_VERIFY_FAILED          = 0x1702,
    GOST_HASH_FAILED            = 0x1703,
    GOST_CIPHER_FAILED          = 0x1704,

    // ---- GPU acceleration errors ----
    GPU_NOT_AVAILABLE           = 0x1800,
    GPU_DRIVER_ERROR            = 0x1801,
    GPU_OUT_OF_MEMORY           = 0x1802,
    GPU_KERNEL_COMPILE_FAILED   = 0x1803,
    GPU_KERNEL_EXECUTION_FAILED = 0x1804,
};

// ============================================================================
// CONTAINER MODULE ERROR CODES (0x2000 - 0x2FFF)
// ============================================================================

enum class ContainerError : int32_t {
    CONTAINER_BASE              = 0x2000,
    CONTAINER_NOT_FOUND         = 0x2001,
    CONTAINER_ALREADY_EXISTS    = 0x2002,
    CONTAINER_FULL              = 0x2003,
    CONTAINER_CORRUPTED         = 0x2004,
    CONTAINER_LOCKED            = 0x2005,
    CONTAINER_ALREADY_OPEN      = 0x2006,
    CONTAINER_NOT_OPEN          = 0x2007,
    CONTAINER_VERSION_UNSUPPORTED = 0x2008,
    CONTAINER_FORMAT_INVALID    = 0x2009,
    CONTAINER_HEADER_CORRUPTED  = 0x200A,
    CONTAINER_METADATA_CORRUPTED = 0x200B,

    // ---- File operations ----
    FILE_ADD_FAILED             = 0x2100,
    FILE_EXTRACT_FAILED         = 0x2101,
    FILE_DELETE_FAILED          = 0x2102,
    FILE_RENAME_FAILED          = 0x2103,
    FILE_NOT_IN_CONTAINER       = 0x2104,
    FILE_ALREADY_IN_CONTAINER   = 0x2105,
    FILE_SIZE_EXCEEDS_LIMIT     = 0x2106,
    FILE_NAME_TOO_LONG          = 0x2107,

    // ---- Deduplication ----
    DEDUP_CHUNKING_FAILED       = 0x2200,
    DEDUP_MANIFEST_CORRUPTED    = 0x2201,
    DEDUP_GC_FAILED             = 0x2202,
    DEDUP_INDEX_FULL            = 0x2203,

    // ---- Journal/WAL ----
    WAL_WRITE_FAILED            = 0x2300,
    WAL_READ_FAILED             = 0x2301,
    WAL_CORRUPTED               = 0x2302,
    WAL_REPLAY_FAILED           = 0x2303,
    CHECKPOINT_FAILED           = 0x2304,
    RECOVERY_FAILED             = 0x2305,

    // ---- Compression ----
    COMPRESSION_FAILED          = 0x2400,
    DECOMPRESSION_FAILED        = 0x2401,
    COMPRESSION_ALGO_UNSUPPORTED = 0x2402,
    COMPRESSION_RATIO_INVALID   = 0x2403,

    // ---- Migration ----
    MIGRATION_FAILED            = 0x2500,
    MIGRATION_NOT_NEEDED        = 0x2501,
    MIGRATION_IN_PROGRESS       = 0x2502,
    BACKWARD_COMPATIBILITY_BROKEN = 0x2503,

    // ---- Plausible deniability ----
    HIDDEN_CONTAINER_NOT_FOUND  = 0x2600,
    HIDDEN_CONTAINER_CORRUPTED  = 0x2601,
    DENIABLE_ENCRYPTION_FAILED  = 0x2602,
    PLAUSIBLE_DENIABILITY_ERROR = 0x2603,
};

// ============================================================================
// PKCS#11 MODULE ERROR CODES (0x3000 - 0x3FFF)
// ============================================================================

enum class Pkcs11Error : int32_t {
    PKCS11_BASE                 = 0x3000,
    TOKEN_NOT_FOUND             = 0x3001,
    TOKEN_NOT_PRESENT           = 0x3002,
    TOKEN_REMOVED               = 0x3003,
    TOKEN_ERROR                 = 0x3004,
    TOKEN_READ_ONLY             = 0x3005,
    TOKEN_WRITE_PROTECTED       = 0x3006,
    TOKEN_MEMORY_FULL           = 0x3007,
    TOKEN_SESSION_COUNT_EXCEEDED = 0x3008,

    // ---- Session errors ----
    SESSION_OPEN_FAILED         = 0x3100,
    SESSION_CLOSE_FAILED        = 0x3101,
    SESSION_HANDLE_INVALID      = 0x3102,
    SESSION_READ_ONLY           = 0x3103,
    SESSION_EXISTS              = 0x3104,
    SESSION_COUNT_EXCEEDED      = 0x3105,

    // ---- Authentication errors ----
    PIN_INCORRECT               = 0x3200,
    PIN_LOCKED                  = 0x3201,
    PIN_EXPIRED                 = 0x3202,
    PIN_CHANGE_REQUIRED         = 0x3203,
    PIN_TOO_WEAK                = 0x3204,
    PIN_LENGTH_INVALID          = 0x3205,
    USER_NOT_LOGGED_IN          = 0x3206,
    USER_ALREADY_LOGGED_IN      = 0x3207,
    USER_TYPE_INVALID           = 0x3208,

    // ---- Adapter errors ----
    ADAPTER_NOT_FOUND           = 0x3300,
    ADAPTER_INIT_FAILED         = 0x3301,
    ADAPTER_NOT_SUPPORTED       = 0x3302,
    RUTOKEN_ERROR               = 0x3303,
    ETOKEN_ERROR                = 0x3304,
    SMARTCARD_ERROR             = 0x3305,
    PCSC_ERROR                  = 0x3306,
    PCSC_NOT_AVAILABLE          = 0x3307,

    // ---- Certificate errors ----
    CERTIFICATE_IMPORT_FAILED   = 0x3400,
    CERTIFICATE_EXPORT_FAILED   = 0x3401,
    CERTIFICATE_PARSE_FAILED    = 0x3402,
    CERTIFICATE_NOT_FOUND       = 0x3403,
    X509_PARSE_FAILED           = 0x3404,
    X509_CHAIN_VERIFICATION_FAILED = 0x3405,
};

// ============================================================================
// SECURE I/O MODULE ERROR CODES (0x4000 - 0x4FFF)
// ============================================================================

enum class SecureIOError : int32_t {
    SECURE_IO_BASE              = 0x4000,

    // ---- Secure file operations ----
    SECURE_FILE_OPEN_FAILED     = 0x4001,
    SECURE_FILE_WRITE_FAILED    = 0x4002,
    SECURE_FILE_READ_FAILED     = 0x4003,
    SECURE_FILE_SEEK_FAILED     = 0x4004,
    SECURE_FILE_FLUSH_FAILED    = 0x4005,
    SECURE_FILE_CLOSE_FAILED    = 0x4006,
    SECURE_FILE_LOCK_FAILED     = 0x4007,
    SECURE_FILE_UNLOCK_FAILED   = 0x4008,
    SECURE_FILE_PERMISSION_FAILED = 0x4009,

    // ---- Memory operations ----
    MEMORY_LOCK_FAILED          = 0x4100,
    MEMORY_UNLOCK_FAILED        = 0x4101,
    MEMORY_PROTECTION_FAILED    = 0x4102,
    MEMORY_WIPE_FAILED          = 0x4103,
    SECURE_ALLOC_FAILED         = 0x4104,
    SECURE_FREE_FAILED          = 0x4105,
    ANTI_COLD_BOOT_FAILED       = 0x4106,
    MEMORY_TOO_LARGE            = 0x4107,

    // ---- Secure wipe ----
    WIPE_FAILED                 = 0x4200,
    WIPE_VERIFICATION_FAILED    = 0x4201,
    WIPE_ALGORITHM_UNSUPPORTED  = 0x4202,
    WIPE_PATTERN_INVALID        = 0x4203,
    GUTMANN_WIPE_FAILED         = 0x4204,
    DOD_WIPE_FAILED             = 0x4205,
    NIST_WIPE_FAILED            = 0x4206,
};

// ============================================================================
// SECURITY MODULE ERROR CODES (0x5000 - 0x5FFF)
// ============================================================================

enum class SecurityError : int32_t {
    SECURITY_BASE               = 0x5000,

    // ---- Anti-debug ----
    DEBUGGER_DETECTED           = 0x5001,
    ANTI_DEBUG_INIT_FAILED      = 0x5002,
    PTRACE_FAILED               = 0x5003,
    NT_GLOBAL_FLAG_CHECK_FAILED = 0x5004,
    TASK_EXCEPTION_CHECK_FAILED = 0x5005,

    // ---- Integrity ----
    INTEGRITY_CHECK_FAILED      = 0x5100,
    PE_INTEGRITY_FAILED         = 0x5101,
    ELF_INTEGRITY_FAILED        = 0x5102,
    MACHO_INTEGRITY_FAILED      = 0x5103,
    RUNTIME_INTEGRITY_FAILED    = 0x5104,
    CODE_SIGNATURE_INVALID      = 0x5105,
    HASH_MISMATCH               = 0x5106,

    // ---- DMA protection ----
    DMA_PROTECTION_FAILED       = 0x5200,
    IOMMU_NOT_AVAILABLE         = 0x5201,
    THUNDERBOLT_ATTACK_DETECTED = 0x5202,
    ACPI_CHECK_FAILED           = 0x5203,
    KERNEL_LOCKDOWN_FAILED      = 0x5204,
    DMA_GUARD_NOT_AVAILABLE     = 0x5205,

    // ---- Secure input ----
    SECURE_INPUT_INIT_FAILED    = 0x5300,
    SCRAMBLE_PAD_FAILED         = 0x5301,
    PIN_ENTROPY_TOO_LOW         = 0x5302,
    KEYBOARD_LAYOUT_DETECTION_FAILED = 0x5303,
    SECURE_EDIT_FAILED          = 0x5304,

    // ---- Shamir Secret Sharing ----
    SHAMIR_SPLIT_FAILED         = 0x5400,
    SHAMIR_COMBINE_FAILED       = 0x5401,
    SHAMIR_INVALID_SHARE        = 0x5402,
    SHAMIR_INSUFFICIENT_SHARES  = 0x5403,
    SHAMIR_DUPLICATE_SHARE      = 0x5404,
    SHAMIR_CORRUPTED_SHARE      = 0x5405,
    SHAMIR_VERIFICATION_FAILED  = 0x5406,
    GF256_ARITHMETIC_ERROR      = 0x5407,
    POLYNOMIAL_EVALUATION_ERROR = 0x5408,

    // ---- TPM ----
    TPM_NOT_AVAILABLE           = 0x5500,
    TPM_INIT_FAILED             = 0x5501,
    TPM_PCR_EXTEND_FAILED       = 0x5502,
    TPM_PCR_QUOTE_FAILED        = 0x5503,
    TPM_SEAL_FAILED             = 0x5504,
    TPM_UNSEAL_FAILED           = 0x5505,
    TPM_PCR_VALUE_MISMATCH      = 0x5506,
    TPM_ATTESTATION_FAILED      = 0x5507,

    // ---- TDX/SEV ----
    TDX_NOT_AVAILABLE           = 0x5600,
    SEV_NOT_AVAILABLE           = 0x5601,
    TDX_INIT_FAILED             = 0x5602,
    SEV_INIT_FAILED             = 0x5603,
    ATTESTATION_REPORT_FAILED   = 0x5604,
    SECURE_GUEST_POLICY_FAILED  = 0x5605,
    TRUSTED_EXECUTION_FAILED    = 0x5606,
};

// ============================================================================
// FIDO2 MODULE ERROR CODES (0x6000 - 0x6FFF)
// ============================================================================

enum class Fido2Error : int32_t {
    FIDO2_BASE                  = 0x6000,
    AUTHENTICATOR_NOT_FOUND     = 0x6001,
    AUTHENTICATOR_ERROR         = 0x6002,
    AUTHENTICATOR_TIMEOUT       = 0x6003,
    AUTHENTICATOR_REMOVED       = 0x6004,
    CTAP_ERROR                  = 0x6005,
    CTAP_HID_ERROR              = 0x6006,
    CTAP_BLE_ERROR              = 0x6007,
    WEBAUTHN_ERROR              = 0x6008,
    WEBAUTHN_ASSERTION_FAILED   = 0x6009,
    WEBAUTHN_ATTESTATION_FAILED = 0x600A,
    CREDENTIAL_EXCLUDED         = 0x600B,
    USER_VERIFICATION_FAILED    = 0x600C,
    PIN_REQUIRED                = 0x600D,
    PIN_AUTH_FAILED             = 0x600E,
    YUBIKEY_PIV_ERROR           = 0x600F,
    NITROKEY_ERROR              = 0x6010,
    SOLOKEY_ERROR               = 0x6011,
    UVP_ERROR                   = 0x6012,
    KEEPALIVE_CANCEL            = 0x6013,
    NO_CREDENTIALS              = 0x6014,
    USER_ACTION_TIMEOUT         = 0x6015,
};

// ============================================================================
// CONFIGURATION ERROR CODES (0x7000 - 0x7FFF)
// ============================================================================

enum class ConfigError : int32_t {
    CONFIG_BASE                 = 0x7000,
    CONFIG_FILE_NOT_FOUND       = 0x7001,
    CONFIG_FILE_CORRUPTED       = 0x7002,
    CONFIG_PARSE_FAILED         = 0x7003,
    CONFIG_KEY_NOT_FOUND        = 0x7004,
    CONFIG_VALUE_INVALID        = 0x7005,
    CONFIG_TYPE_MISMATCH        = 0x7006,
    CONFIG_VERSION_MISMATCH     = 0x7007,
    CONFIG_VALIDATION_FAILED    = 0x7008,
    CONFIG_ENCRYPTION_FAILED    = 0x7009,
    CONFIG_DECRYPTION_FAILED    = 0x700A,
};

// ============================================================================
// ERROR CODE TO STRING CONVERSION
// ============================================================================

/// Convert an ErrorCode to a human-readable string
inline constexpr std::string_view error_code_to_string(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::SUCCESS:                    return "SUCCESS";
        case ErrorCode::UNKNOWN_ERROR:              return "UNKNOWN_ERROR";
        case ErrorCode::NOT_IMPLEMENTED:            return "NOT_IMPLEMENTED";
        case ErrorCode::INVALID_ARGUMENT:           return "INVALID_ARGUMENT";
        case ErrorCode::INVALID_STATE:              return "INVALID_STATE";
        case ErrorCode::OUT_OF_MEMORY:              return "OUT_OF_MEMORY";
        case ErrorCode::BUFFER_TOO_SMALL:           return "BUFFER_TOO_SMALL";
        case ErrorCode::NULL_POINTER:               return "NULL_POINTER";
        case ErrorCode::OPERATION_TIMEOUT:          return "OPERATION_TIMEOUT";
        case ErrorCode::OPERATION_CANCELLED:        return "OPERATION_CANCELLED";
        case ErrorCode::NOT_INITIALIZED:            return "NOT_INITIALIZED";
        case ErrorCode::ALREADY_INITIALIZED:        return "ALREADY_INITIALIZED";
        case ErrorCode::VERSION_MISMATCH:           return "VERSION_MISMATCH";
        case ErrorCode::PLATFORM_NOT_SUPPORTED:     return "PLATFORM_NOT_SUPPORTED";
        case ErrorCode::FEATURE_DISABLED:           return "FEATURE_DISABLED";
        case ErrorCode::RESOURCE_BUSY:              return "RESOURCE_BUSY";
        case ErrorCode::ACCESS_DENIED:              return "ACCESS_DENIED";
        case ErrorCode::PERMISSION_DENIED:          return "PERMISSION_DENIED";
        case ErrorCode::INVALID_HANDLE:             return "INVALID_HANDLE";
        case ErrorCode::INVALID_SESSION:            return "INVALID_SESSION";
        case ErrorCode::SESSION_EXPIRED:            return "SESSION_EXPIRED";
        case ErrorCode::THREAD_SAFETY_VIOLATION:    return "THREAD_SAFETY_VIOLATION";
        case ErrorCode::INTERNAL_INCONSISTENCY:     return "INTERNAL_INCONSISTENCY";
        case ErrorCode::IO_ERROR:                   return "IO_ERROR";
        case ErrorCode::FILE_NOT_FOUND:             return "FILE_NOT_FOUND";
        case ErrorCode::FILE_ACCESS_DENIED:         return "FILE_ACCESS_DENIED";
        case ErrorCode::FILE_LOCKED:                return "FILE_LOCKED";
        case ErrorCode::FILE_CORRUPTED:             return "FILE_CORRUPTED";
        case ErrorCode::FILE_TOO_LARGE:             return "FILE_TOO_LARGE";
        case ErrorCode::DISK_FULL:                  return "DISK_FULL";
        case ErrorCode::DIRECTORY_NOT_FOUND:        return "DIRECTORY_NOT_FOUND";
        case ErrorCode::PATH_TOO_LONG:              return "PATH_TOO_LONG";
        case ErrorCode::NETWORK_ERROR:              return "NETWORK_ERROR";
        case ErrorCode::CONNECTION_FAILED:          return "CONNECTION_FAILED";
        case ErrorCode::CONNECTION_TIMEOUT:         return "CONNECTION_TIMEOUT";
        case ErrorCode::CONNECTION_RESET:           return "CONNECTION_RESET";
        case ErrorCode::DNS_RESOLUTION_FAILED:      return "DNS_RESOLUTION_FAILED";
        case ErrorCode::PROTOCOL_ERROR:             return "PROTOCOL_ERROR";
        case ErrorCode::TLS_HANDSHAKE_FAILED:       return "TLS_HANDSHAKE_FAILED";
        case ErrorCode::TLS_CERTIFICATE_INVALID:    return "TLS_CERTIFICATE_INVALID";
        case ErrorCode::SERIALIZATION_ERROR:        return "SERIALIZATION_ERROR";
        case ErrorCode::DESERIALIZATION_ERROR:      return "DESERIALIZATION_ERROR";
        case ErrorCode::INVALID_FORMAT:             return "INVALID_FORMAT";
        case ErrorCode::DATA_CORRUPTED:             return "DATA_CORRUPTED";
        case ErrorCode::CHECKSUM_MISMATCH:          return "CHECKSUM_MISMATCH";
        case ErrorCode::SIGNATURE_INVALID:          return "SIGNATURE_INVALID";
        case ErrorCode::ENCRYPTION_FAILED:          return "ENCRYPTION_FAILED";
        case ErrorCode::DECRYPTION_FAILED:          return "DECRYPTION_FAILED";
        case ErrorCode::AUTHENTICATION_FAILED:      return "AUTHENTICATION_FAILED";
        case ErrorCode::TAG_MISMATCH:               return "TAG_MISMATCH";
        case ErrorCode::IV_LENGTH_INVALID:          return "IV_LENGTH_INVALID";
        case ErrorCode::PADDING_INVALID:            return "PADDING_INVALID";
        case ErrorCode::CIPHER_NOT_INITIALIZED:     return "CIPHER_NOT_INITIALIZED";
        case ErrorCode::CIPHER_ALREADY_FINALIZED:   return "CIPHER_ALREADY_FINALIZED";
        case ErrorCode::DATA_TOO_LARGE:             return "DATA_TOO_LARGE";
        case ErrorCode::KEY_EXPAND_FAILED:          return "KEY_EXPAND_FAILED";
        default:                                    return "UNKNOWN_ERROR_CODE";
    }
}

/// Convert a CryptoError to a human-readable string
inline constexpr std::string_view crypto_error_to_string(CryptoError code) noexcept {
    switch (code) {
        case CryptoError::CRYPTO_BASE:                  return "CRYPTO_BASE";
        case CryptoError::KEY_GENERATION_FAILED:        return "KEY_GENERATION_FAILED";
        case CryptoError::KEY_IMPORT_FAILED:            return "KEY_IMPORT_FAILED";
        case CryptoError::KEY_EXPORT_FAILED:            return "KEY_EXPORT_FAILED";
        case CryptoError::KEY_SIZE_INVALID:             return "KEY_SIZE_INVALID";
        case CryptoError::KEY_TYPE_UNSUPPORTED:         return "KEY_TYPE_UNSUPPORTED";
        case CryptoError::KEY_NOT_FOUND:                return "KEY_NOT_FOUND";
        case CryptoError::KEY_ALREADY_EXISTS:           return "KEY_ALREADY_EXISTS";
        case CryptoError::KEY_DESTROY_FAILED:           return "KEY_DESTROY_FAILED";
        case CryptoError::KEY_DERIVATION_FAILED:        return "KEY_DERIVATION_FAILED";
        case CryptoError::KEY_WRAP_FAILED:              return "KEY_WRAP_FAILED";
        case CryptoError::KEY_UNWRAP_FAILED:            return "KEY_UNWRAP_FAILED";
        case CryptoError::ENCRYPTION_FAILED:            return "ENCRYPTION_FAILED";
        case CryptoError::DECRYPTION_FAILED:            return "DECRYPTION_FAILED";
        case CryptoError::AUTHENTICATION_FAILED:        return "AUTHENTICATION_FAILED";
        case CryptoError::TAG_MISMATCH:                 return "TAG_MISMATCH";
        case CryptoError::IV_LENGTH_INVALID:            return "IV_LENGTH_INVALID";
        case CryptoError::PADDING_INVALID:              return "PADDING_INVALID";
        case CryptoError::CIPHER_NOT_INITIALIZED:       return "CIPHER_NOT_INITIALIZED";
        case CryptoError::CIPHER_ALREADY_FINALIZED:     return "CIPHER_ALREADY_FINALIZED";
        case CryptoError::DATA_TOO_LARGE:               return "DATA_TOO_LARGE";
        case CryptoError::HASH_FAILED:                  return "HASH_FAILED";
        case CryptoError::HASH_ALGORITHM_UNSUPPORTED:   return "HASH_ALGORITHM_UNSUPPORTED";
        case CryptoError::HMAC_FAILED:                  return "HMAC_FAILED";
        case CryptoError::HMAC_VERIFICATION_FAILED:     return "HMAC_VERIFICATION_FAILED";
        case CryptoError::SIGNING_FAILED:               return "SIGNING_FAILED";
        case CryptoError::VERIFICATION_FAILED:          return "VERIFICATION_FAILED";
        case CryptoError::SIGNATURE_EXPIRED:            return "SIGNATURE_EXPIRED";
        case CryptoError::CERTIFICATE_CHAIN_INVALID:    return "CERTIFICATE_CHAIN_INVALID";
        case CryptoError::CERTIFICATE_EXPIRED:          return "CERTIFICATE_EXPIRED";
        case CryptoError::CERTIFICATE_REVOKED:          return "CERTIFICATE_REVOKED";
        case CryptoError::KDF_FAILED:                   return "KDF_FAILED";
        case CryptoError::KDF_PARAMETERS_INVALID:       return "KDF_PARAMETERS_INVALID";
        case CryptoError::KDF_MEMORY_TOO_HIGH:          return "KDF_MEMORY_TOO_HIGH";
        case CryptoError::KDF_TIME_TOO_HIGH:            return "KDF_TIME_TOO_HIGH";
        case CryptoError::KDF_SALT_INVALID:             return "KDF_SALT_INVALID";
        case CryptoError::KYBER_KEYGEN_FAILED:          return "KYBER_KEYGEN_FAILED";
        case CryptoError::KYBER_ENCAPSULATE_FAILED:     return "KYBER_ENCAPSULATE_FAILED";
        case CryptoError::KYBER_DECAPSULATE_FAILED:     return "KYBER_DECAPSULATE_FAILED";
        case CryptoError::KYBER_CIPHERTEXT_INVALID:     return "KYBER_CIPHERTEXT_INVALID";
        case CryptoError::ECC_KEYGEN_FAILED:            return "ECC_KEYGEN_FAILED";
        case CryptoError::ECC_CURVE_UNSUPPORTED:        return "ECC_CURVE_UNSUPPORTED";
        case CryptoError::ECDH_FAILED:                  return "ECDH_FAILED";
        case CryptoError::ECDSA_SIGN_FAILED:            return "ECDSA_SIGN_FAILED";
        case CryptoError::ECDSA_VERIFY_FAILED:          return "ECDSA_VERIFY_FAILED";
        case CryptoError::POINT_NOT_ON_CURVE:           return "POINT_NOT_ON_CURVE";
        case CryptoError::GOST_KEYGEN_FAILED:           return "GOST_KEYGEN_FAILED";
        case CryptoError::GOST_SIGN_FAILED:             return "GOST_SIGN_FAILED";
        case CryptoError::GOST_VERIFY_FAILED:           return "GOST_VERIFY_FAILED";
        case CryptoError::GOST_HASH_FAILED:             return "GOST_HASH_FAILED";
        case CryptoError::GOST_CIPHER_FAILED:           return "GOST_CIPHER_FAILED";
        case CryptoError::GPU_NOT_AVAILABLE:            return "GPU_NOT_AVAILABLE";
        case CryptoError::GPU_DRIVER_ERROR:             return "GPU_DRIVER_ERROR";
        case CryptoError::GPU_OUT_OF_MEMORY:            return "GPU_OUT_OF_MEMORY";
        case CryptoError::GPU_KERNEL_COMPILE_FAILED:    return "GPU_KERNEL_COMPILE_FAILED";
        case CryptoError::GPU_KERNEL_EXECUTION_FAILED:  return "GPU_KERNEL_EXECUTION_FAILED";
        default:                                        return "UNKNOWN_CRYPTO_ERROR";
    }
}

} // namespace securevault

#endif // SECUREVAULT_ERROR_CODES_H