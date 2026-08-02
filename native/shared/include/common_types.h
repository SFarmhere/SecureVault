// ============================================================================
// SecureVault - Common Type Definitions
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
// ============================================================================

#ifndef SECUREVAULT_COMMON_TYPES_H
#define SECUREVAULT_COMMON_TYPES_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <string>
#include <vector>

namespace securevault {

// ============================================================================
// VERSION INFORMATION
// ============================================================================

constexpr uint32_t SECUREVAULT_VERSION_MAJOR = 2;
constexpr uint32_t SECUREVAULT_VERSION_MINOR = 0;
constexpr uint32_t SECUREVAULT_VERSION_PATCH = 0;
constexpr const char* SECUREVAULT_VERSION_STRING = "2.0.0";

// ============================================================================
// FUNDAMENTAL TYPES
// ============================================================================

using SecurityLevelId = uint32_t;
using OperationId = uint64_t;
using SessionId = uint64_t;
using Timestamp = uint64_t;
using DataSize = uint64_t;
using FileOffset = int64_t;

// ============================================================================
// LOG LEVEL ENUMERATION
// ============================================================================

enum class LogLevel : uint32_t {
    EMERGENCY   = 0,
    ALERT       = 1,
    CRITICAL    = 2,
    ERROR       = 3,
    WARNING     = 4,
    NOTICE      = 5,
    INFO        = 6,
    DEBUG       = 7,
    TRACE       = 8,
    MAX         = TRACE
};

// ============================================================================
// SECURITY LEVEL ENUMERATION
// ============================================================================

enum class SecurityLevel : uint32_t {
    ORIGINAL    = 0,
    INDIVIDUAL  = 1,
    CONTAINER   = 2,
    HYPER       = 3,
    MAX         = HYPER
};

inline constexpr const char* security_level_to_string(SecurityLevel level) noexcept {
    switch (level) {
        case SecurityLevel::ORIGINAL:   return "ORIGINAL";
        case SecurityLevel::INDIVIDUAL: return "INDIVIDUAL";
        case SecurityLevel::CONTAINER:  return "CONTAINER";
        case SecurityLevel::HYPER:      return "HYPER";
        default:                        return "UNKNOWN";
    }
}

// ============================================================================
// CIPHER SUITE IDENTIFIERS
// ============================================================================

enum class CipherSuiteId : uint32_t {
    AES_256_GCM       = 0,
    CHACHA20_POLY1305 = 1,
    KYBER1024         = 2,
    RSA_2048          = 3,
    RSA_4096          = 4,
    ECDH_P256         = 5,
    ECDH_P384         = 6,
    ECDH_P521         = 7,
    GOST_2012         = 8,
    GOST_KUZNYECHIK   = 9,
    MAX               = GOST_KUZNYECHIK
};

// ============================================================================
// KEY DERIVATION FUNCTION IDENTIFIERS
// ============================================================================

enum class KdfAlgorithm : uint32_t {
    ARGON2ID            = 0,
    PBKDF2_HMAC_SHA256  = 1,
    SCRYPT              = 2,
    MAX                 = SCRYPT
};

// ============================================================================
// HASH ALGORITHM IDENTIFIERS
// ============================================================================

enum class HashAlgorithm : uint32_t {
    SHA256      = 0,
    SHA384      = 1,
    SHA512      = 2,
    BLAKE2B_512 = 3,
    STREEBOG_512 = 4,
    MAX         = STREEBOG_512
};

// ============================================================================
// CONTAINER FORMAT IDENTIFIERS
// ============================================================================

enum class ContainerFormat : uint32_t {
    V1  = 0,
    V2  = 1,
    MAX = V2
};

// ============================================================================
// COMPRESSION ALGORITHM IDENTIFIERS
// ============================================================================

enum class CompressionAlgorithm : uint32_t {
    NONE = 0,
    LZ4  = 1,
    ZSTD = 2,
    MAX  = ZSTD
};

// ============================================================================
// TOKEN TYPE IDENTIFIERS
// ============================================================================

enum class TokenType : uint32_t {
    NONE        = 0,
    RUTOKEN     = 1,
    ETOKEN      = 2,
    JACARTA     = 3,
    SMARTCARD   = 4,
    YUBIKEY_PIV = 5,
    NITROKEY    = 6,
    SOLOKEY     = 7,
    MAX         = SOLOKEY
};

// ============================================================================
// FIXED-SIZE BUFFERS
// ============================================================================

template <size_t N>
using FixedBuffer = std::array<uint8_t, N>;

using Aes256Key            = FixedBuffer<32>;
using AesGcmIv             = FixedBuffer<12>;
using AesGcmTag            = FixedBuffer<16>;
using ChaCha20Key          = FixedBuffer<32>;
using ChaCha20Nonce        = FixedBuffer<12>;
using Poly1305Tag          = FixedBuffer<16>;
using Kyber1024PublicKey   = FixedBuffer<1568>;
using Kyber1024SecretKey   = FixedBuffer<3168>;
using Kyber1024Ciphertext  = FixedBuffer<1568>;
using Sha256Digest         = FixedBuffer<32>;
using Sha512Digest         = FixedBuffer<64>;
using HmacSha256Result     = FixedBuffer<32>;

// ============================================================================
// KDF PARAMETERS
// ============================================================================

struct Argon2Params {
    uint32_t memory_cost_kb = 64 * 1024;
    uint32_t time_cost = 3;
    uint32_t parallelism = 4;
    uint32_t hash_length = 32;
    FixedBuffer<16> salt{};
};

struct Pbkdf2Params {
    uint32_t iterations = 600000;
    uint32_t hash_length = 32;
    HashAlgorithm hash_algorithm = HashAlgorithm::SHA256;
    FixedBuffer<16> salt{};
};

struct ScryptParams {
    uint32_t log2_n = 20;
    uint32_t r = 8;
    uint32_t p = 1;
    uint32_t hash_length = 32;
    FixedBuffer<16> salt{};
};

// ============================================================================
// CONTAINER AND FILE METADATA
// ============================================================================

struct ContainerInfo {
    ContainerFormat format = ContainerFormat::V1;
    SecurityLevel security_level = SecurityLevel::CONTAINER;
    DataSize total_size = 0;
    DataSize used_size = 0;
    uint32_t file_count = 0;
    CompressionAlgorithm compression = CompressionAlgorithm::ZSTD;
    bool deduplication_enabled = false;
    bool is_hidden = false;
    Timestamp created_at = 0;
    Timestamp modified_at = 0;
};

struct FileMetadata {
    std::string original_path;
    std::string encrypted_path;
    DataSize original_size = 0;
    DataSize encrypted_size = 0;
    CompressionAlgorithm compression = CompressionAlgorithm::NONE;
    bool encrypted = true;
    Timestamp created_at = 0;
    Timestamp modified_at = 0;
    Sha256Digest original_hash{};
    Sha256Digest encrypted_hash{};
};

// ============================================================================
// OPERATION RESULT
// ============================================================================

template <typename T>
struct Result {
    bool success = false;
    int32_t error_code = 0;
    std::string error_message;
    T value{};

    static Result ok(T val) {
        return Result{true, 0, "", std::move(val)};
    }
    static Result fail(int32_t code, std::string message) {
        return Result{false, code, std::move(message), T{}};
    }
};

template <>
struct Result<void> {
    bool success = false;
    int32_t error_code = 0;
    std::string error_message;

    static Result ok() { return Result{true, 0, ""}; }
    static Result fail(int32_t code, std::string message) {
        return Result{false, code, std::move(message)};
    }
};

// ============================================================================
// BYTE ARRAY ALIASES (C++17 compatible — no std::span)
// ============================================================================

using ByteArray = std::vector<uint8_t>;

/// Simple byte span for C++17 (pointer + size)
struct ByteSpan {
    const uint8_t* data = nullptr;
    size_t size = 0;

    ByteSpan() = default;
    ByteSpan(const uint8_t* d, size_t s) : data(d), size(s) {}
    ByteSpan(const ByteArray& vec) : data(vec.data()), size(vec.size()) {}
    const uint8_t* begin() const { return data; }
    const uint8_t* end() const { return data + size; }
    bool empty() const { return size == 0; }
};

/// Mutable byte span
struct MutableByteSpan {
    uint8_t* data = nullptr;
    size_t size = 0;

    MutableByteSpan() = default;
    MutableByteSpan(uint8_t* d, size_t s) : data(d), size(s) {}
    MutableByteSpan(ByteArray& vec) : data(vec.data()), size(vec.size()) {}
    uint8_t* begin() const { return data; }
    uint8_t* end() const { return data + size; }
    bool empty() const { return size == 0; }
};

} // namespace securevault

#endif // SECUREVAULT_COMMON_TYPES_H