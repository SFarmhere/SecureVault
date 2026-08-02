// ============================================================================
// SecureVault - Container Format v1
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Standard encrypted container format (v1).
//   Structure:
//     [Header 512B]  - Magic, version, container ID, key info
//     [Key Blob]     - RSA-encrypted or password-derived AES key
//     [Metadata]     - Encrypted file metadata (JSON)
//     [Data Blocks]  - AES-256-GCM encrypted file data
//     [WAL]          - Write-Ahead Log for crash recovery
//     [Footer]       - HMAC-SHA256 of entire container
// ============================================================================

#ifndef SECUREVAULT_FORMAT_V1_H
#define SECUREVAULT_FORMAT_V1_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>

#include "common_types.h"
#include "error_codes.h"

namespace securevault {
namespace container {

// ============================================================================
// FORMAT V1 CONSTANTS
// ============================================================================

/// Magic bytes for format v1 containers
constexpr std::array<uint8_t, 8> CONTAINER_V1_MAGIC = {
    'S', 'V', 'C', 'T', 'R', '1', '\0', '\0'
};

/// Format v1 header size in bytes
constexpr size_t CONTAINER_V1_HEADER_SIZE = 512;

/// Format v1 version
constexpr uint32_t CONTAINER_V1_VERSION = 1;

/// Maximum container password length
constexpr size_t CONTAINER_MAX_PASSWORD_LENGTH = 256;

/// Maximum file name length within container
constexpr size_t CONTAINER_MAX_FILENAME_LENGTH = 4096;

/// Maximum number of files in a container
constexpr uint32_t CONTAINER_MAX_FILES = 1000000;

/// Default data block size (4 KB)
constexpr uint32_t CONTAINER_DEFAULT_BLOCK_SIZE = 4096;

// ============================================================================
// FORMAT V1 HEADER
// ============================================================================

/// Container header (fixed 512 bytes, stored at offset 0)
struct ContainerV1Header {
    /// Magic bytes: "SVCTR1\0\0"
    std::array<uint8_t, 8> magic = CONTAINER_V1_MAGIC;

    /// Format version (1)
    uint32_t version = CONTAINER_V1_VERSION;

    /// Container ID (16 bytes)
    std::array<uint8_t, 16> container_id{};

    /// Security level
    SecurityLevel security_level = SecurityLevel::CONTAINER;

    /// Key derivation algorithm
    KdfAlgorithm kdf_algorithm = KdfAlgorithm::ARGON2ID;

    /// KDF parameters (serialized)
    std::array<uint8_t, 64> kdf_params{};

    /// Key wrapping method:
    ///   0 = password-derived (KDF)
    ///   1 = RSA-OAEP wrapped
    uint32_t key_wrapping_method = 0;

    /// RSA key size in bits (if RSA wrapping)
    uint32_t rsa_key_bits = 0;

    /// Compression algorithm
    CompressionAlgorithm compression = CompressionAlgorithm::ZSTD;

    /// Whether deduplication is enabled
    uint32_t deduplication_enabled = 0;

    /// Whether WAL is enabled
    uint32_t wal_enabled = 1;

    /// Data block size in bytes
    uint32_t block_size = CONTAINER_DEFAULT_BLOCK_SIZE;

    /// Total container size in bytes
    DataSize total_size = 0;

    /// Used space in bytes
    DataSize used_size = 0;

    /// Number of files stored
    uint32_t file_count = 0;

    /// Container creation timestamp
    Timestamp created_at = 0;

    /// Last modification timestamp
    Timestamp modified_at = 0;

    /// Reserved for future use
    std::array<uint8_t, 128> reserved{};

    /// Header checksum (CRC32 of first 480 bytes)
    uint32_t header_checksum = 0;

    /// Serialize header to bytes
    /// @param output Output buffer (must be at least CONTAINER_V1_HEADER_SIZE)
    /// @return ErrorCode::SUCCESS on success
    ErrorCode serialize(MutableByteSpan output) const;

    /// Deserialize header from bytes
    /// @param input Input buffer (must be at least CONTAINER_V1_HEADER_SIZE)
    /// @return ErrorCode::SUCCESS on success
    ErrorCode deserialize(ByteSpan input);

    /// Validate header (magic, version, checksum)
    /// @return ErrorCode::SUCCESS if valid
    ErrorCode validate() const;

    /// Compute header checksum
    /// @return CRC32 checksum of the header
    uint32_t compute_checksum() const;
};

// ============================================================================
// FORMAT V1 KEY BLOB
// ============================================================================

/// Encrypted container key blob
struct ContainerV1KeyBlob {
    /// Key wrapping method (matches header)
    uint32_t wrapping_method = 0;

    /// Salt for KDF (16 bytes)
    std::array<uint8_t, 16> salt{};

    /// IV for key encryption (12 bytes)
    std::array<uint8_t, 12> iv{};

    /// Encrypted AES-256 key (32 bytes plaintext)
    /// For password: AES-256-GCM encrypted with KDF-derived key
    /// For RSA: RSA-OAEP encrypted
    std::vector<uint8_t> encrypted_key;

    /// Authentication tag (16 bytes)
    std::array<uint8_t, 16> tag{};

    /// Serialize key blob to bytes
    /// @param output Output byte array
    void serialize(ByteArray& output) const;

    /// Deserialize key blob from bytes
    /// @param input Input byte span
    /// @return ErrorCode::SUCCESS on success
    ErrorCode deserialize(ByteSpan input);
};

// ============================================================================
// FORMAT V1 DATA BLOCK
// ============================================================================

/// A single encrypted data block
struct ContainerV1DataBlock {
    /// Block index
    uint64_t index = 0;

    /// Original (uncompressed) size
    DataSize original_size = 0;

    /// Stored (compressed) size
    DataSize stored_size = 0;

    /// Compression algorithm used
    CompressionAlgorithm compression = CompressionAlgorithm::NONE;

    /// IV for this block (12 bytes)
    std::array<uint8_t, 12> iv{};

    /// Encrypted block data
    std::vector<uint8_t> data;

    /// Authentication tag (16 bytes)
    std::array<uint8_t, 16> tag{};

    /// SHA-256 hash of the original block (for deduplication)
    Sha256Digest content_hash{};
};

// ============================================================================
// FORMAT V1 FOOTER
// ============================================================================

/// Container footer (fixed 64 bytes, stored at end)
struct ContainerV1Footer {
    /// Magic bytes: "SVCTR1FT"
    std::array<uint8_t, 8> magic = {'S', 'V', 'C', 'T', 'R', '1', 'F', 'T'};

    /// HMAC-SHA256 of the entire container (header + key blob + metadata + data)
    std::array<uint8_t, 32> hmac{};

    /// Container ID (16 bytes)
    std::array<uint8_t, 16> container_id{};

    /// Reserved
    std::array<uint8_t, 8> reserved{};
};

// ============================================================================
// FORMAT V1 FILE ENTRY
// ============================================================================

/// File entry in the container metadata
struct ContainerV1FileEntry {
    /// File path within container
    std::string path;

    /// Original file size
    DataSize original_size = 0;

    /// Stored file size
    DataSize stored_size = 0;

    /// Compression algorithm
    CompressionAlgorithm compression = CompressionAlgorithm::NONE;

    /// List of data block indices
    std::vector<uint64_t> block_indices;

    /// SHA-256 hash of original file
    Sha256Digest original_hash{};

    /// File creation timestamp
    Timestamp created_at = 0;

    /// File modification timestamp
    Timestamp modified_at = 0;
};

} // namespace container
} // namespace securevault

#endif // SECUREVAULT_FORMAT_V1_H