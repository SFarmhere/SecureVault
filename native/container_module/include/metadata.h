// ============================================================================
// SecureVault - Container Metadata
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Container metadata structures and serialization.
//   Metadata is stored encrypted inside the container and
//   authenticated with HMAC-SHA256.
// ============================================================================

#ifndef SECUREVAULT_CONTAINER_METADATA_H
#define SECUREVAULT_CONTAINER_METADATA_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <map>

#include "common_types.h"
#include "error_codes.h"

namespace securevault {
namespace container {

// ============================================================================
// METADATA CONSTANTS
// ============================================================================

/// Maximum metadata size (16 MB)
constexpr size_t CONTAINER_MAX_METADATA_SIZE = 16 * 1024 * 1024;

/// Metadata format version
constexpr uint32_t CONTAINER_METADATA_VERSION = 1;

// ============================================================================
// METADATA STRUCTURES
// ============================================================================

/// Container-level metadata
struct ContainerMetadata {
    /// Metadata format version
    uint32_t version = CONTAINER_METADATA_VERSION;

    /// Container ID
    std::array<uint8_t, 16> container_id{};

    /// Container format
    ContainerFormat format = ContainerFormat::V1;

    /// Security level
    SecurityLevel security_level = SecurityLevel::CONTAINER;

    /// Container creation timestamp
    Timestamp created_at = 0;

    /// Last modification timestamp
    Timestamp modified_at = 0;

    /// Total container size
    DataSize total_size = 0;

    /// Used space
    DataSize used_size = 0;

    /// Number of files
    uint32_t file_count = 0;

    /// Compression algorithm
    CompressionAlgorithm compression = CompressionAlgorithm::ZSTD;

    /// Whether deduplication is enabled
    bool deduplication_enabled = false;

    /// Whether WAL is enabled
    bool wal_enabled = true;

    /// Whether this is a hidden container (format v2)
    bool is_hidden = false;

    /// Custom metadata key-value pairs
    std::map<std::string, std::string> custom_fields;
};

/// File-level metadata within a container
struct ContainerFileMetadata {
    /// File path within container
    std::string path;

    /// Original file size
    DataSize original_size = 0;

    /// Stored (compressed + encrypted) size
    DataSize stored_size = 0;

    /// Compression algorithm used
    CompressionAlgorithm compression = CompressionAlgorithm::NONE;

    /// Whether the file is encrypted
    bool encrypted = true;

    /// File creation timestamp
    Timestamp created_at = 0;

    /// File modification timestamp
    Timestamp modified_at = 0;

    /// SHA-256 hash of original file
    Sha256Digest original_hash{};

    /// SHA-256 hash of stored file
    Sha256Digest stored_hash{};

    /// List of data block indices
    std::vector<uint64_t> block_indices;

    /// Custom file metadata
    std::map<std::string, std::string> custom_fields;
};

// ============================================================================
// METADATA SERIALIZATION
// ============================================================================

/// Serialize container metadata to JSON bytes
/// @param metadata Container metadata
/// @param output Output JSON bytes
/// @return ErrorCode::SUCCESS on success
ErrorCode serialize_container_metadata(
    const ContainerMetadata& metadata,
    ByteArray& output
);

/// Deserialize container metadata from JSON bytes
/// @param input Input JSON bytes
/// @param metadata Output container metadata
/// @return ErrorCode::SUCCESS on success
ErrorCode deserialize_container_metadata(
    ByteSpan input,
    ContainerMetadata& metadata
);

/// Serialize file metadata to JSON bytes
/// @param metadata File metadata
/// @param output Output JSON bytes
/// @return ErrorCode::SUCCESS on success
ErrorCode serialize_file_metadata(
    const ContainerFileMetadata& metadata,
    ByteArray& output
);

/// Deserialize file metadata from JSON bytes
/// @param input Input JSON bytes
/// @param metadata Output file metadata
/// @return ErrorCode::SUCCESS on success
ErrorCode deserialize_file_metadata(
    ByteSpan input,
    ContainerFileMetadata& metadata
);

/// Serialize a list of file metadata to JSON bytes
/// @param files List of file metadata
/// @param output Output JSON bytes
/// @return ErrorCode::SUCCESS on success
ErrorCode serialize_file_metadata_list(
    const std::vector<ContainerFileMetadata>& files,
    ByteArray& output
);

/// Deserialize a list of file metadata from JSON bytes
/// @param input Input JSON bytes
/// @param files Output list of file metadata
/// @return ErrorCode::SUCCESS on success
ErrorCode deserialize_file_metadata_list(
    ByteSpan input,
    std::vector<ContainerFileMetadata>& files
);

// ============================================================================
// METADATA ENCRYPTION
// ============================================================================

/// Encrypt metadata with AES-256-GCM
/// @param plaintext Plaintext metadata bytes
/// @param key 256-bit AES key
/// @param output Output encrypted bytes (IV + ciphertext + tag)
/// @return ErrorCode::SUCCESS on success
ErrorCode encrypt_metadata(
    ByteSpan plaintext,
    const Aes256Key& key,
    ByteArray& output
);

/// Decrypt metadata with AES-256-GCM
/// @param encrypted Encrypted metadata bytes (IV + ciphertext + tag)
/// @param key 256-bit AES key
/// @param output Output plaintext metadata bytes
/// @return ErrorCode::SUCCESS on success
ErrorCode decrypt_metadata(
    ByteSpan encrypted,
    const Aes256Key& key,
    ByteArray& output
);

} // namespace container
} // namespace securevault

#endif // SECUREVAULT_CONTAINER_METADATA_H