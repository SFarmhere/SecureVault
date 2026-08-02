// ============================================================================
// SecureVault - Container Module Public API
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Main public API for the encrypted container module.
//   Provides virtual encrypted containers (format v1/v2) with:
//     - AES-256-GCM file encryption
//     - RSA key wrapping
//     - Content-defined chunking (CDC) deduplication
//     - Write-Ahead Log (WAL) for crash recovery
//     - Plausible deniability (hidden containers, format v2)
//     - Automatic garbage collection
//     - Compression (LZ4, Zstandard)
//
// DESIGN:
//   - All operations go through the ContainerManager singleton
//   - Containers are identified by ContainerId
//   - All file operations are transactional (WAL)
//   - All metadata is authenticated (HMAC-SHA256)
// ============================================================================

#ifndef SECUREVAULT_CONTAINER_API_H
#define SECUREVAULT_CONTAINER_API_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <filesystem>

#include "common_types.h"
#include "error_codes.h"
#include "platform.h"
#include "crypto_api.h"

#include "format_v1.h"
#include "format_v2.h"
#include "metadata.h"

namespace securevault {
namespace container {

// ============================================================================
// CONTAINER IDENTIFIER
// ============================================================================

/// Unique container identifier (128-bit)
struct ContainerId {
    /// Raw 16-byte identifier
    std::array<uint8_t, 16> bytes{};

    /// Generate a new random container ID
    static ContainerId generate();

    /// Convert to hex string
    std::string to_hex() const;

    /// Parse from hex string
    static std::optional<ContainerId> from_hex(const std::string& hex);

    /// Compare for equality
    bool operator==(const ContainerId& other) const {
        return bytes == other.bytes;
    }
    bool operator!=(const ContainerId& other) const {
        return bytes != other.bytes;
    }
};

// ============================================================================
// CONTAINER OPTIONS
// ============================================================================

/// Options for creating a new container
struct ContainerCreateOptions {
    /// Container format version
    ContainerFormat format = ContainerFormat::V1;

    /// Security level
    SecurityLevel security_level = SecurityLevel::CONTAINER;

    /// Container size in bytes
    DataSize size = 0;

    /// Compression algorithm
    CompressionAlgorithm compression = CompressionAlgorithm::ZSTD;

    /// Enable content-defined chunking deduplication
    bool enable_deduplication = true;

    /// Enable Write-Ahead Log for crash recovery
    bool enable_wal = true;

    /// Enable automatic garbage collection
    bool enable_gc = true;

    /// Chunk size for deduplication (default: 4 KB)
    uint32_t chunk_size = 4096;

    /// Minimum chunk size (CDC)
    uint32_t min_chunk_size = 2048;

    /// Maximum chunk size (CDC)
    uint32_t max_chunk_size = 8192;

    /// RSA key size for key wrapping (2048 or 4096)
    uint32_t rsa_key_bits = 2048;

    /// Password for container encryption
    std::string password;

    /// Optional RSA public key for key wrapping
    std::optional<crypto::RsaPublicKey> wrapping_key;
};

/// Options for opening an existing container
struct ContainerOpenOptions {
    /// Password for container decryption
    std::string password;

    /// Optional RSA private key for key unwrapping
    std::optional<crypto::RsaPrivateKey> unwrapping_key;

    /// Open in read-only mode
    bool read_only = false;

    /// Recover from WAL on open
    bool recover_on_open = true;
};

// ============================================================================
// CONTAINER STATUS
// ============================================================================

/// Current status of a container
struct ContainerStatus {
    /// Container ID
    ContainerId id;

    /// Container format
    ContainerFormat format = ContainerFormat::V1;

    /// Security level
    SecurityLevel security_level = SecurityLevel::CONTAINER;

    /// Total container size
    DataSize total_size = 0;

    /// Used space
    DataSize used_size = 0;

    /// Number of files stored
    uint32_t file_count = 0;

    /// Whether the container is open
    bool is_open = false;

    /// Whether the container is read-only
    bool is_read_only = false;

    /// Whether the container is hidden (format v2)
    bool is_hidden = false;

    /// Whether deduplication is enabled
    bool deduplication_enabled = false;

    /// Whether WAL is enabled
    bool wal_enabled = false;

    /// Number of pending WAL entries
    uint32_t pending_wal_entries = 0;

    /// Last error message
    std::string last_error;

    /// Container creation time
    Timestamp created_at = 0;

    /// Last modification time
    Timestamp modified_at = 0;
};

// ============================================================================
// CONTAINER MANAGER
// ============================================================================

/// Main container management class
class ContainerManager {
public:
    /// Get the singleton instance
    static ContainerManager& instance();

    /// Initialize the container module
    /// @return ErrorCode::SUCCESS on success
    static ErrorCode initialize();

    /// Shutdown the container module
    static void shutdown();

    // ========================================================================
    // CONTAINER LIFECYCLE
    // ========================================================================

    /// Create a new container
    /// @param path Path to the container file
    /// @param options Container creation options
    /// @param container_id Output container ID
    /// @return ErrorCode::SUCCESS on success
    ErrorCode create_container(
        const std::filesystem::path& path,
        const ContainerCreateOptions& options,
        ContainerId& container_id
    );

    /// Open an existing container
    /// @param path Path to the container file
    /// @param options Container open options
    /// @return ErrorCode::SUCCESS on success
    ErrorCode open_container(
        const std::filesystem::path& path,
        const ContainerOpenOptions& options
    );

    /// Close an open container
    /// @param container_id Container to close
    /// @return ErrorCode::SUCCESS on success
    ErrorCode close_container(const ContainerId& container_id);

    /// Delete a container file
    /// @param path Path to the container file
    /// @param secure_wipe Whether to securely wipe the file first
    /// @return ErrorCode::SUCCESS on success
    ErrorCode delete_container(
        const std::filesystem::path& path,
        bool secure_wipe = true
    );

    /// Get container status
    /// @param container_id Container to query
    /// @return Optional ContainerStatus if container exists
    std::optional<ContainerStatus> get_status(const ContainerId& container_id) const;

    /// List all open containers
    /// @return Vector of container IDs
    std::vector<ContainerId> list_open_containers() const;

    // ========================================================================
    // FILE OPERATIONS
    // ========================================================================

    /// Add a file to a container
    /// @param container_id Target container
    /// @param source_path Path to the source file
    /// @param target_path Path within the container
    /// @return ErrorCode::SUCCESS on success
    ErrorCode add_file(
        const ContainerId& container_id,
        const std::filesystem::path& source_path,
        const std::filesystem::path& target_path
    );

    /// Extract a file from a container
    /// @param container_id Source container
    /// @param container_path Path within the container
    /// @param target_path Path to write the extracted file
    /// @return ErrorCode::SUCCESS on success
    ErrorCode extract_file(
        const ContainerId& container_id,
        const std::filesystem::path& container_path,
        const std::filesystem::path& target_path
    );

    /// Delete a file from a container
    /// @param container_id Target container
    /// @param container_path Path within the container
    /// @return ErrorCode::SUCCESS on success
    ErrorCode delete_file(
        const ContainerId& container_id,
        const std::filesystem::path& container_path
    );

    /// Rename a file within a container
    /// @param container_id Target container
    /// @param old_path Current path within the container
    /// @param new_path New path within the container
    /// @return ErrorCode::SUCCESS on success
    ErrorCode rename_file(
        const ContainerId& container_id,
        const std::filesystem::path& old_path,
        const std::filesystem::path& new_path
    );

    /// List files in a container
    /// @param container_id Container to list
    /// @param directory Directory within the container (empty = root)
    /// @return Result containing list of file metadata
    Result<std::vector<FileMetadata>> list_files(
        const ContainerId& container_id,
        const std::filesystem::path& directory = ""
    );

    /// Check if a file exists in a container
    /// @param container_id Container to check
    /// @param container_path Path within the container
    /// @return true if the file exists
    bool file_exists(
        const ContainerId& container_id,
        const std::filesystem::path& container_path
    ) const;

    // ========================================================================
    // CONTAINER MAINTENANCE
    // ========================================================================

    /// Run garbage collection on a container
    /// @param container_id Container to clean
    /// @return ErrorCode::SUCCESS on success
    ErrorCode run_garbage_collection(const ContainerId& container_id);

    /// Check container integrity
    /// @param container_id Container to check
    /// @return ErrorCode::SUCCESS if intact, error code otherwise
    ErrorCode check_integrity(const ContainerId& container_id);

    /// Recover container from WAL
    /// @param container_id Container to recover
    /// @return ErrorCode::SUCCESS on success
    ErrorCode recover_from_wal(const ContainerId& container_id);

    /// Compact a container (remove unused space)
    /// @param container_id Container to compact
    /// @return ErrorCode::SUCCESS on success
    ErrorCode compact(const ContainerId& container_id);

    /// Change container password
    /// @param container_id Container to update
    /// @param old_password Current password
    /// @param new_password New password
    /// @return ErrorCode::SUCCESS on success
    ErrorCode change_password(
        const ContainerId& container_id,
        const std::string& old_password,
        const std::string& new_password
    );

    // ========================================================================
    // HIDDEN CONTAINERS (FORMAT V2)
    // ========================================================================

    /// Create a hidden container (plausible deniability)
    /// @param outer_path Path to the outer container file
    /// @param outer_password Password for the outer container
    /// @param inner_password Password for the hidden inner container
    /// @param inner_size Size of the hidden container
    /// @param container_id Output container ID
    /// @return ErrorCode::SUCCESS on success
    ErrorCode create_hidden_container(
        const std::filesystem::path& outer_path,
        const std::string& outer_password,
        const std::string& inner_password,
        DataSize inner_size,
        ContainerId& container_id
    );

    /// Open a hidden container
    /// @param outer_path Path to the outer container file
    /// @param inner_password Password for the hidden inner container
    /// @return ErrorCode::SUCCESS on success
    ErrorCode open_hidden_container(
        const std::filesystem::path& outer_path,
        const std::string& inner_password
    );

private:
    ContainerManager() = default;
    ~ContainerManager() = default;

    ContainerManager(const ContainerManager&) = delete;
    ContainerManager& operator=(const ContainerManager&) = delete;

    static std::unique_ptr<ContainerManager> instance_;
    static bool initialized_;
};

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Create a container and add files in one call
/// @param path Container file path
/// @param options Container creation options
/// @param files Map of source paths to container paths
/// @return ErrorCode::SUCCESS on success
ErrorCode create_container_with_files(
    const std::filesystem::path& path,
    const ContainerCreateOptions& options,
    const std::vector<std::pair<std::filesystem::path, std::filesystem::path>>& files
);

/// Extract all files from a container to a directory
/// @param container_path Container file path
/// @param password Container password
/// @param output_dir Directory to extract to
/// @return ErrorCode::SUCCESS on success
ErrorCode extract_all_files(
    const std::filesystem::path& container_path,
    const std::string& password,
    const std::filesystem::path& output_dir
);

} // namespace container
} // namespace securevault

#endif // SECUREVAULT_CONTAINER_API_H