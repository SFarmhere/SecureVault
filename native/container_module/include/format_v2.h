// ============================================================================
// SecureVault - Container Format v2 (Hidden Containers)
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Hidden container format (v2) with plausible deniability.
//   Structure:
//     [Outer Header]   - Indistinguishable from random data
//     [Outer Data]     - Random data + encrypted inner container
//     [Inner Header]   - Hidden at a pseudo-random offset
//     [Inner Data]     - Double-encrypted file data
//
//   The outer container looks like random noise. Without the inner
//   password, it's impossible to prove a hidden container exists.
// ============================================================================

#ifndef SECUREVAULT_FORMAT_V2_H
#define SECUREVAULT_FORMAT_V2_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>

#include "common_types.h"
#include "error_codes.h"

namespace securevault {
namespace container {

// ============================================================================
// FORMAT V2 CONSTANTS
// ============================================================================

/// Magic bytes for format v2 containers (looks like random data)
constexpr std::array<uint8_t, 8> CONTAINER_V2_MAGIC = {
    0x8F, 0x3A, 0xC1, 0x5E, 0x2B, 0x94, 0x7D, 0x01
};

/// Format v2 version
constexpr uint32_t CONTAINER_V2_VERSION = 2;

/// Minimum hidden container size (64 MB)
constexpr DataSize CONTAINER_V2_MIN_SIZE = 64 * 1024 * 1024;

/// Hidden header size (4096 bytes, spread across the container)
constexpr size_t CONTAINER_V2_HIDDEN_HEADER_SIZE = 4096;

/// Number of candidate hidden header locations
constexpr uint32_t CONTAINER_V2_HEADER_CANDIDATES = 64;

// ============================================================================
// FORMAT V2 OUTER HEADER
// ============================================================================

/// Outer header (looks like random data, no magic detectable)
struct ContainerV2OuterHeader {
    /// Random-looking bytes (no detectable magic)
    std::array<uint8_t, 256> random_padding{};

    /// Outer container size
    DataSize total_size = 0;

    /// Number of hidden header candidates
    uint32_t header_candidates = CONTAINER_V2_HEADER_CANDIDATES;

    /// Reserved
    std::array<uint8_t, 128> reserved{};
};

// ============================================================================
// FORMAT V2 HIDDEN HEADER
// ============================================================================

/// Hidden header (encrypted, only discoverable with inner password)
struct ContainerV2HiddenHeader {
    /// Magic bytes (encrypted, not visible in raw container)
    std::array<uint8_t, 8> magic = CONTAINER_V2_MAGIC;

    /// Format version (2)
    uint32_t version = CONTAINER_V2_VERSION;

    /// Container ID (16 bytes)
    std::array<uint8_t, 16> container_id{};

    /// Inner container size
    DataSize inner_size = 0;

    /// Inner data offset
    DataSize inner_offset = 0;

    /// KDF algorithm for inner password
    KdfAlgorithm kdf_algorithm = KdfAlgorithm::ARGON2ID;

    /// KDF salt (16 bytes)
    std::array<uint8_t, 16> kdf_salt{};

    /// IV for inner header encryption (12 bytes)
    std::array<uint8_t, 12> iv{};

    /// Authentication tag (16 bytes)
    std::array<uint8_t, 16> tag{};

    /// Reserved
    std::array<uint8_t, 64> reserved{};
};

// ============================================================================
// FORMAT V2 ENCRYPTION
// ============================================================================

/// Encrypt the hidden header
/// @param header Hidden header to encrypt
/// @param password Inner password
/// @param output Output encrypted header bytes
/// @return ErrorCode::SUCCESS on success
ErrorCode encrypt_hidden_header(
    const ContainerV2HiddenHeader& header,
    const std::string& password,
    ByteArray& output
);

/// Decrypt the hidden header
/// @param encrypted_header Encrypted header bytes
/// @param password Inner password
/// @param header Output decrypted header
/// @return ErrorCode::SUCCESS on success, TAG_MISMATCH if wrong password
ErrorCode decrypt_hidden_header(
    ByteSpan encrypted_header,
    const std::string& password,
    ContainerV2HiddenHeader& header
);

/// Find the hidden header location in a container
/// @param container_data Container file data
/// @param password Inner password
/// @param header_offset Output found header offset
/// @return ErrorCode::SUCCESS if found, HIDDEN_CONTAINER_NOT_FOUND otherwise
ErrorCode find_hidden_header(
    ByteSpan container_data,
    const std::string& password,
    DataSize& header_offset
);

/// Generate random-looking padding for the outer container
/// @param size Number of bytes to generate
/// @param output Output random bytes
/// @return ErrorCode::SUCCESS on success
ErrorCode generate_outer_padding(
    size_t size,
    ByteArray& output
);

} // namespace container
} // namespace securevault

#endif // SECUREVAULT_FORMAT_V2_H