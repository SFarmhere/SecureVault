// ============================================================================
// SecureVault - AES-256 Encryption
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   AES-256 encryption with GCM mode (authenticated encryption).
//   Uses hardware AES-NI acceleration when available.
//   All operations are constant-time to prevent side-channel attacks.
// ============================================================================

#ifndef SECUREVAULT_AES_H
#define SECUREVAULT_AES_H

#include <cstdint>
#include <array>
#include <vector>

#include "common_types.h"
#include "error_codes.h"

namespace securevault {
namespace crypto {

// ============================================================================
// AES-256-GCM CONSTANTS
// ============================================================================

/// AES block size in bytes
constexpr size_t AES_BLOCK_SIZE = 16;

/// AES-256 key size in bytes
constexpr size_t AES_256_KEY_SIZE = 32;

/// GCM IV size in bytes (recommended 12)
constexpr size_t GCM_IV_SIZE = 12;

/// GCM authentication tag size in bytes
constexpr size_t GCM_TAG_SIZE = 16;

// ============================================================================
// AES-256-GCM ENCRYPTION
// ============================================================================

/// Encrypt data with AES-256-GCM
/// @param key 256-bit AES key
/// @param iv 12-byte GCM IV/nonce
/// @param plaintext Data to encrypt
/// @param aad Additional authenticated data (optional)
/// @param output Output buffer for ciphertext (size = plaintext.size())
/// @param tag Output buffer for 16-byte authentication tag
/// @return ErrorCode::SUCCESS on success
ErrorCode aes_256_gcm_encrypt(
    const Aes256Key& key,
    const AesGcmIv& iv,
    ByteSpan plaintext,
    ByteSpan aad,
    MutableByteSpan output,
    AesGcmTag& tag
);

/// Decrypt data with AES-256-GCM
/// @param key 256-bit AES key
/// @param iv 12-byte GCM IV/nonce
/// @param ciphertext Data to decrypt
/// @param aad Additional authenticated data (optional)
/// @param tag 16-byte authentication tag
/// @param output Output buffer for plaintext (size = ciphertext.size())
/// @return ErrorCode::SUCCESS on success, TAG_MISMATCH if authentication fails
ErrorCode aes_256_gcm_decrypt(
    const Aes256Key& key,
    const AesGcmIv& iv,
    ByteSpan ciphertext,
    ByteSpan aad,
    const AesGcmTag& tag,
    MutableByteSpan output
);

// ============================================================================
// AES-256-CBC (legacy, for container format v1 compatibility)
// ============================================================================

/// Encrypt data with AES-256-CBC (PKCS#7 padding)
/// @param key 256-bit AES key
/// @param iv 16-byte CBC IV
/// @param plaintext Data to encrypt
/// @param output Output buffer (size = plaintext.size() + 16)
/// @return ErrorCode::SUCCESS on success
ErrorCode aes_256_cbc_encrypt(
    const Aes256Key& key,
    const std::array<uint8_t, 16>& iv,
    ByteSpan plaintext,
    MutableByteSpan output
);

/// Decrypt data with AES-256-CBC (PKCS#7 padding)
/// @param key 256-bit AES key
/// @param iv 16-byte CBC IV
/// @param ciphertext Data to decrypt
/// @param output Output buffer (size = ciphertext.size())
/// @return ErrorCode::SUCCESS on success
ErrorCode aes_256_cbc_decrypt(
    const Aes256Key& key,
    const std::array<uint8_t, 16>& iv,
    ByteSpan ciphertext,
    MutableByteSpan output
);

// ============================================================================
// AES KEY SCHEDULE
// ============================================================================

/// Number of rounds for AES-256
constexpr size_t AES_256_ROUNDS = 14;

/// Expanded key size (rounds + 1) * block_size
constexpr size_t AES_256_EXPANDED_KEY_SIZE = (AES_256_ROUNDS + 1) * AES_BLOCK_SIZE;

/// Expanded AES-256 key schedule
struct Aes256ExpandedKey {
    std::array<uint8_t, AES_256_EXPANDED_KEY_SIZE> round_keys{};
};

/// Expand a 256-bit AES key into the key schedule
/// @param key 256-bit AES key
/// @param expanded_key Output expanded key schedule
/// @return ErrorCode::SUCCESS on success
ErrorCode aes_256_expand_key(
    const Aes256Key& key,
    Aes256ExpandedKey& expanded_key
);

// ============================================================================
// CONSTANT-TIME COMPARISON
// ============================================================================

/// Constant-time comparison of two byte arrays
/// @param a First array
/// @param b Second array
/// @param length Number of bytes to compare
/// @return true if all bytes are equal
bool constant_time_equals(
    const uint8_t* a,
    const uint8_t* b,
    size_t length
);

} // namespace crypto
} // namespace securevault

#endif // SECUREVAULT_AES_H