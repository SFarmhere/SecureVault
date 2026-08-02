// ============================================================================
// SecureVault - AES-256-GCM Cipher Suite
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   AES-256-GCM authenticated encryption cipher suite.
//   Primary symmetric cipher for SecureVault.
// ============================================================================

#ifndef SECUREVAULT_AES256_GCM_H
#define SECUREVAULT_AES256_GCM_H

#include <cstdint>
#include <array>
#include <vector>

#include "common_types.h"
#include "error_codes.h"
#include "../aes.h"

namespace securevault {
namespace crypto {

// ============================================================================
// AES-256-GCM CIPHER SUITE
// ============================================================================

/// AES-256-GCM cipher suite identifier
constexpr CipherSuiteId AES256_GCM_SUITE_ID = CipherSuiteId::AES_256_GCM;

/// Encrypt with AES-256-GCM (convenience wrapper)
/// @param key 256-bit AES key
/// @param iv 12-byte GCM IV
/// @param plaintext Data to encrypt
/// @param aad Additional authenticated data
/// @return Result containing ciphertext + 16-byte tag
inline Result<ByteArray> aes256_gcm_encrypt(
    const Aes256Key& key,
    const AesGcmIv& iv,
    ByteSpan plaintext,
    ByteSpan aad = {}
) {
    ByteArray output(plaintext.size);
    AesGcmTag tag{};

    auto result = aes_256_gcm_encrypt(key, iv, plaintext, aad,
                                      MutableByteSpan(output), tag);
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(
            static_cast<int32_t>(result), "AES-256-GCM encryption failed");
    }

    // Append tag to ciphertext
    output.insert(output.end(), tag.begin(), tag.end());
    return Result<ByteArray>::ok(std::move(output));
}

/// Decrypt with AES-256-GCM (convenience wrapper)
/// @param key 256-bit AES key
/// @param iv 12-byte GCM IV
/// @param ciphertext Data to decrypt (includes 16-byte tag at end)
/// @param aad Additional authenticated data
/// @return Result containing plaintext
inline Result<ByteArray> aes256_gcm_decrypt(
    const Aes256Key& key,
    const AesGcmIv& iv,
    ByteSpan ciphertext,
    ByteSpan aad = {}
) {
    if (ciphertext.size < GCM_TAG_SIZE) {
        return Result<ByteArray>::fail(
            static_cast<int32_t>(ErrorCode::INVALID_ARGUMENT),
            "Ciphertext too short");
    }

    size_t data_size = ciphertext.size - GCM_TAG_SIZE;
    AesGcmTag tag{};
    std::copy(ciphertext.data + data_size,
              ciphertext.data + ciphertext.size,
              tag.begin());

    ByteArray output(data_size);
    auto result = aes_256_gcm_decrypt(key, iv,
                                      ByteSpan(ciphertext.data, data_size),
                                      aad, tag, MutableByteSpan(output));
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(
            static_cast<int32_t>(result), "AES-256-GCM decryption failed");
    }

    return Result<ByteArray>::ok(std::move(output));
}

} // namespace crypto
} // namespace securevault

#endif // SECUREVAULT_AES256_GCM_H