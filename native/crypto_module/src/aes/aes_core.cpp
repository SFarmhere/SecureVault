// ============================================================================
// SecureVault - AES-256-GCM Implementation
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   AES-256-GCM authenticated encryption using OpenSSL EVP API.
//   Uses hardware AES-NI acceleration when available (via OpenSSL).
//   All operations are constant-time (OpenSSL guarantees this).
// ============================================================================

#include "aes.h"
#include "logging.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <cstring>

namespace securevault {
namespace crypto {

// ============================================================================
// CONSTANT-TIME COMPARISON
// ============================================================================

bool constant_time_equals(const uint8_t* a, const uint8_t* b, size_t length) {
    if (!a || !b) return false;

    uint8_t diff = 0;
    for (size_t i = 0; i < length; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

// ============================================================================
// AES-256-GCM ENCRYPTION
// ============================================================================

ErrorCode aes_256_gcm_encrypt(
    const Aes256Key& key,
    const AesGcmIv& iv,
    ByteSpan plaintext,
    ByteSpan aad,
    MutableByteSpan output,
    AesGcmTag& tag
) {
    if (output.size < plaintext.size) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ErrorCode::ENCRYPTION_FAILED;
    }

    int len = 0;
    int total_len = 0;

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    // Set IV length (12 bytes for GCM)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    // Provide AAD if present
    if (aad.size > 0) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data, static_cast<int>(aad.size)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::ENCRYPTION_FAILED;
        }
    }

    // Encrypt plaintext
    if (plaintext.size > 0) {
        if (EVP_EncryptUpdate(ctx, output.data, &len,
                              plaintext.data, static_cast<int>(plaintext.size)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::ENCRYPTION_FAILED;
        }
        total_len = len;
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, output.data + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }
    total_len += len;

    // Get authentication tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ErrorCode::SUCCESS;
}

// ============================================================================
// AES-256-GCM DECRYPTION
// ============================================================================

ErrorCode aes_256_gcm_decrypt(
    const Aes256Key& key,
    const AesGcmIv& iv,
    ByteSpan ciphertext,
    ByteSpan aad,
    const AesGcmTag& tag,
    MutableByteSpan output
) {
    if (output.size < ciphertext.size) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ErrorCode::DECRYPTION_FAILED;
    }

    int len = 0;
    int total_len = 0;

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }

    // Provide AAD if present
    if (aad.size > 0) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data, static_cast<int>(aad.size)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::DECRYPTION_FAILED;
        }
    }

    // Decrypt ciphertext
    if (ciphertext.size > 0) {
        if (EVP_DecryptUpdate(ctx, output.data, &len,
                              ciphertext.data, static_cast<int>(ciphertext.size)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::DECRYPTION_FAILED;
        }
        total_len = len;
    }

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_SIZE,
                            const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }

    // Finalize decryption (verifies tag)
    int ret = EVP_DecryptFinal_ex(ctx, output.data + total_len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        // Authentication failed
        return ErrorCode::TAG_MISMATCH;
    }

    return ErrorCode::SUCCESS;
}

// ============================================================================
// AES-256-CBC (legacy, for container format v1)
// ============================================================================

ErrorCode aes_256_cbc_encrypt(
    const Aes256Key& key,
    const std::array<uint8_t, 16>& iv,
    ByteSpan plaintext,
    MutableByteSpan output
) {
    // PKCS#7 padding: output size = plaintext + (16 - plaintext % 16)
    size_t padded_size = ((plaintext.size / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
    if (output.size < padded_size) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ErrorCode::ENCRYPTION_FAILED;

    int len = 0;
    int total_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    if (EVP_EncryptUpdate(ctx, output.data, &len,
                          plaintext.data, static_cast<int>(plaintext.size)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }
    total_len = len;

    if (EVP_EncryptFinal_ex(ctx, output.data + total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ErrorCode::SUCCESS;
}

ErrorCode aes_256_cbc_decrypt(
    const Aes256Key& key,
    const std::array<uint8_t, 16>& iv,
    ByteSpan ciphertext,
    MutableByteSpan output
) {
    if (ciphertext.size % AES_BLOCK_SIZE != 0) {
        return ErrorCode::INVALID_ARGUMENT;
    }
    if (output.size < ciphertext.size) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ErrorCode::DECRYPTION_FAILED;

    int len = 0;
    int total_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }

    if (EVP_DecryptUpdate(ctx, output.data, &len,
                          ciphertext.data, static_cast<int>(ciphertext.size)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }
    total_len = len;

    int ret = EVP_DecryptFinal_ex(ctx, output.data + total_len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        return ErrorCode::PADDING_INVALID;
    }

    return ErrorCode::SUCCESS;
}

// ============================================================================
// AES KEY SCHEDULE
// ============================================================================

ErrorCode aes_256_expand_key(
    const Aes256Key& key,
    Aes256ExpandedKey& expanded_key
) {
    // Use OpenSSL to expand the key
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return ErrorCode::KEY_EXPAND_FAILED;

    // Initialize with the key to trigger key expansion
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), nullptr, key.data(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::KEY_EXPAND_FAILED;
    }

    // Copy the expanded key from the context
    // Note: OpenSSL doesn't expose the raw key schedule directly,
    // so we use the context's internal key data
    const AES_KEY* aes_key = static_cast<const AES_KEY*>(
        EVP_CIPHER_CTX_get_cipher_data(ctx));
    if (aes_key) {
        std::memcpy(expanded_key.round_keys.data(), aes_key->rd_key,
                    AES_256_EXPANDED_KEY_SIZE);
    }

    EVP_CIPHER_CTX_free(ctx);
    return ErrorCode::SUCCESS;
}

} // namespace crypto
} // namespace securevault