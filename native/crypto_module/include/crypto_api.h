// ============================================================================
// SecureVault - Crypto Module Public API
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Main public API for the cryptographic module.
//   Provides AES-256-GCM, ChaCha20-Poly1305, RSA, ECC, Kyber1024,
//   KDF (Argon2id, PBKDF2, scrypt), and side-channel protection.
// ============================================================================

#ifndef SECUREVAULT_CRYPTO_API_H
#define SECUREVAULT_CRYPTO_API_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>

#include "common_types.h"
#include "error_codes.h"
#include "platform.h"

#include "aes.h"
#include "rsa.h"
#include "cipher_suites/aes256_gcm.h"
#include "cipher_suites/chacha20_poly1305.h"
#include "cipher_suites/kyber1024.h"

namespace securevault {
namespace crypto {

// ============================================================================
// CRYPTO CONTEXT
// ============================================================================

class CryptoContext {
public:
    static ErrorCode initialize();
    static void shutdown();
    static bool is_initialized();
    static CryptoContext& instance();

    // ========================================================================
    // SYMMETRIC ENCRYPTION
    // ========================================================================

    Result<ByteArray> aes_gcm_encrypt(
        const Aes256Key& key,
        ByteSpan plaintext,
        ByteSpan aad = {}
    );

    Result<ByteArray> aes_gcm_decrypt(
        const Aes256Key& key,
        ByteSpan ciphertext,
        ByteSpan aad = {}
    );

    Result<ByteArray> chacha20_encrypt(
        const ChaCha20Key& key,
        ByteSpan plaintext,
        ByteSpan aad = {}
    );

    Result<ByteArray> chacha20_decrypt(
        const ChaCha20Key& key,
        ByteSpan ciphertext,
        ByteSpan aad = {}
    );

    // ========================================================================
    // ASYMMETRIC ENCRYPTION (RSA)
    // ========================================================================

    Result<RsaKeyPair> rsa_generate_keypair(uint32_t bits = 2048);

    Result<ByteArray> rsa_encrypt(
        const RsaPublicKey& public_key,
        ByteSpan plaintext
    );

    Result<ByteArray> rsa_decrypt(
        const RsaPrivateKey& private_key,
        ByteSpan ciphertext
    );

    Result<ByteArray> rsa_sign(
        const RsaPrivateKey& private_key,
        ByteSpan data,
        HashAlgorithm hash_algorithm = HashAlgorithm::SHA256
    );

    ErrorCode rsa_verify(
        const RsaPublicKey& public_key,
        ByteSpan data,
        ByteSpan signature,
        HashAlgorithm hash_algorithm = HashAlgorithm::SHA256
    );

    // ========================================================================
    // POST-QUANTUM (Kyber1024)
    // ========================================================================

    Result<KyberKeyPair> kyber_generate_keypair();

    Result<KyberEncapsulation> kyber_encapsulate(
        const Kyber1024PublicKey& public_key
    );

    Result<ByteArray> kyber_decapsulate(
        const Kyber1024SecretKey& private_key,
        ByteSpan ciphertext
    );

    // ========================================================================
    // KEY DERIVATION
    // ========================================================================

    Result<ByteArray> derive_argon2id(
        ByteSpan password,
        const Argon2Params& params
    );

    Result<ByteArray> derive_pbkdf2(
        ByteSpan password,
        const Pbkdf2Params& params
    );

    Result<ByteArray> derive_scrypt(
        ByteSpan password,
        const ScryptParams& params
    );

    // ========================================================================
    // HASHING
    // ========================================================================

    Result<ByteArray> hash(
        ByteSpan data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256
    );

    Result<ByteArray> hmac(
        ByteSpan key,
        ByteSpan data,
        HashAlgorithm algorithm = HashAlgorithm::SHA256
    );

    // ========================================================================
    // RANDOM NUMBER GENERATION
    // ========================================================================

    Result<ByteArray> random_bytes(size_t size);
    Aes256Key random_aes_key();
    AesGcmIv random_gcm_iv();

    CryptoContext() = default;
    ~CryptoContext() = default;

    CryptoContext(const CryptoContext&) = delete;
    CryptoContext& operator=(const CryptoContext&) = delete;

private:

    static std::unique_ptr<CryptoContext> instance_;
    static bool initialized_;
};

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

ErrorCode encrypt_file_aes_gcm(
    const std::string& input_path,
    const std::string& output_path,
    const Aes256Key& key
);

ErrorCode decrypt_file_aes_gcm(
    const std::string& input_path,
    const std::string& output_path,
    const Aes256Key& key
);

Result<Sha256Digest> hash_file_sha256(const std::string& file_path);

} // namespace crypto
} // namespace securevault

#endif // SECUREVAULT_CRYPTO_API_H