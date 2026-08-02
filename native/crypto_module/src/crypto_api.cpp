// ============================================================================
// SecureVault - Crypto Module Implementation
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Implementation of the CryptoContext singleton and convenience functions.
//   Provides the main entry point for all cryptographic operations.
// ============================================================================

#include "crypto_api.h"
#include "logging.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <fstream>
#include <iterator>

namespace securevault {
namespace crypto {

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::unique_ptr<CryptoContext> CryptoContext::instance_ = nullptr;
bool CryptoContext::initialized_ = false;

// ============================================================================
// INITIALIZATION
// ============================================================================

ErrorCode CryptoContext::initialize() {
    if (initialized_) {
        return ErrorCode::SUCCESS;
    }

    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS |
                        OPENSSL_INIT_ADD_ALL_CIPHERS |
                        OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);

    instance_ = std::unique_ptr<CryptoContext>(new CryptoContext());
    initialized_ = true;

    LOG_INFO("crypto", "context", "Crypto module initialized (OpenSSL {})",
             OpenSSL_version(OPENSSL_VERSION));

    return ErrorCode::SUCCESS;
}

void CryptoContext::shutdown() {
    if (!initialized_) return;

    instance_.reset();
    initialized_ = false;

    LOG_INFO("crypto", "context", "Crypto module shutdown complete");
}

bool CryptoContext::is_initialized() {
    return initialized_;
}

CryptoContext& CryptoContext::instance() {
    if (!initialized_) {
        initialize();
    }
    return *instance_;
}

// ============================================================================
// SYMMETRIC ENCRYPTION
// ============================================================================

Result<ByteArray> CryptoContext::aes_gcm_encrypt(
    const Aes256Key& key,
    ByteSpan plaintext,
    ByteSpan aad
) {
    auto iv = random_gcm_iv();
    ByteArray output(plaintext.size + GCM_TAG_SIZE);
    AesGcmTag tag{};

    auto result = aes_256_gcm_encrypt(key, iv, plaintext, aad,
                                      MutableByteSpan(output.data(), plaintext.size),
                                      tag);
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(static_cast<int32_t>(result),
                                       "AES-256-GCM encryption failed");
    }

    // Append IV and tag to output
    output.resize(plaintext.size + GCM_TAG_SIZE);
    std::copy(tag.begin(), tag.end(), output.begin() + plaintext.size);

    // Prepend IV for self-contained format
    ByteArray final_output;
    final_output.reserve(GCM_IV_SIZE + output.size());
    final_output.insert(final_output.end(), iv.begin(), iv.end());
    final_output.insert(final_output.end(), output.begin(), output.end());

    return Result<ByteArray>::ok(std::move(final_output));
}

Result<ByteArray> CryptoContext::aes_gcm_decrypt(
    const Aes256Key& key,
    ByteSpan ciphertext,
    ByteSpan aad
) {
    if (ciphertext.size < GCM_IV_SIZE + GCM_TAG_SIZE) {
        return Result<ByteArray>::fail(static_cast<int32_t>(ErrorCode::INVALID_ARGUMENT),
                                       "Ciphertext too short");
    }

    // Extract IV (first 12 bytes)
    AesGcmIv iv{};
    std::copy(ciphertext.data, ciphertext.data + GCM_IV_SIZE, iv.begin());

    // Extract tag (last 16 bytes)
    AesGcmTag tag{};
    std::copy(ciphertext.data + ciphertext.size - GCM_TAG_SIZE,
              ciphertext.data + ciphertext.size, tag.begin());

    // Decrypt data (between IV and tag)
    size_t data_size = ciphertext.size - GCM_IV_SIZE - GCM_TAG_SIZE;
    ByteArray output(data_size);

    auto result = aes_256_gcm_decrypt(key, iv,
                                      ByteSpan(ciphertext.data + GCM_IV_SIZE, data_size),
                                      aad, tag, MutableByteSpan(output));
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(static_cast<int32_t>(result),
                                       "AES-256-GCM decryption failed");
    }

    return Result<ByteArray>::ok(std::move(output));
}

Result<ByteArray> CryptoContext::chacha20_encrypt(
    const ChaCha20Key& key,
    ByteSpan plaintext,
    ByteSpan aad
) {
    // Generate random nonce
    ChaCha20Nonce nonce{};
    auto random_result = random_bytes(CHACHA20_NONCE_SIZE);
    if (!random_result.success) {
        return random_result;
    }
    std::copy(random_result.value.begin(), random_result.value.end(), nonce.begin());

    ByteArray output(plaintext.size + POLY1305_TAG_SIZE);
    Poly1305Tag tag{};

    auto result = chacha20_poly1305_encrypt(key, nonce, plaintext, aad,
                                            MutableByteSpan(output.data(), plaintext.size),
                                            tag);
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(static_cast<int32_t>(result),
                                       "ChaCha20-Poly1305 encryption failed");
    }

    // Append tag
    std::copy(tag.begin(), tag.end(), output.begin() + plaintext.size);

    // Prepend nonce
    ByteArray final_output;
    final_output.reserve(CHACHA20_NONCE_SIZE + output.size());
    final_output.insert(final_output.end(), nonce.begin(), nonce.end());
    final_output.insert(final_output.end(), output.begin(), output.end());

    return Result<ByteArray>::ok(std::move(final_output));
}

Result<ByteArray> CryptoContext::chacha20_decrypt(
    const ChaCha20Key& key,
    ByteSpan ciphertext,
    ByteSpan aad
) {
    if (ciphertext.size < CHACHA20_NONCE_SIZE + POLY1305_TAG_SIZE) {
        return Result<ByteArray>::fail(static_cast<int32_t>(ErrorCode::INVALID_ARGUMENT),
                                       "Ciphertext too short");
    }

    // Extract nonce (first 12 bytes)
    ChaCha20Nonce nonce{};
    std::copy(ciphertext.data, ciphertext.data + CHACHA20_NONCE_SIZE, nonce.begin());

    // Extract tag (last 16 bytes)
    Poly1305Tag tag{};
    std::copy(ciphertext.data + ciphertext.size - POLY1305_TAG_SIZE,
              ciphertext.data + ciphertext.size, tag.begin());

    // Decrypt data
    size_t data_size = ciphertext.size - CHACHA20_NONCE_SIZE - POLY1305_TAG_SIZE;
    ByteArray output(data_size);

    auto result = chacha20_poly1305_decrypt(key, nonce,
                                            ByteSpan(ciphertext.data + CHACHA20_NONCE_SIZE, data_size),
                                            aad, tag, MutableByteSpan(output));
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(static_cast<int32_t>(result),
                                       "ChaCha20-Poly1305 decryption failed");
    }

    return Result<ByteArray>::ok(std::move(output));
}

// ============================================================================
// ASYMMETRIC ENCRYPTION (RSA)
// ============================================================================

Result<RsaKeyPair> CryptoContext::rsa_generate_keypair(uint32_t bits) {
    RsaKeyPair key_pair;
    // Qualify the call to bypass name hiding: the member function
    // CryptoContext::rsa_generate_keypair(uint32_t) hides the namespace-level
    // free function rsa_generate_keypair(uint32_t, RsaKeyPair&) declared in rsa.h.
    auto result = ::securevault::crypto::rsa_generate_keypair(bits, key_pair);
    if (result != ErrorCode::SUCCESS) {
        return Result<RsaKeyPair>::fail(static_cast<int32_t>(result),
                                        "RSA key generation failed");
    }
    return Result<RsaKeyPair>::ok(std::move(key_pair));
}

Result<ByteArray> CryptoContext::rsa_encrypt(
    const RsaPublicKey& public_key,
    ByteSpan plaintext
) {
    ByteArray ciphertext(public_key.bits / 8);
    auto result = rsa_encrypt_oaep(public_key, plaintext, MutableByteSpan(ciphertext));
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(static_cast<int32_t>(result),
                                       "RSA encryption failed");
    }
    return Result<ByteArray>::ok(std::move(ciphertext));
}

Result<ByteArray> CryptoContext::rsa_decrypt(
    const RsaPrivateKey& private_key,
    ByteSpan ciphertext
) {
    ByteArray plaintext(private_key.bits / 8);
    auto result = rsa_decrypt_oaep(private_key, ciphertext, MutableByteSpan(plaintext));
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(static_cast<int32_t>(result),
                                       "RSA decryption failed");
    }
    return Result<ByteArray>::ok(std::move(plaintext));
}

Result<ByteArray> CryptoContext::rsa_sign(
    const RsaPrivateKey& private_key,
    ByteSpan data,
    HashAlgorithm hash_algorithm
) {
    ByteArray signature(private_key.bits / 8);
    auto result = rsa_sign_pss(private_key, data, MutableByteSpan(signature));
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(static_cast<int32_t>(result),
                                       "RSA signing failed");
    }
    return Result<ByteArray>::ok(std::move(signature));
}

ErrorCode CryptoContext::rsa_verify(
    const RsaPublicKey& public_key,
    ByteSpan data,
    ByteSpan signature,
    HashAlgorithm hash_algorithm
) {
    return rsa_verify_pss(public_key, data, signature);
}

// ============================================================================
// POST-QUANTUM (Kyber1024)
// ============================================================================

Result<KyberKeyPair> CryptoContext::kyber_generate_keypair() {
    KyberKeyPair key_pair;
    auto result = kyber1024_generate_keypair(key_pair);
    if (result != ErrorCode::SUCCESS) {
        return Result<KyberKeyPair>::fail(static_cast<int32_t>(result),
                                          "Kyber1024 key generation failed");
    }
    return Result<KyberKeyPair>::ok(std::move(key_pair));
}

Result<KyberEncapsulation> CryptoContext::kyber_encapsulate(
    const Kyber1024PublicKey& public_key
) {
    KyberEncapsulation encapsulation;
    auto result = kyber1024_encapsulate(public_key, encapsulation);
    if (result != ErrorCode::SUCCESS) {
        return Result<KyberEncapsulation>::fail(static_cast<int32_t>(result),
                                                "Kyber1024 encapsulation failed");
    }
    return Result<KyberEncapsulation>::ok(std::move(encapsulation));
}

Result<ByteArray> CryptoContext::kyber_decapsulate(
    const Kyber1024SecretKey& private_key,
    ByteSpan ciphertext
) {
    if (ciphertext.size != KYBER1024_CIPHERTEXT_SIZE) {
        return Result<ByteArray>::fail(static_cast<int32_t>(ErrorCode::INVALID_ARGUMENT),
                                       "Invalid Kyber1024 ciphertext size");
    }

    Kyber1024Ciphertext ct{};
    std::copy(ciphertext.data, ciphertext.data + KYBER1024_CIPHERTEXT_SIZE, ct.begin());

    std::array<uint8_t, KYBER1024_SHARED_SECRET_SIZE> shared_secret{};
    auto result = kyber1024_decapsulate(private_key, ct, shared_secret);
    if (result != ErrorCode::SUCCESS) {
        return Result<ByteArray>::fail(static_cast<int32_t>(result),
                                       "Kyber1024 decapsulation failed");
    }

    ByteArray output(shared_secret.begin(), shared_secret.end());
    return Result<ByteArray>::ok(std::move(output));
}

// ============================================================================
// KEY DERIVATION
// ============================================================================

Result<ByteArray> CryptoContext::derive_argon2id(
    ByteSpan password,
    const Argon2Params& params
) {
    // Argon2id implementation would go here
    // For now, return NOT_IMPLEMENTED
    return Result<ByteArray>::fail(static_cast<int32_t>(ErrorCode::NOT_IMPLEMENTED),
                                   "Argon2id not yet implemented");
}

Result<ByteArray> CryptoContext::derive_pbkdf2(
    ByteSpan password,
    const Pbkdf2Params& params
) {
    ByteArray output(params.hash_length);

    const EVP_MD* md = EVP_sha256();
    if (params.hash_algorithm == HashAlgorithm::SHA384) {
        md = EVP_sha384();
    } else if (params.hash_algorithm == HashAlgorithm::SHA512) {
        md = EVP_sha512();
    }

    if (PKCS5_PBKDF2_HMAC(
            reinterpret_cast<const char*>(password.data),
            static_cast<int>(password.size),
            params.salt.data(),
            static_cast<int>(params.salt.size()),
            static_cast<int>(params.iterations),
            md,
            static_cast<int>(params.hash_length),
            output.data()) != 1) {
        return Result<ByteArray>::fail(static_cast<int32_t>(CryptoError::KDF_FAILED),
                                       "PBKDF2 derivation failed");
    }

    return Result<ByteArray>::ok(std::move(output));
}

Result<ByteArray> CryptoContext::derive_scrypt(
    ByteSpan password,
    const ScryptParams& params
) {
    ByteArray output(params.hash_length);

    if (EVP_PBE_scrypt(
            reinterpret_cast<const char*>(password.data),
            static_cast<size_t>(password.size),
            params.salt.data(),
            static_cast<size_t>(params.salt.size()),
            static_cast<uint64_t>(1) << params.log2_n,
            static_cast<uint64_t>(params.r),
            static_cast<uint64_t>(params.p),
            0,  // maxmem: 0 = use OpenSSL default
            output.data(),
            static_cast<size_t>(params.hash_length)) != 1) {
        return Result<ByteArray>::fail(static_cast<int32_t>(CryptoError::KDF_FAILED),
                                       "scrypt derivation failed");
    }

    return Result<ByteArray>::ok(std::move(output));
}

// ============================================================================
// HASHING
// ============================================================================

Result<ByteArray> CryptoContext::hash(
    ByteSpan data,
    HashAlgorithm algorithm
) {
    const EVP_MD* md = nullptr;
    switch (algorithm) {
        case HashAlgorithm::SHA256:     md = EVP_sha256(); break;
        case HashAlgorithm::SHA384:     md = EVP_sha384(); break;
        case HashAlgorithm::SHA512:     md = EVP_sha512(); break;
        case HashAlgorithm::BLAKE2B_512: md = EVP_blake2b512(); break;
        default:
            return Result<ByteArray>::fail(
                static_cast<int32_t>(CryptoError::HASH_ALGORITHM_UNSUPPORTED),
                "Unsupported hash algorithm");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return Result<ByteArray>::fail(static_cast<int32_t>(CryptoError::HASH_FAILED),
                                       "Failed to create hash context");
    }

    ByteArray output(EVP_MD_size(md));

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data, data.size) != 1 ||
        EVP_DigestFinal_ex(ctx, output.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return Result<ByteArray>::fail(static_cast<int32_t>(CryptoError::HASH_FAILED),
                                       "Hash computation failed");
    }

    EVP_MD_CTX_free(ctx);
    return Result<ByteArray>::ok(std::move(output));
}

Result<ByteArray> CryptoContext::hmac(
    ByteSpan key,
    ByteSpan data,
    HashAlgorithm algorithm
) {
    const EVP_MD* md = nullptr;
    switch (algorithm) {
        case HashAlgorithm::SHA256:     md = EVP_sha256(); break;
        case HashAlgorithm::SHA384:     md = EVP_sha384(); break;
        case HashAlgorithm::SHA512:     md = EVP_sha512(); break;
        default:
            return Result<ByteArray>::fail(
                static_cast<int32_t>(CryptoError::HASH_ALGORITHM_UNSUPPORTED),
                "Unsupported hash algorithm");
    }

    ByteArray output(EVP_MD_size(md));

    unsigned int out_len = 0;
    if (HMAC(md, key.data, static_cast<int>(key.size),
             data.data, data.size,
             output.data(), &out_len) == nullptr) {
        return Result<ByteArray>::fail(static_cast<int32_t>(CryptoError::HMAC_FAILED),
                                       "HMAC computation failed");
    }

    output.resize(out_len);
    return Result<ByteArray>::ok(std::move(output));
}

// ============================================================================
// RANDOM NUMBER GENERATION
// ============================================================================

Result<ByteArray> CryptoContext::random_bytes(size_t size) {
    ByteArray output(size);
    if (RAND_bytes(output.data(), static_cast<int>(size)) != 1) {
        return Result<ByteArray>::fail(static_cast<int32_t>(CryptoError::ENCRYPTION_FAILED),
                                       "Random byte generation failed");
    }
    return Result<ByteArray>::ok(std::move(output));
}

Aes256Key CryptoContext::random_aes_key() {
    Aes256Key key{};
    RAND_bytes(key.data(), static_cast<int>(key.size()));
    return key;
}

AesGcmIv CryptoContext::random_gcm_iv() {
    AesGcmIv iv{};
    RAND_bytes(iv.data(), static_cast<int>(iv.size()));
    return iv;
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

ErrorCode encrypt_file_aes_gcm(
    const std::string& input_path,
    const std::string& output_path,
    const Aes256Key& key
) {
    // Read input file
    std::ifstream input(input_path, std::ios::binary);
    if (!input.is_open()) {
        return ErrorCode::FILE_NOT_FOUND;
    }

    std::vector<uint8_t> plaintext(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    input.close();

    // Encrypt
    auto& ctx = CryptoContext::instance();
    auto result = ctx.aes_gcm_encrypt(key, ByteSpan(plaintext));
    if (!result.success) {
        return static_cast<ErrorCode>(result.error_code);
    }

    // Write output file
    std::ofstream output(output_path, std::ios::binary);
    if (!output.is_open()) {
        return ErrorCode::FILE_ACCESS_DENIED;
    }
    output.write(reinterpret_cast<const char*>(result.value.data()),
                 static_cast<std::streamsize>(result.value.size()));
    output.close();

    return ErrorCode::SUCCESS;
}

ErrorCode decrypt_file_aes_gcm(
    const std::string& input_path,
    const std::string& output_path,
    const Aes256Key& key
) {
    // Read input file
    std::ifstream input(input_path, std::ios::binary);
    if (!input.is_open()) {
        return ErrorCode::FILE_NOT_FOUND;
    }

    std::vector<uint8_t> ciphertext(
        (std::istreambuf_iterator<char>(input)),
        std::istreambuf_iterator<char>());
    input.close();

    // Decrypt
    auto& ctx = CryptoContext::instance();
    auto result = ctx.aes_gcm_decrypt(key, ByteSpan(ciphertext));
    if (!result.success) {
        return static_cast<ErrorCode>(result.error_code);
    }

    // Write output file
    std::ofstream output(output_path, std::ios::binary);
    if (!output.is_open()) {
        return ErrorCode::FILE_ACCESS_DENIED;
    }
    output.write(reinterpret_cast<const char*>(result.value.data()),
                 static_cast<std::streamsize>(result.value.size()));
    output.close();

    return ErrorCode::SUCCESS;
}

Result<Sha256Digest> hash_file_sha256(const std::string& file_path) {
    std::ifstream input(file_path, std::ios::binary);
    if (!input.is_open()) {
        return Result<Sha256Digest>::fail(
            static_cast<int32_t>(ErrorCode::FILE_NOT_FOUND),
            "File not found: " + file_path);
    }

    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);

    std::vector<char> buffer(64 * 1024);
    while (input) {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        std::streamsize count = input.gcount();
        if (count > 0) {
            SHA256_Update(&sha_ctx, buffer.data(), static_cast<size_t>(count));
        }
    }
    input.close();

    Sha256Digest digest{};
    SHA256_Final(digest.data(), &sha_ctx);

    return Result<Sha256Digest>::ok(digest);
}

} // namespace crypto
} // namespace securevault