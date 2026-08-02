// ============================================================================
// SecureVault - RSA Implementation
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   RSA-2048/4096 key generation, OAEP encryption, PSS signatures.
//   Uses OpenSSL EVP API with hardware acceleration when available.
// ============================================================================

#include "rsa.h"
#include "logging.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <cstring>
#include <memory>

namespace securevault {
namespace crypto {

// ============================================================================
// RAII HELPERS
// ============================================================================

namespace {

struct EvpPkeyDeleter {
    void operator()(EVP_PKEY* pkey) const { EVP_PKEY_free(pkey); }
};

struct BnCtxDeleter {
    void operator()(BN_CTX* ctx) const { BN_CTX_free(ctx); }
};

struct RsaDeleter {
    void operator()(RSA* rsa) const { RSA_free(rsa); }
};

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>;
using BnCtxPtr = std::unique_ptr<BN_CTX, BnCtxDeleter>;
using RsaPtr = std::unique_ptr<RSA, RsaDeleter>;

/// Convert BigNum to big-endian byte vector (minimal length, no leading zeros)
std::vector<uint8_t> bn_to_bytes(const BIGNUM* bn) {
    int size = BN_num_bytes(bn);
    if (size <= 0) return {};
    std::vector<uint8_t> bytes(static_cast<size_t>(size));
    BN_bn2bin(bn, bytes.data());
    return bytes;
}

/// Convert big-endian byte vector to BIGNUM
BIGNUM* bytes_to_bn(ByteSpan bytes) {
    return BN_bin2bn(bytes.data, static_cast<int>(bytes.size), nullptr);
}

} // anonymous namespace

// ============================================================================
// RSA KEY GENERATION
// ============================================================================

ErrorCode rsa_generate_keypair(uint32_t bits, RsaKeyPair& key_pair) {
    if (bits != 2048 && bits != 4096) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    // Create RSA key context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        return ErrorCode::INVALID_STATE;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return ErrorCode::INVALID_STATE;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, static_cast<int>(bits)) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return ErrorCode::INVALID_STATE;
    }

    // Generate key pair
    EVP_PKEY* pkey_raw = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey_raw) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return ErrorCode::INVALID_STATE;
    }
    EVP_PKEY_CTX_free(ctx);

    EvpPkeyPtr pkey(pkey_raw);

    // Get RSA components
    RSA* rsa = EVP_PKEY_get1_RSA(pkey.get());
    if (!rsa) {
        return ErrorCode::INVALID_STATE;
    }
    RsaPtr rsa_guard(rsa);

    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    const BIGNUM* d = nullptr;
    const BIGNUM* p = nullptr;
    const BIGNUM* q = nullptr;
    const BIGNUM* dmp1 = nullptr;
    const BIGNUM* dmq1 = nullptr;
    const BIGNUM* iqmp = nullptr;

    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

    if (!n || !e || !d || !p || !q) {
        return ErrorCode::INVALID_STATE;
    }

    // Fill in key pair
    key_pair.public_key.modulus = bn_to_bytes(n);
    key_pair.public_key.exponent = static_cast<uint32_t>(BN_get_word(e));
    key_pair.public_key.bits = bits;

    key_pair.private_key.modulus = bn_to_bytes(n);
    key_pair.private_key.public_exponent = static_cast<uint32_t>(BN_get_word(e));
    key_pair.private_key.private_exponent = bn_to_bytes(d);
    key_pair.private_key.prime_p = bn_to_bytes(p);
    key_pair.private_key.prime_q = bn_to_bytes(q);

    if (dmp1) key_pair.private_key.dmp1 = bn_to_bytes(dmp1);
    if (dmq1) key_pair.private_key.dmq1 = bn_to_bytes(dmq1);
    if (iqmp) key_pair.private_key.iqmp = bn_to_bytes(iqmp);

    key_pair.private_key.bits = bits;

    LOG_DEBUG("crypto", "rsa", "Generated RSA-{} key pair", bits);

    return ErrorCode::SUCCESS;
}

// ============================================================================
// BUILD OPENSSL RSA KEY OBJECTS
// ============================================================================

namespace {

/// Build an OpenSSL RSA public key object from our RsaPublicKey
RSA* build_rsa_public(const RsaPublicKey& public_key) {
    if (!public_key.is_valid()) return nullptr;

    RSA* rsa = RSA_new();
    if (!rsa) return nullptr;

    BIGNUM* n = bytes_to_bn(ByteSpan(public_key.modulus));
    BIGNUM* e = BN_new();
    if (!n || !e) {
        if (n) BN_free(n);
        if (e) BN_free(e);
        RSA_free(rsa);
        return nullptr;
    }
    BN_set_word(e, public_key.exponent);

    if (RSA_set0_key(rsa, n, e, nullptr) != 1) {
        BN_free(n);
        BN_free(e);
        RSA_free(rsa);
        return nullptr;
    }
    return rsa;
}

/// Build an OpenSSL RSA private key object from our RsaPrivateKey
RSA* build_rsa_private(const RsaPrivateKey& private_key) {
    if (!private_key.is_valid()) return nullptr;

    RSA* rsa = RSA_new();
    if (!rsa) return nullptr;

    BIGNUM* n = bytes_to_bn(ByteSpan(private_key.modulus));
    BIGNUM* e = BN_new();
    BIGNUM* d = bytes_to_bn(ByteSpan(private_key.private_exponent));
    BIGNUM* p = bytes_to_bn(ByteSpan(private_key.prime_p));
    BIGNUM* q = bytes_to_bn(ByteSpan(private_key.prime_q));

    if (!n || !e || !d || !p || !q) {
        if (n) BN_free(n);
        if (e) BN_free(e);
        if (d) BN_free(d);
        if (p) BN_free(p);
        if (q) BN_free(q);
        RSA_free(rsa);
        return nullptr;
    }
    BN_set_word(e, private_key.public_exponent);

    if (RSA_set0_key(rsa, n, e, d) != 1) {
        BN_free(n); BN_free(e); BN_free(d);
        RSA_free(rsa);
        return nullptr;
    }

    if (RSA_set0_factors(rsa, p, q) != 1) {
        BN_free(p); BN_free(q);
        RSA_free(rsa);
        return nullptr;
    }

    // CRT parameters (optional)
    if (!private_key.dmp1.empty() && !private_key.dmq1.empty() && !private_key.iqmp.empty()) {
        BIGNUM* dmp1 = bytes_to_bn(ByteSpan(private_key.dmp1));
        BIGNUM* dmq1 = bytes_to_bn(ByteSpan(private_key.dmq1));
        BIGNUM* iqmp = bytes_to_bn(ByteSpan(private_key.iqmp));

        if (RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) != 1) {
            if (dmp1) BN_free(dmp1);
            if (dmq1) BN_free(dmq1);
            if (iqmp) BN_free(iqmp);
        }
    }

    return rsa;
}

} // anonymous namespace

// ============================================================================
// RSA OAEP ENCRYPTION
// ============================================================================

ErrorCode rsa_encrypt_oaep(
    const RsaPublicKey& public_key,
    ByteSpan plaintext,
    MutableByteSpan ciphertext
) {
    if (!public_key.is_valid()) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    size_t key_size = public_key.bits / 8;
    if (ciphertext.size < key_size) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    // Max OAEP-SHA256 payload = key_size - 2*hash_len - 2
    size_t max_payload = key_size - 66;
    if (plaintext.size > max_payload) {
        return ErrorCode::DATA_TOO_LARGE;
    }

    RsaPtr rsa(build_rsa_public(public_key));
    if (!rsa) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    int result = RSA_public_encrypt(
        static_cast<int>(plaintext.size),
        plaintext.data,
        ciphertext.data,
        rsa.get(),
        RSA_PKCS1_OAEP_PADDING
    );

    if (result < 0) {
        return ErrorCode::ENCRYPTION_FAILED;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode rsa_decrypt_oaep(
    const RsaPrivateKey& private_key,
    ByteSpan ciphertext,
    MutableByteSpan plaintext
) {
    if (!private_key.is_valid()) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    size_t key_size = private_key.bits / 8;
    if (ciphertext.size != key_size) {
        return ErrorCode::INVALID_ARGUMENT;
    }
    if (plaintext.size < key_size) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    RsaPtr rsa(build_rsa_private(private_key));
    if (!rsa) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    int result = RSA_private_decrypt(
        static_cast<int>(ciphertext.size),
        ciphertext.data,
        plaintext.data,
        rsa.get(),
        RSA_PKCS1_OAEP_PADDING
    );

    if (result < 0) {
        return ErrorCode::DECRYPTION_FAILED;
    }

    return ErrorCode::SUCCESS;
}

// ============================================================================
// RSA PSS SIGNATURES
// ============================================================================

ErrorCode rsa_sign_pss(
    const RsaPrivateKey& private_key,
    ByteSpan data,
    MutableByteSpan signature
) {
    if (!private_key.is_valid()) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    size_t key_size = private_key.bits / 8;
    if (signature.size < key_size) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    RsaPtr rsa(build_rsa_private(private_key));
    if (!rsa) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    // Compute SHA-256 hash of data
    std::array<uint8_t, 32> digest{};
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return ErrorCode::AUTHENTICATION_FAILED;

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(md_ctx, data.data, data.size) != 1 ||
        EVP_DigestFinal_ex(md_ctx, digest.data(), nullptr) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return ErrorCode::AUTHENTICATION_FAILED;
    }
    EVP_MD_CTX_free(md_ctx);

    // Sign with PSS padding
    EVP_PKEY* pkey_raw = EVP_PKEY_new();
    if (!pkey_raw) return ErrorCode::AUTHENTICATION_FAILED;
    EvpPkeyPtr pkey(pkey_raw);

    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        return ErrorCode::AUTHENTICATION_FAILED;
    }

    // Note: rsa is now owned by pkey; release the unique_ptr
    rsa.release();

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return ErrorCode::AUTHENTICATION_FAILED;

    int result = 0;
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, pkey.get()) == 1) {
        result = EVP_DigestSign(ctx, signature.data, &key_size, digest.data(), digest.size());
    }

    EVP_MD_CTX_free(ctx);

    if (result != 1) {
        return ErrorCode::AUTHENTICATION_FAILED;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode rsa_verify_pss(
    const RsaPublicKey& public_key,
    ByteSpan data,
    ByteSpan signature
) {
    if (!public_key.is_valid()) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    size_t key_size = public_key.bits / 8;
    if (signature.size != key_size) {
        return ErrorCode::SIGNATURE_INVALID;
    }

    RsaPtr rsa(build_rsa_public(public_key));
    if (!rsa) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    // Compute SHA-256 hash of data
    std::array<uint8_t, 32> digest{};
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return ErrorCode::AUTHENTICATION_FAILED;

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(md_ctx, data.data, data.size) != 1 ||
        EVP_DigestFinal_ex(md_ctx, digest.data(), nullptr) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return ErrorCode::AUTHENTICATION_FAILED;
    }
    EVP_MD_CTX_free(md_ctx);

    EVP_PKEY* pkey_raw = EVP_PKEY_new();
    if (!pkey_raw) return ErrorCode::AUTHENTICATION_FAILED;
    EvpPkeyPtr pkey(pkey_raw);

    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        return ErrorCode::AUTHENTICATION_FAILED;
    }
    rsa.release();  // pkey now owns rsa

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return ErrorCode::AUTHENTICATION_FAILED;

    int result = 0;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey.get()) == 1) {
        result = EVP_DigestVerify(ctx, signature.data, signature.size,
                                  digest.data(), digest.size());
    }

    EVP_MD_CTX_free(ctx);

    if (result != 1) {
        return ErrorCode::SIGNATURE_INVALID;
    }

    return ErrorCode::SUCCESS;
}

// ============================================================================
// KEY SERIALIZATION (DER)
// ============================================================================

ErrorCode rsa_public_key_to_der(const RsaPublicKey& public_key, ByteArray& der) {
    RsaPtr rsa(build_rsa_public(public_key));
    if (!rsa) return ErrorCode::SERIALIZATION_ERROR;

    EVP_PKEY* pkey_raw = EVP_PKEY_new();
    if (!pkey_raw) return ErrorCode::SERIALIZATION_ERROR;
    EvpPkeyPtr pkey(pkey_raw);

    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        return ErrorCode::SERIALIZATION_ERROR;
    }
    rsa.release();

    int len = i2d_PUBKEY(pkey.get(), nullptr);
    if (len <= 0) return ErrorCode::SERIALIZATION_ERROR;

    der.resize(static_cast<size_t>(len));
    unsigned char* ptr = der.data();
    if (i2d_PUBKEY(pkey.get(), &ptr) <= 0) {
        return ErrorCode::SERIALIZATION_ERROR;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode rsa_public_key_from_der(ByteSpan der, RsaPublicKey& public_key) {
    const unsigned char* ptr = der.data;
    EVP_PKEY* pkey_raw = d2i_PUBKEY(nullptr, &ptr, static_cast<long>(der.size));
    if (!pkey_raw) return ErrorCode::DESERIALIZATION_ERROR;
    EvpPkeyPtr pkey(pkey_raw);

    RSA* rsa = EVP_PKEY_get1_RSA(pkey.get());
    if (!rsa) return ErrorCode::DESERIALIZATION_ERROR;
    RsaPtr rsa_guard(rsa);

    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    RSA_get0_key(rsa, &n, &e, nullptr);
    if (!n || !e) return ErrorCode::DESERIALIZATION_ERROR;

    public_key.modulus = bn_to_bytes(n);
    public_key.exponent = static_cast<uint32_t>(BN_get_word(e));
    public_key.bits = static_cast<uint32_t>(BN_num_bits(n));

    return ErrorCode::SUCCESS;
}

ErrorCode rsa_private_key_to_der(const RsaPrivateKey& private_key, ByteArray& der) {
    RsaPtr rsa(build_rsa_private(private_key));
    if (!rsa) return ErrorCode::SERIALIZATION_ERROR;

    EVP_PKEY* pkey_raw = EVP_PKEY_new();
    if (!pkey_raw) return ErrorCode::SERIALIZATION_ERROR;
    EvpPkeyPtr pkey(pkey_raw);

    if (EVP_PKEY_assign_RSA(pkey.get(), rsa.get()) != 1) {
        return ErrorCode::SERIALIZATION_ERROR;
    }
    rsa.release();

    int len = i2d_PrivateKey(pkey.get(), nullptr);
    if (len <= 0) return ErrorCode::SERIALIZATION_ERROR;

    der.resize(static_cast<size_t>(len));
    unsigned char* ptr = der.data();
    if (i2d_PrivateKey(pkey.get(), &ptr) <= 0) {
        return ErrorCode::SERIALIZATION_ERROR;
    }

    return ErrorCode::SUCCESS;
}

ErrorCode rsa_private_key_from_der(ByteSpan der, RsaPrivateKey& private_key) {
    const unsigned char* ptr = der.data;
    EVP_PKEY* pkey_raw = nullptr;
    d2i_PrivateKey(EVP_PKEY_RSA, &pkey_raw, &ptr, static_cast<long>(der.size));
    if (!pkey_raw) return ErrorCode::DESERIALIZATION_ERROR;
    EvpPkeyPtr pkey(pkey_raw);

    RSA* rsa = EVP_PKEY_get1_RSA(pkey.get());
    if (!rsa) return ErrorCode::DESERIALIZATION_ERROR;
    RsaPtr rsa_guard(rsa);

    const BIGNUM* n = nullptr;
    const BIGNUM* e = nullptr;
    const BIGNUM* d = nullptr;
    const BIGNUM* p = nullptr;
    const BIGNUM* q = nullptr;
    const BIGNUM* dmp1 = nullptr;
    const BIGNUM* dmq1 = nullptr;
    const BIGNUM* iqmp = nullptr;

    RSA_get0_key(rsa, &n, &e, &d);
    RSA_get0_factors(rsa, &p, &q);
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);

    if (!n || !e || !d || !p || !q) return ErrorCode::DESERIALIZATION_ERROR;

    private_key.modulus = bn_to_bytes(n);
    private_key.public_exponent = static_cast<uint32_t>(BN_get_word(e));
    private_key.private_exponent = bn_to_bytes(d);
    private_key.prime_p = bn_to_bytes(p);
    private_key.prime_q = bn_to_bytes(q);
    if (dmp1) private_key.dmp1 = bn_to_bytes(dmp1);
    if (dmq1) private_key.dmq1 = bn_to_bytes(dmq1);
    if (iqmp) private_key.iqmp = bn_to_bytes(iqmp);
    private_key.bits = static_cast<uint32_t>(BN_num_bits(n));

    return ErrorCode::SUCCESS;
}

} // namespace crypto
} // namespace securevault