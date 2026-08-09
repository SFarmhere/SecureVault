// ============================================================================
// SecureVault - Kyber1024 Post-Quantum Cipher Suite Implementation
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Implementation of CRYSTALS-Kyber-1024 key encapsulation mechanism (KEM).
//   NIST-selected post-quantum algorithm, security level 5.
//   Uses OpenSSL for SHA3/SHAKE and random number generation.
// ============================================================================

#include "cipher_suites/kyber1024.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <algorithm>

namespace securevault {
namespace crypto {

// ============================================================================
// KYBER PARAMETERS (Kyber-1024)
// ============================================================================

namespace {

// Kyber-1024 parameters
constexpr size_t KYBER_N = 256;          // Polynomial degree
constexpr size_t KYBER_K = 4;            // Module rank (4 for Kyber-1024)
constexpr size_t KYBER_Q = 3329;         // Modulus
constexpr size_t KYBER_ETA = 2;          // Noise parameter
constexpr size_t KYBER_DU = 11;          // Compression for u
constexpr size_t KYBER_DV = 5;           // Compression for v
constexpr size_t KYBER_SYMBYTES = 32;    // Symmetric bytes (256-bit)
constexpr size_t KYBER_POLYBYTES = 384;  // 256 * 12 / 8
constexpr size_t KYBER_POLYVECBYTES = KYBER_K * KYBER_POLYBYTES;
constexpr size_t KYBER_POLYCOMPRESSEDBYTES = 128;  // 256 * 4 / 8
constexpr size_t KYBER_POLYVECCOMPRESSEDBYTES = KYBER_K * KYBER_POLYCOMPRESSEDBYTES;

// NTT constants
constexpr int16_t ZETA = 17;  // Primitive 256th root of unity mod 3329

// Montgomery constant: 2^16 mod q
constexpr int32_t MONT = -1044;  // 2^16 mod 3329 = 3329 - 1044

// QINV = -q^{-1} mod 2^16
constexpr int32_t QINV = -3327;

// ============================================================================
// MODULAR ARITHMETIC
// ============================================================================

/// Montgomery reduction
inline int16_t montgomery_reduce(int32_t a) {
    int16_t t = static_cast<int16_t>(static_cast<int16_t>(a) * QINV);
    t = static_cast<int16_t>((a - static_cast<int32_t>(t) * KYBER_Q) >> 16);
    return t;
}

/// Barrett reduction
inline int16_t barrett_reduce(int16_t a) {
    constexpr int32_t V = (1 << 26) / KYBER_Q;
    int16_t t = static_cast<int16_t>((static_cast<int32_t>(V) * a + (1 << 25)) >> 26);
    t = static_cast<int16_t>(a - t * static_cast<int32_t>(KYBER_Q));
    return t;
}

/// Conditional subtraction of q
inline int16_t csubq(int16_t a) {
    a -= KYBER_Q;
    a += (a >> 15) & KYBER_Q;
    return a;
}

/// Conditional addition of q
inline int16_t caddq(int16_t a) {
    a += (a >> 15) & KYBER_Q;
    return a;
}

// ============================================================================
// NTT (Number Theoretic Transform)
// ============================================================================

// Precomputed NTT zetas
constexpr int16_t ZETAS[128] = {
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628
};

/// Forward NTT
void ntt(int16_t r[KYBER_N]) {
    size_t k = 0;
    for (size_t len = 128; len >= 2; len >>= 1) {
        for (size_t start = 0; start < KYBER_N; start += 2 * len) {
            int16_t zeta = ZETAS[++k];
            for (size_t j = start; j < start + len; ++j) {
                int16_t t = montgomery_reduce(static_cast<int32_t>(zeta) * r[j + len]);
                r[j + len] = static_cast<int16_t>(r[j] - t);
                r[j] = static_cast<int16_t>(r[j] + t);
            }
        }
    }
}

/// Inverse NTT
void invntt(int16_t r[KYBER_N]) {
    size_t k = 127;
    for (size_t len = 2; len <= 128; len <<= 1) {
        for (size_t start = 0; start < KYBER_N; start += 2 * len) {
            int16_t zeta = ZETAS[k--];
            for (size_t j = start; j < start + len; ++j) {
                int16_t t = r[j];
                r[j] = barrett_reduce(static_cast<int16_t>(t + r[j + len]));
                r[j + len] = static_cast<int16_t>(r[j + len] - t);
                r[j + len] = montgomery_reduce(static_cast<int32_t>(zeta) * r[j + len]);
            }
        }
    }
    for (size_t i = 0; i < KYBER_N; ++i) {
        r[i] = montgomery_reduce(static_cast<int32_t>(r[i]) * MONT);
    }
}

/// Pointwise multiplication in NTT domain
void basemul(int16_t r[KYBER_N], const int16_t a[KYBER_N],
             const int16_t b[KYBER_N], size_t zeta) {
    for (size_t i = 0; i < KYBER_N / 4; ++i) {
        size_t j = 4 * i;
        int32_t t0 = static_cast<int32_t>(a[j]) * b[j];
        int32_t t1 = static_cast<int32_t>(a[j + 1]) * b[j + 1];
        int32_t t2 = static_cast<int32_t>(a[j]) * b[j + 1];
        int32_t t3 = static_cast<int32_t>(a[j + 1]) * b[j];

        r[j] = montgomery_reduce(t0 + montgomery_reduce(static_cast<int32_t>(zeta) * t1));
        r[j + 1] = montgomery_reduce(t2 + t3);
    }
}

// ============================================================================
// POLYNOMIAL OPERATIONS
// ============================================================================

/// Add two polynomials
void poly_add(int16_t r[KYBER_N], const int16_t a[KYBER_N],
              const int16_t b[KYBER_N]) {
    for (size_t i = 0; i < KYBER_N; ++i) {
        r[i] = csubq(static_cast<int16_t>(a[i] + b[i]));
    }
}

/// Subtract two polynomials
void poly_sub(int16_t r[KYBER_N], const int16_t a[KYBER_N],
              const int16_t b[KYBER_N]) {
    for (size_t i = 0; i < KYBER_N; ++i) {
        r[i] = csubq(static_cast<int16_t>(a[i] - b[i]));
    }
}

/// Multiply two polynomials (NTT domain)
void poly_mul(int16_t r[KYBER_N], const int16_t a[KYBER_N],
              const int16_t b[KYBER_N]) {
    for (size_t i = 0; i < KYBER_N / 4; ++i) {
        basemul(r + 4 * i, a + 4 * i, b + 4 * i, ZETAS[64 + i]);
    }
}

/// Compress polynomial coefficients
void poly_compress(uint8_t* r, const int16_t a[KYBER_N], size_t d) {
    size_t t[8];
    if (d == 4) {
        for (size_t i = 0; i < KYBER_N / 8; ++i) {
            for (size_t j = 0; j < 8; ++j) {
                t[j] = (((static_cast<uint32_t>(a[8 * i + j]) << 4) + KYBER_Q / 2) / KYBER_Q) & 15;
            }
            r[i] = static_cast<uint8_t>(t[0] | (t[1] << 4));
            r[i + KYBER_N / 8] = static_cast<uint8_t>(t[2] | (t[3] << 4));
            r[i + 2 * KYBER_N / 8] = static_cast<uint8_t>(t[4] | (t[5] << 4));
            r[i + 3 * KYBER_N / 8] = static_cast<uint8_t>(t[6] | (t[7] << 4));
        }
    } else if (d == 5) {
        for (size_t i = 0; i < KYBER_N / 8; ++i) {
            for (size_t j = 0; j < 8; ++j) {
                t[j] = (((static_cast<uint32_t>(a[8 * i + j]) << 5) + KYBER_Q / 2) / KYBER_Q) & 31;
            }
            r[5 * i + 0] = static_cast<uint8_t>(t[0] | (t[1] << 5));
            r[5 * i + 1] = static_cast<uint8_t>((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            r[5 * i + 2] = static_cast<uint8_t>((t[3] >> 1) | (t[4] << 4));
            r[5 * i + 3] = static_cast<uint8_t>((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            r[5 * i + 4] = static_cast<uint8_t>((t[6] >> 2) | (t[7] << 3));
        }
    } else if (d == 10) {
        for (size_t i = 0; i < KYBER_N / 4; ++i) {
            for (size_t j = 0; j < 4; ++j) {
                t[j] = (((static_cast<uint32_t>(a[4 * i + j]) << 10) + KYBER_Q / 2) / KYBER_Q) & 1023;
            }
            r[5 * i + 0] = static_cast<uint8_t>(t[0]);
            r[5 * i + 1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 2));
            r[5 * i + 2] = static_cast<uint8_t>((t[1] >> 6) | (t[2] << 4));
            r[5 * i + 3] = static_cast<uint8_t>((t[2] >> 4) | (t[3] << 6));
            r[5 * i + 4] = static_cast<uint8_t>(t[3] >> 2);
        }
    } else if (d == 11) {
        for (size_t i = 0; i < KYBER_N / 8; ++i) {
            for (size_t j = 0; j < 8; ++j) {
                t[j] = (((static_cast<uint32_t>(a[8 * i + j]) << 11) + KYBER_Q / 2) / KYBER_Q) & 2047;
            }
            r[11 * i + 0] = static_cast<uint8_t>(t[0]);
            r[11 * i + 1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 3));
            r[11 * i + 2] = static_cast<uint8_t>((t[1] >> 5) | (t[2] << 6));
            r[11 * i + 3] = static_cast<uint8_t>((t[2] >> 2) | (t[3] << 9));
            r[11 * i + 4] = static_cast<uint8_t>((t[3] >> 7) | (t[4] << 4));
            r[11 * i + 5] = static_cast<uint8_t>((t[4] >> 4) | (t[5] << 7));
            r[11 * i + 6] = static_cast<uint8_t>((t[5] >> 1) | (t[6] << 10));
            r[11 * i + 7] = static_cast<uint8_t>((t[6] >> 6) | (t[7] << 5));
            r[11 * i + 8] = static_cast<uint8_t>(t[7] >> 3);
        }
    }
}

/// Decompress polynomial coefficients
void poly_decompress(int16_t r[KYBER_N], const uint8_t* a, size_t d) {
    if (d == 4) {
        for (size_t i = 0; i < KYBER_N / 2; ++i) {
            r[2 * i] = static_cast<int16_t>(((static_cast<uint32_t>(a[i] & 15) << 4) * KYBER_Q + 8) >> 4);
            r[2 * i + 1] = static_cast<int16_t>(((static_cast<uint32_t>(a[i] >> 4) << 4) * KYBER_Q + 8) >> 4);
        }
    } else if (d == 5) {
        for (size_t i = 0; i < KYBER_N / 8; ++i) {
            size_t t0 = a[5 * i + 0];
            size_t t1 = a[5 * i + 1];
            size_t t2 = a[5 * i + 2];
            size_t t3 = a[5 * i + 3];
            size_t t4 = a[5 * i + 4];

            r[8 * i + 0] = static_cast<int16_t>(((t0 & 31) << 5) * KYBER_Q / 32 + 16 >> 5);
            r[8 * i + 1] = static_cast<int16_t>((((t0 >> 5) | (t1 << 3)) & 31) * KYBER_Q / 32 + 16 >> 5);
            r[8 * i + 2] = static_cast<int16_t>((((t1 >> 2) | (t2 << 6)) & 31) * KYBER_Q / 32 + 16 >> 5);
            r[8 * i + 3] = static_cast<int16_t>((((t2 >> 4) | (t3 << 1)) & 31) * KYBER_Q / 32 + 16 >> 5);
            r[8 * i + 4] = static_cast<int16_t>((((t3 >> 7) | (t4 << 4)) & 31) * KYBER_Q / 32 + 16 >> 5);
            r[8 * i + 5] = static_cast<int16_t>((((t4 >> 1) | (t3 >> 6)) & 31) * KYBER_Q / 32 + 16 >> 5);
            r[8 * i + 6] = static_cast<int16_t>((((t4 >> 6) | (t3 >> 3)) & 31) * KYBER_Q / 32 + 16 >> 5);
            r[8 * i + 7] = static_cast<int16_t>((t4 >> 2) * KYBER_Q / 32 + 16 >> 5);
        }
    } else if (d == 10) {
        for (size_t i = 0; i < KYBER_N / 4; ++i) {
            size_t t0 = a[5 * i + 0];
            size_t t1 = a[5 * i + 1];
            size_t t2 = a[5 * i + 2];
            size_t t3 = a[5 * i + 3];
            size_t t4 = a[5 * i + 4];

            r[4 * i + 0] = static_cast<int16_t>(((t0 | (t1 << 8)) & 1023) * KYBER_Q / 1024 + 512 >> 10);
            r[4 * i + 1] = static_cast<int16_t>((((t1 >> 2) | (t2 << 6)) & 1023) * KYBER_Q / 1024 + 512 >> 10);
            r[4 * i + 2] = static_cast<int16_t>((((t2 >> 4) | (t3 << 4)) & 1023) * KYBER_Q / 1024 + 512 >> 10);
            r[4 * i + 3] = static_cast<int16_t>((((t3 >> 6) | (t4 << 2)) & 1023) * KYBER_Q / 1024 + 512 >> 10);
        }
    } else if (d == 11) {
        for (size_t i = 0; i < KYBER_N / 8; ++i) {
            size_t t0 = a[11 * i + 0];
            size_t t1 = a[11 * i + 1];
            size_t t2 = a[11 * i + 2];
            size_t t3 = a[11 * i + 3];
            size_t t4 = a[11 * i + 4];
            size_t t5 = a[11 * i + 5];
            size_t t6 = a[11 * i + 6];
            size_t t7 = a[11 * i + 7];
            size_t t8 = a[11 * i + 8];

            r[8 * i + 0] = static_cast<int16_t>(((t0 | (t1 << 8)) & 2047) * KYBER_Q / 2048 + 1024 >> 11);
            r[8 * i + 1] = static_cast<int16_t>((((t1 >> 3) | (t2 << 5)) & 2047) * KYBER_Q / 2048 + 1024 >> 11);
            r[8 * i + 2] = static_cast<int16_t>((((t2 >> 6) | (t3 << 2) | (t4 << 10)) & 2047) * KYBER_Q / 2048 + 1024 >> 11);
            r[8 * i + 3] = static_cast<int16_t>((((t4 >> 1) | (t5 << 7)) & 2047) * KYBER_Q / 2048 + 1024 >> 11);
            r[8 * i + 4] = static_cast<int16_t>((((t5 >> 4) | (t6 << 4)) & 2047) * KYBER_Q / 2048 + 1024 >> 11);
            r[8 * i + 5] = static_cast<int16_t>((((t6 >> 7) | (t7 << 1) | (t8 << 9)) & 2047) * KYBER_Q / 2048 + 1024 >> 11);
            r[8 * i + 6] = static_cast<int16_t>((((t8 >> 2) | (t7 >> 6)) & 2047) * KYBER_Q / 2048 + 1024 >> 11);
            r[8 * i + 7] = static_cast<int16_t>((t8 >> 5) * KYBER_Q / 2048 + 1024 >> 11);
        }
    }
}

/// Serialize polynomial to bytes (12-bit coefficients)
void poly_to_bytes(uint8_t* r, const int16_t a[KYBER_N]) {
    for (size_t i = 0; i < KYBER_N / 2; ++i) {
        uint16_t t0 = static_cast<uint16_t>(a[2 * i]);
        uint16_t t1 = static_cast<uint16_t>(a[2 * i + 1]);
        r[3 * i + 0] = static_cast<uint8_t>(t0);
        r[3 * i + 1] = static_cast<uint8_t>((t0 >> 8) | (t1 << 4));
        r[3 * i + 2] = static_cast<uint8_t>(t1 >> 4);
    }
}

/// Deserialize polynomial from bytes
void poly_from_bytes(int16_t r[KYBER_N], const uint8_t* a) {
    for (size_t i = 0; i < KYBER_N / 2; ++i) {
        r[2 * i] = static_cast<int16_t>((a[3 * i] | (static_cast<uint16_t>(a[3 * i + 1]) << 8)) & 0xFFF);
        r[2 * i + 1] = static_cast<int16_t>((a[3 * i + 1] >> 4) | (static_cast<uint16_t>(a[3 * i + 2]) << 4));
    }
}

// ============================================================================
// HASHING (SHA3/SHAKE via OpenSSL)
// ============================================================================

/// SHA3-256 hash
void sha3_256(uint8_t* output, const uint8_t* input, size_t input_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, input, input_len);
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, output, &out_len);
    EVP_MD_CTX_free(ctx);
}

/// SHA3-512 hash
void sha3_512(uint8_t* output, const uint8_t* input, size_t input_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr);
    EVP_DigestUpdate(ctx, input, input_len);
    unsigned int out_len = 0;
    EVP_DigestFinal_ex(ctx, output, &out_len);
    EVP_MD_CTX_free(ctx);
}

/// SHAKE-128 extendable output function
void shake128(uint8_t* output, size_t output_len, const uint8_t* input, size_t input_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    EVP_DigestInit_ex(ctx, EVP_shake128(), nullptr);
    EVP_DigestUpdate(ctx, input, input_len);
    EVP_DigestFinalXOF(ctx, output, output_len);
    EVP_MD_CTX_free(ctx);
}

/// SHAKE-256 extendable output function
void shake256(uint8_t* output, size_t output_len, const uint8_t* input, size_t input_len) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr);
    EVP_DigestUpdate(ctx, input, input_len);
    EVP_DigestFinalXOF(ctx, output, output_len);
    EVP_MD_CTX_free(ctx);
}

// ============================================================================
// SAMPLING
// ============================================================================

/// Sample polynomial from uniform distribution (rejection sampling)
void poly_uniform(int16_t r[KYBER_N], const uint8_t seed[32], uint16_t nonce) {
    uint8_t buf[3 * KYBER_N];
    uint8_t extseed[33];
    std::memcpy(extseed, seed, 32);
    extseed[32] = static_cast<uint8_t>(nonce);
    shake128(buf, sizeof(buf), extseed, 33);

    size_t pos = 0;
    size_t i = 0;
    while (i < KYBER_N) {
        uint16_t val = static_cast<uint16_t>(buf[pos]) |
                       (static_cast<uint16_t>(buf[pos + 1]) << 8);
        pos += 2;
        if (val < 19 * KYBER_Q) {
            r[i++] = static_cast<int16_t>(val - (val / KYBER_Q) * KYBER_Q);
        }
    }
}

/// Sample polynomial from centered binomial distribution
void poly_cbd_eta2(int16_t r[KYBER_N], const uint8_t buf[2 * KYBER_N * KYBER_ETA / 4]) {
    for (size_t i = 0; i < KYBER_N / 8; ++i) {
        uint32_t t = static_cast<uint32_t>(buf[4 * i]) |
                     (static_cast<uint32_t>(buf[4 * i + 1]) << 8) |
                     (static_cast<uint32_t>(buf[4 * i + 2]) << 16) |
                     (static_cast<uint32_t>(buf[4 * i + 3]) << 24);
        uint32_t d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for (size_t j = 0; j < 8; ++j) {
            int16_t a = static_cast<int16_t>((d >> (4 * j + 0)) & 0x3);
            int16_t b = static_cast<int16_t>((d >> (4 * j + 2)) & 0x3);
            r[8 * i + j] = static_cast<int16_t>(a - b);
        }
    }
}

/// Sample noise polynomial
void poly_getnoise_eta2(int16_t r[KYBER_N], const uint8_t seed[32], uint8_t nonce) {
    uint8_t buf[2 * KYBER_N * KYBER_ETA / 4];
    uint8_t extseed[33];
    std::memcpy(extseed, seed, 32);
    extseed[32] = nonce;
    shake256(buf, sizeof(buf), extseed, 33);
    poly_cbd_eta2(r, buf);
}

} // namespace (закрытие anonymous — публичные функции ниже)

// ============================================================================
// KEY GENERATION
// ============================================================================

ErrorCode kyber1024_generate_keypair(KyberKeyPair& key_pair) {
    // Generate random seed
    uint8_t seed[2 * KYBER_SYMBYTES];
    if (RAND_bytes(seed, sizeof(seed)) != 1) {
        return static_cast<ErrorCode>(CryptoError::KYBER_KEYGEN_FAILED);
    }

    // Derive public seed and noise seed
    uint8_t public_seed[KYBER_SYMBYTES];
    uint8_t noise_seed[KYBER_SYMBYTES];
    sha3_512(public_seed, seed, sizeof(seed));
    std::memcpy(noise_seed, public_seed + KYBER_SYMBYTES, KYBER_SYMBYTES);

    // Generate matrix A and sample noise
    int16_t a[KYBER_K][KYBER_K][KYBER_N];
    int16_t s[KYBER_K][KYBER_N];
    int16_t e[KYBER_K][KYBER_N];

    for (size_t i = 0; i < KYBER_K; ++i) {
        for (size_t j = 0; j < KYBER_K; ++j) {
            poly_uniform(a[i][j], public_seed, static_cast<uint16_t>(i * KYBER_K + j));
        }
        poly_getnoise_eta2(s[i], noise_seed, static_cast<uint8_t>(i));
        poly_getnoise_eta2(e[i], noise_seed, static_cast<uint8_t>(i + KYBER_K));
    }

    // Compute t = A*s + e
    int16_t t[KYBER_K][KYBER_N];
    for (size_t i = 0; i < KYBER_K; ++i) {
        std::memset(t[i], 0, sizeof(t[i]));
        for (size_t j = 0; j < KYBER_K; ++j) {
            int16_t tmp[KYBER_N];
            poly_mul(tmp, a[i][j], s[j]);
            poly_add(t[i], t[i], tmp);
        }
        poly_add(t[i], t[i], e[i]);
    }

    // Serialize public key: t (compressed) + public_seed
    uint8_t* pk = key_pair.public_key.data();
    for (size_t i = 0; i < KYBER_K; ++i) {
        poly_to_bytes(pk + i * KYBER_POLYBYTES, t[i]);
    }
    std::memcpy(pk + KYBER_POLYVECBYTES, public_seed, KYBER_SYMBYTES);

    // Serialize secret key: s (compressed) + public key
    uint8_t* sk = key_pair.secret_key.data();
    for (size_t i = 0; i < KYBER_K; ++i) {
        poly_to_bytes(sk + i * KYBER_POLYBYTES, s[i]);
    }
    std::memcpy(sk + KYBER_POLYVECBYTES, pk, KYBER1024_PUBLIC_KEY_SIZE);

    return ErrorCode::SUCCESS;
}

// ============================================================================
// ENCAPSULATION
// ============================================================================

ErrorCode kyber1024_encapsulate(
    const Kyber1024PublicKey& public_key,
    KyberEncapsulation& encapsulation
) {
    // Parse public key
    int16_t t[KYBER_K][KYBER_N];
    uint8_t public_seed[KYBER_SYMBYTES];
    for (size_t i = 0; i < KYBER_K; ++i) {
        poly_from_bytes(t[i], public_key.data() + i * KYBER_POLYBYTES);
    }
    std::memcpy(public_seed, public_key.data() + KYBER_POLYVECBYTES, KYBER_SYMBYTES);

    // Generate random m
    uint8_t m[KYBER_SYMBYTES];
    if (RAND_bytes(m, sizeof(m)) != 1) {
        return static_cast<ErrorCode>(CryptoError::KYBER_ENCAPSULATE_FAILED);
    }

    // Derive seeds
    uint8_t kr[2 * KYBER_SYMBYTES];
    sha3_256(kr, m, KYBER_SYMBYTES);
    uint8_t rho[KYBER_SYMBYTES];
    uint8_t sigma[KYBER_SYMBYTES];
    std::memcpy(rho, kr, KYBER_SYMBYTES);
    std::memcpy(sigma, kr + KYBER_SYMBYTES, KYBER_SYMBYTES);

    // Generate matrix A
    int16_t a[KYBER_K][KYBER_K][KYBER_N];
    for (size_t i = 0; i < KYBER_K; ++i) {
        for (size_t j = 0; j < KYBER_K; ++j) {
            poly_uniform(a[i][j], rho, static_cast<uint16_t>(j * KYBER_K + i));
        }
    }

    // Sample noise
    int16_t sp[KYBER_K][KYBER_N];
    int16_t ep[KYBER_K][KYBER_N];
    int16_t epp[KYBER_N];
    for (size_t i = 0; i < KYBER_K; ++i) {
        poly_getnoise_eta2(sp[i], sigma, static_cast<uint8_t>(i));
        poly_getnoise_eta2(ep[i], sigma, static_cast<uint8_t>(i + KYBER_K));
    }
    poly_getnoise_eta2(epp, sigma, static_cast<uint8_t>(2 * KYBER_K));

    // Compute u = A^T * sp + ep
    int16_t u[KYBER_K][KYBER_N];
    for (size_t i = 0; i < KYBER_K; ++i) {
        std::memset(u[i], 0, sizeof(u[i]));
        for (size_t j = 0; j < KYBER_K; ++j) {
            int16_t tmp[KYBER_N];
            poly_mul(tmp, a[j][i], sp[j]);
            poly_add(u[i], u[i], tmp);
        }
        poly_add(u[i], u[i], ep[i]);
    }

    // Compute v = t^T * sp + epp + m
    int16_t v[KYBER_N];
    std::memset(v, 0, sizeof(v));
    for (size_t i = 0; i < KYBER_K; ++i) {
        int16_t tmp[KYBER_N];
        poly_mul(tmp, t[i], sp[i]);
        poly_add(v, v, tmp);
    }
    poly_add(v, v, epp);

    // Add message (encode m as polynomial)
    for (size_t i = 0; i < KYBER_N; ++i) {
        v[i] = static_cast<int16_t>(v[i] + ((m[i / 8] >> (i % 8)) & 1) * (KYBER_Q / 2));
        v[i] = csubq(v[i]);
    }

    // Compress and serialize ciphertext
    uint8_t* ct = encapsulation.ciphertext.data();
    for (size_t i = 0; i < KYBER_K; ++i) {
        poly_compress(ct + i * KYBER_POLYCOMPRESSEDBYTES, u[i], KYBER_DU);
    }
    poly_compress(ct + KYBER_POLYVECCOMPRESSEDBYTES, v, KYBER_DV);

    // Derive shared secret
    uint8_t buf[KYBER_SYMBYTES + KYBER1024_CIPHERTEXT_SIZE];
    std::memcpy(buf, m, KYBER_SYMBYTES);
    std::memcpy(buf + KYBER_SYMBYTES, ct, KYBER1024_CIPHERTEXT_SIZE);
    sha3_256(encapsulation.shared_secret.data(), buf, sizeof(buf));

    return ErrorCode::SUCCESS;
}

// ============================================================================
// DECAPSULATION
// ============================================================================

ErrorCode kyber1024_decapsulate(
    const Kyber1024SecretKey& secret_key,
    const Kyber1024Ciphertext& ciphertext,
    std::array<uint8_t, KYBER1024_SHARED_SECRET_SIZE>& shared_secret
) {
    // Parse secret key
    int16_t s[KYBER_K][KYBER_N];
    for (size_t i = 0; i < KYBER_K; ++i) {
        poly_from_bytes(s[i], secret_key.data() + i * KYBER_POLYBYTES);
    }

    // Parse public key from secret key
    Kyber1024PublicKey public_key{};
    std::memcpy(public_key.data(), secret_key.data() + KYBER_POLYVECBYTES,
                KYBER1024_PUBLIC_KEY_SIZE);

    // Parse ciphertext
    int16_t u[KYBER_K][KYBER_N];
    int16_t v[KYBER_N];
    for (size_t i = 0; i < KYBER_K; ++i) {
        poly_decompress(u[i], ciphertext.data() + i * KYBER_POLYCOMPRESSEDBYTES, KYBER_DU);
    }
    poly_decompress(v, ciphertext.data() + KYBER_POLYVECCOMPRESSEDBYTES, KYBER_DV);

    // Compute m' = v - s^T * u
    int16_t mp[KYBER_N];
    std::memset(mp, 0, sizeof(mp));
    for (size_t i = 0; i < KYBER_K; ++i) {
        int16_t tmp[KYBER_N];
        poly_mul(tmp, s[i], u[i]);
        poly_sub(mp, mp, tmp);
    }
    poly_add(mp, mp, v);

    // Decode message
    uint8_t m[KYBER_SYMBYTES];
    std::memset(m, 0, sizeof(m));
    for (size_t i = 0; i < KYBER_N; ++i) {
        int16_t val = csubq(mp[i]);
        if (val > KYBER_Q / 4) {
            m[i / 8] |= static_cast<uint8_t>(1 << (i % 8));
        }
    }

    // Re-encapsulate to verify
    KyberEncapsulation re_encap;
    auto result = ::securevault::crypto::kyber1024_encapsulate(public_key, re_encap);
    if (result != ErrorCode::SUCCESS) {
        return result;
    }

    // Compare ciphertexts (constant-time)
    uint8_t diff = 0;
    for (size_t i = 0; i < KYBER1024_CIPHERTEXT_SIZE; ++i) {
        diff |= static_cast<uint8_t>(re_encap.ciphertext[i] ^ ciphertext[i]);
    }

    // Derive shared secret (use m if valid, else use re-encapsulated m)
    uint8_t buf[KYBER_SYMBYTES + KYBER1024_CIPHERTEXT_SIZE];
    if (diff == 0) {
        std::memcpy(buf, m, KYBER_SYMBYTES);
    } else {
        // Use re-encapsulated shared secret as fallback (implicit rejection)
        std::memcpy(buf, re_encap.shared_secret.data(), KYBER_SYMBYTES);
    }
    std::memcpy(buf + KYBER_SYMBYTES, ciphertext.data(), KYBER1024_CIPHERTEXT_SIZE);
    sha3_256(shared_secret.data(), buf, sizeof(buf));

    return ErrorCode::SUCCESS;
}

// ============================================================================
// KEY SERIALIZATION
// ============================================================================

void kyber1024_public_key_to_bytes(
    const Kyber1024PublicKey& public_key,
    ByteArray& output
) {
    output.assign(public_key.begin(), public_key.end());
}

ErrorCode kyber1024_public_key_from_bytes(
    ByteSpan input,
    Kyber1024PublicKey& public_key
) {
    if (input.size != KYBER1024_PUBLIC_KEY_SIZE) {
        return ErrorCode::INVALID_ARGUMENT;
    }
    std::copy(input.begin(), input.end(), public_key.begin());
    return ErrorCode::SUCCESS;
}

void kyber1024_secret_key_to_bytes(
    const Kyber1024SecretKey& secret_key,
    ByteArray& output
) {
    output.assign(secret_key.begin(), secret_key.end());
}

ErrorCode kyber1024_secret_key_from_bytes(
    ByteSpan input,
    Kyber1024SecretKey& secret_key
) {
    if (input.size != KYBER1024_SECRET_KEY_SIZE) {
        return ErrorCode::INVALID_ARGUMENT;
    }
    std::copy(input.begin(), input.end(), secret_key.begin());
    return ErrorCode::SUCCESS;
}

} // namespace crypto
} // namespace securevault
