// ============================================================================
// SecureVault - ChaCha20-Poly1305 Cipher Suite Implementation
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Implementation of ChaCha20-Poly1305 authenticated encryption (RFC 7539).
//   Provides ChaCha20 stream cipher, Poly1305 MAC, and AEAD construction.
//   Uses OpenSSL EVP interface for hardware-accelerated operations.
// ============================================================================

#include "cipher_suites/chacha20_poly1305.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>

namespace securevault {
namespace crypto {

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

/// Rotate left 32-bit value
inline uint32_t rotl32(uint32_t value, int shift) noexcept {
    return (value << shift) | (value >> (32 - shift));
}

// ============================================================================
// CHACHA20 STREAM CIPHER (low-level)
// ============================================================================

void chacha20_block(
    const ChaCha20Key& key,
    const ChaCha20Nonce& nonce,
    uint32_t counter,
    std::array<uint8_t, CHACHA20_BLOCK_SIZE>& output
) {
    // ChaCha20 state: 16 x 32-bit words
    // Constants: "expand 32-byte k"
    uint32_t state[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,  // constants
        0, 0, 0, 0,                                      // key (8 words)
        0, 0, 0, 0,                                      // key (8 words)
        counter,                                         // counter
        0, 0, 0                                          // nonce (3 words)
    };

    // Load key (little-endian)
    for (size_t i = 0; i < 8; ++i) {
        state[4 + i] = static_cast<uint32_t>(key[i * 4]) |
                       (static_cast<uint32_t>(key[i * 4 + 1]) << 8) |
                       (static_cast<uint32_t>(key[i * 4 + 2]) << 16) |
                       (static_cast<uint32_t>(key[i * 4 + 3]) << 24);
    }

    // Load nonce (little-endian)
    for (size_t i = 0; i < 3; ++i) {
        state[13 + i] = static_cast<uint32_t>(nonce[i * 4]) |
                        (static_cast<uint32_t>(nonce[i * 4 + 1]) << 8) |
                        (static_cast<uint32_t>(nonce[i * 4 + 2]) << 16) |
                        (static_cast<uint32_t>(nonce[i * 4 + 3]) << 24);
    }

    // Working state
    uint32_t x[16];
    std::memcpy(x, state, sizeof(x));

    // 20 rounds (10 double rounds)
    for (int round = 0; round < 10; ++round) {
        // Column rounds
        x[0]  += x[4];  x[12] = rotl32(x[12] ^ x[0],  16);
        x[1]  += x[5];  x[13] = rotl32(x[13] ^ x[1],  16);
        x[2]  += x[6];  x[14] = rotl32(x[14] ^ x[2],  16);
        x[3]  += x[7];  x[15] = rotl32(x[15] ^ x[3],  16);

        x[8]  += x[12]; x[4]  = rotl32(x[4]  ^ x[8],  12);
        x[9]  += x[13]; x[5]  = rotl32(x[5]  ^ x[9],  12);
        x[10] += x[14]; x[6]  = rotl32(x[6]  ^ x[10], 12);
        x[11] += x[15]; x[7]  = rotl32(x[7]  ^ x[11], 12);

        x[0]  += x[4];  x[12] = rotl32(x[12] ^ x[0],  8);
        x[1]  += x[5];  x[13] = rotl32(x[13] ^ x[1],  8);
        x[2]  += x[6];  x[14] = rotl32(x[14] ^ x[2],  8);
        x[3]  += x[7];  x[15] = rotl32(x[15] ^ x[3],  8);

        x[8]  += x[12]; x[4]  = rotl32(x[4]  ^ x[8],  7);
        x[9]  += x[13]; x[5]  = rotl32(x[5]  ^ x[9],  7);
        x[10] += x[14]; x[6]  = rotl32(x[6]  ^ x[10], 7);
        x[11] += x[15]; x[7]  = rotl32(x[7]  ^ x[11], 7);

        // Diagonal rounds
        x[0]  += x[5];  x[15] = rotl32(x[15] ^ x[0],  16);
        x[1]  += x[6];  x[12] = rotl32(x[12] ^ x[1],  16);
        x[2]  += x[7];  x[13] = rotl32(x[13] ^ x[2],  16);
        x[3]  += x[4];  x[14] = rotl32(x[14] ^ x[3],  16);

        x[10] += x[15]; x[5]  = rotl32(x[5]  ^ x[10], 12);
        x[11] += x[12]; x[6]  = rotl32(x[6]  ^ x[11], 12);
        x[8]  += x[13]; x[7]  = rotl32(x[7]  ^ x[8],  12);
        x[9]  += x[14]; x[4]  = rotl32(x[4]  ^ x[9],  12);

        x[0]  += x[5];  x[15] = rotl32(x[15] ^ x[0],  8);
        x[1]  += x[6];  x[12] = rotl32(x[12] ^ x[1],  8);
        x[2]  += x[7];  x[13] = rotl32(x[13] ^ x[2],  8);
        x[3]  += x[4];  x[14] = rotl32(x[14] ^ x[3],  8);

        x[10] += x[15]; x[5]  = rotl32(x[5]  ^ x[10], 7);
        x[11] += x[12]; x[6]  = rotl32(x[6]  ^ x[11], 7);
        x[8]  += x[13]; x[7]  = rotl32(x[7]  ^ x[8],  7);
        x[9]  += x[14]; x[4]  = rotl32(x[4]  ^ x[9],  7);
    }

    // Add original state
    for (int i = 0; i < 16; ++i) {
        x[i] += state[i];
    }

    // Serialize to output (little-endian)
    for (size_t i = 0; i < 16; ++i) {
        output[i * 4]     = static_cast<uint8_t>(x[i]);
        output[i * 4 + 1] = static_cast<uint8_t>(x[i] >> 8);
        output[i * 4 + 2] = static_cast<uint8_t>(x[i] >> 16);
        output[i * 4 + 3] = static_cast<uint8_t>(x[i] >> 24);
    }
}

void chacha20_xor(
    const ChaCha20Key& key,
    const ChaCha20Nonce& nonce,
    uint32_t counter,
    ByteSpan input,
    MutableByteSpan output
) {
    if (input.size != output.size) {
        return;
    }

    std::array<uint8_t, CHACHA20_BLOCK_SIZE> block{};
    size_t offset = 0;

    while (offset < input.size) {
        chacha20_block(key, nonce, counter, block);

        size_t chunk = std::min(CHACHA20_BLOCK_SIZE, input.size - offset);
        for (size_t i = 0; i < chunk; ++i) {
            output.data[offset + i] = input.data[offset + i] ^ block[i];
        }

        offset += chunk;
        ++counter;
    }
}

// ============================================================================
// POLY1305 MAC (low-level)
// ============================================================================

namespace {

// Poly1305 field prime: 2^130 - 5
constexpr uint64_t P0 = 0x3ffffff;
constexpr uint64_t P1 = 0x3ffffff;
constexpr uint64_t P2 = 0x3ffffff;
constexpr uint64_t P3 = 0x3ffffff;
constexpr uint64_t P4 = 0x3ffffffffffffff;

// Load 16 bytes as little-endian 128-bit number
void load_le16(const uint8_t* in, uint64_t& r0, uint64_t& r1, uint64_t& r2,
               uint64_t& r3, uint64_t& r4) {
    r0 = static_cast<uint64_t>(in[0]) |
         (static_cast<uint64_t>(in[1]) << 8) |
         (static_cast<uint64_t>(in[2]) << 16) |
         (static_cast<uint64_t>(in[3]) << 24) |
         (static_cast<uint64_t>(in[4]) << 32) |
         (static_cast<uint64_t>(in[5]) << 40) |
         (static_cast<uint64_t>(in[6]) << 48) |
         (static_cast<uint64_t>(in[7]) << 56);
    r0 &= 0xfffffffffff;

    r1 = static_cast<uint64_t>(in[8]) |
         (static_cast<uint64_t>(in[9]) << 8) |
         (static_cast<uint64_t>(in[10]) << 16) |
         (static_cast<uint64_t>(in[11]) << 24) |
         (static_cast<uint64_t>(in[12]) << 32) |
         (static_cast<uint64_t>(in[13]) << 40) |
         (static_cast<uint64_t>(in[14]) << 48) |
         (static_cast<uint64_t>(in[15]) << 56);
    r1 &= 0xfffffffffff;
}

// Store 16 bytes as little-endian 128-bit number
void store_le16(uint8_t* out, uint64_t h0, uint64_t h1, uint64_t h2,
                uint64_t h3, uint64_t h4) {
    // h0..h4 are 44-bit limbs; combine into 128-bit little-endian
    uint64_t c0 = h0 | (h1 << 44);
    uint64_t c1 = (h1 >> 20) | (h2 << 24) | (h3 << 68);
    // h3 is 44-bit, h4 is 42-bit
    uint64_t c2 = (h3 >> 20) | (h4 << 24);

    out[0]  = static_cast<uint8_t>(c0);
    out[1]  = static_cast<uint8_t>(c0 >> 8);
    out[2]  = static_cast<uint8_t>(c0 >> 16);
    out[3]  = static_cast<uint8_t>(c0 >> 24);
    out[4]  = static_cast<uint8_t>(c0 >> 32);
    out[5]  = static_cast<uint8_t>(c0 >> 40);
    out[6]  = static_cast<uint8_t>(c0 >> 48);
    out[7]  = static_cast<uint8_t>(c0 >> 56);

    out[8]  = static_cast<uint8_t>(c1);
    out[9]  = static_cast<uint8_t>(c1 >> 8);
    out[10] = static_cast<uint8_t>(c1 >> 16);
    out[11] = static_cast<uint8_t>(c1 >> 24);
    out[12] = static_cast<uint8_t>(c1 >> 32);
    out[13] = static_cast<uint8_t>(c1 >> 40);
    out[14] = static_cast<uint8_t>(c1 >> 48);
    out[15] = static_cast<uint8_t>(c1 >> 56);
}

} // namespace

void poly1305_mac(
    const std::array<uint8_t, 32>& key,
    ByteSpan data,
    Poly1305Tag& tag
) {
    // Poly1305 reference implementation (RFC 8439)
    // r = key[0..15] clamped, s = key[16..31]

    uint64_t r0, r1, r2, r3, r4;
    load_le16(key.data(), r0, r1, r2, r3, r4);

    // Clamp r
    r0 &= 0x0ffffffc0fffffffULL;
    r1 &= 0x0ffffffc0ffffffcULL;
    r2 &= 0x0ffffffc0ffffffcULL;
    r3 &= 0x0ffffffc0ffffffcULL;
    r4 &= 0x0ffffffc0ffffffcULL;

    uint64_t s0, s1, s2, s3, s4;
    load_le16(key.data() + 16, s0, s1, s2, s3, s4);

    uint64_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

    // Process data in 16-byte blocks
    size_t offset = 0;
    while (offset < data.size) {
        uint8_t block[16] = {0};
        size_t chunk = std::min<size_t>(16, data.size - offset);
        std::memcpy(block, data.data + offset, chunk);
        block[chunk] = 1;  // add 2^128 bit

        uint64_t t0, t1, t2, t3, t4;
        load_le16(block, t0, t1, t2, t3, t4);

        // h += block
        h0 += t0; h1 += t1; h2 += t2; h3 += t3; h4 += t4;

        // h *= r (schoolbook multiplication with 44-bit limbs)
        uint64_t d0 = h0 * r0;
        uint64_t d1 = h0 * r1 + h1 * r0;
        uint64_t d2 = h0 * r2 + h1 * r1 + h2 * r0;
        uint64_t d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0;
        uint64_t d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        uint64_t d5 = h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
        uint64_t d6 = h2 * r4 + h3 * r3 + h4 * r2;
        uint64_t d7 = h3 * r4 + h4 * r3;
        uint64_t d8 = h4 * r4;

        // Reduce mod 2^130-5
        uint64_t c = d0 >> 44; h0 = d0 & P0;
        d1 += c; c = d1 >> 44; h1 = d1 & P1;
        d2 += c; c = d2 >> 44; h2 = d2 & P2;
        d3 += c; c = d3 >> 44; h3 = d3 & P3;
        d4 += c; c = d4 >> 44; h4 = d4 & P4;
        d5 += c; c = d5 >> 44; d6 += c;
        c = d6 >> 44; d7 += c;
        c = d7 >> 44; d8 += c;

        // Fold d5..d8 back into h0..h4 (multiply by 5)
        uint64_t carry = d5 * 5;
        h0 += carry; carry = h0 >> 44; h0 &= P0;
        h1 += carry; carry = h1 >> 44; h1 &= P1;
        h2 += carry; carry = h2 >> 44; h2 &= P2;
        h3 += carry; carry = h3 >> 44; h3 &= P3;
        h4 += carry; carry = h4 >> 44; h4 &= P4;
        h0 += carry * 5;

        offset += chunk;
    }

    // Final reduction
    uint64_t c = h0 >> 44; h0 &= P0;
    h1 += c; c = h1 >> 44; h1 &= P1;
    h2 += c; c = h2 >> 44; h2 &= P2;
    h3 += c; c = h3 >> 44; h3 &= P3;
    h4 += c; c = h4 >> 44; h4 &= P4;
    h0 += c * 5;

    // Compute h + s
    uint64_t g0 = h0 + s0; c = g0 >> 44; g0 &= P0;
    uint64_t g1 = h1 + s1 + c; c = g1 >> 44; g1 &= P1;
    uint64_t g2 = h2 + s2 + c; c = g2 >> 44; g2 &= P2;
    uint64_t g3 = h3 + s3 + c; c = g3 >> 44; g3 &= P3;
    uint64_t g4 = h4 + s4 + c; g4 &= P4;

    // Select h or h+s (whichever is smaller)
    uint64_t mask = (g4 >> 42) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    store_le16(tag.data(), h0, h1, h2, h3, h4);
}

// ============================================================================
// CHACHA20-POLY1305 AEAD
// ============================================================================

ErrorCode chacha20_poly1305_encrypt(
    const ChaCha20Key& key,
    const ChaCha20Nonce& nonce,
    ByteSpan plaintext,
    ByteSpan aad,
    MutableByteSpan output,
    Poly1305Tag& tag
) {
    if (output.size < plaintext.size) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    // Use OpenSSL EVP for ChaCha20-Poly1305 AEAD
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ErrorCode::ENCRYPTION_FAILED;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    // Set IV length (12 bytes for ChaCha20-Poly1305)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::IV_LENGTH_INVALID;
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    // Set AAD
    int out_len = 0;
    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data,
                              static_cast<int>(aad.size)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::ENCRYPTION_FAILED;
        }
    }

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx, output.data, &out_len,
                          plaintext.data, static_cast<int>(plaintext.size)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    // Finalize
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, output.data + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    // Get tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                            static_cast<int>(tag.size()), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::ENCRYPTION_FAILED;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ErrorCode::SUCCESS;
}

ErrorCode chacha20_poly1305_decrypt(
    const ChaCha20Key& key,
    const ChaCha20Nonce& nonce,
    ByteSpan ciphertext,
    ByteSpan aad,
    const Poly1305Tag& tag,
    MutableByteSpan output
) {
    if (output.size < ciphertext.size) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return ErrorCode::DECRYPTION_FAILED;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            static_cast<int>(nonce.size()), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::IV_LENGTH_INVALID;
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }

    // Set AAD
    int out_len = 0;
    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &out_len, aad.data,
                              static_cast<int>(aad.size)) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return ErrorCode::DECRYPTION_FAILED;
        }
    }

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx, output.data, &out_len,
                          ciphertext.data, static_cast<int>(ciphertext.size)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                            static_cast<int>(tag.size()),
                            const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::DECRYPTION_FAILED;
    }

    // Finalize (verifies tag)
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, output.data + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return ErrorCode::TAG_MISMATCH;
    }

    EVP_CIPHER_CTX_free(ctx);
    return ErrorCode::SUCCESS;
}

} // namespace crypto
} // namespace securevault