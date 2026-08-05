// ============================================================================
// SecureVault - ChaCha20-Poly1305 Cipher Suite Tests
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Unit tests for ChaCha20-Poly1305 authenticated encryption.
//   Tests RFC 7539 test vectors, AEAD round-trip, and error handling.
// ============================================================================

#include "catch2/catch_test_macros.hpp"

#include <array>
#include <algorithm>

#include "cipher_suites/chacha20_poly1305.h"

using namespace securevault;
using namespace securevault::crypto;

// ============================================================================
// RFC 7539 TEST VECTORS
// ============================================================================

TEST_CASE("ChaCha20-Poly1305 RFC 7539 test vector", "[crypto][chacha20]") {
    // RFC 7539 Section 2.3.2 test vector
    ChaCha20Key key{};
    const uint8_t key_data[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    std::copy(std::begin(key_data), std::end(key_data), key.begin());

    ChaCha20Nonce nonce{};
    const uint8_t nonce_data[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    std::copy(std::begin(nonce_data), std::end(nonce_data), nonce.begin());

    // Expected keystream block (first 64 bytes)
    const uint8_t expected[64] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15,
        0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03,
        0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09,
        0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
        0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    };

    std::array<uint8_t, CHACHA20_BLOCK_SIZE> block{};
    chacha20_block(key, nonce, 1, block);

    std::array<uint8_t, CHACHA20_BLOCK_SIZE> expected_array{};
    std::copy(std::begin(expected), std::end(expected), expected_array.begin());
    
    REQUIRE(block == expected_array);
}

TEST_CASE("ChaCha20-Poly1305 encrypt/decrypt round-trip", "[crypto][chacha20]") {
    ChaCha20Key key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i * 3 + 1);
    }

    ChaCha20Nonce nonce{};
    for (size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<uint8_t>(i * 5 + 2);
    }

    const std::string plaintext_str = "SecureVault ChaCha20-Poly1305 test message";
    ByteArray plaintext(plaintext_str.begin(), plaintext_str.end());
    ByteArray aad = {0x01, 0x02, 0x03, 0x04};

    ByteArray ciphertext(plaintext.size());
    Poly1305Tag tag{};

    auto result = chacha20_poly1305_encrypt(
        key, nonce, ByteSpan(plaintext), ByteSpan(aad),
        MutableByteSpan(ciphertext), tag);

    REQUIRE(result == ErrorCode::SUCCESS);

    // Decrypt
    ByteArray decrypted(plaintext.size());
    result = chacha20_poly1305_decrypt(
        key, nonce, ByteSpan(ciphertext), ByteSpan(aad),
        tag, MutableByteSpan(decrypted));

    REQUIRE(result == ErrorCode::SUCCESS);
    REQUIRE(decrypted == plaintext);
}

TEST_CASE("ChaCha20-Poly1305 tag mismatch detection", "[crypto][chacha20]") {
    ChaCha20Key key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i + 1);
    }

    ChaCha20Nonce nonce{};
    for (size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<uint8_t>(i + 2);
    }

    const std::string plaintext_str = "Test data for tag verification";
    ByteArray plaintext(plaintext_str.begin(), plaintext_str.end());

    ByteArray ciphertext(plaintext.size());
    Poly1305Tag tag{};

    auto result = chacha20_poly1305_encrypt(
        key, nonce, ByteSpan(plaintext), {},
        MutableByteSpan(ciphertext), tag);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Corrupt ciphertext
    ciphertext[0] ^= 0xFF;

    ByteArray decrypted(plaintext.size());
    result = chacha20_poly1305_decrypt(
        key, nonce, ByteSpan(ciphertext), {},
        tag, MutableByteSpan(decrypted));

    REQUIRE(result == ErrorCode::TAG_MISMATCH);
}

TEST_CASE("ChaCha20-Poly1305 AAD mismatch detection", "[crypto][chacha20]") {
    ChaCha20Key key{};
    for (size_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(i * 2);
    }

    ChaCha20Nonce nonce{};
    for (size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<uint8_t>(i * 3);
    }

    const std::string plaintext_str = "AAD verification test";
    ByteArray plaintext(plaintext_str.begin(), plaintext_str.end());
    ByteArray aad1 = {0xAA, 0xBB, 0xCC};
    ByteArray aad2 = {0xAA, 0xBB, 0xDD};  // Different AAD

    ByteArray ciphertext(plaintext.size());
    Poly1305Tag tag{};

    auto result = chacha20_poly1305_encrypt(
        key, nonce, ByteSpan(plaintext), ByteSpan(aad1),
        MutableByteSpan(ciphertext), tag);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Decrypt with wrong AAD
    ByteArray decrypted(plaintext.size());
    result = chacha20_poly1305_decrypt(
        key, nonce, ByteSpan(ciphertext), ByteSpan(aad2),
        tag, MutableByteSpan(decrypted));

    REQUIRE(result == ErrorCode::TAG_MISMATCH);
}

TEST_CASE("ChaCha20-Poly1305 buffer too small", "[crypto][chacha20]") {
    ChaCha20Key key{};
    ChaCha20Nonce nonce{};
    ByteArray plaintext = {1, 2, 3, 4, 5};
    ByteArray small_output(3);  // Too small
    Poly1305Tag tag{};

    auto result = chacha20_poly1305_encrypt(
        key, nonce, ByteSpan(plaintext), {},
        MutableByteSpan(small_output), tag);

    REQUIRE(result == ErrorCode::BUFFER_TOO_SMALL);
}

TEST_CASE("ChaCha20-Poly1305 empty plaintext", "[crypto][chacha20]") {
    ChaCha20Key key{};
    ChaCha20Nonce nonce{};
    ByteArray plaintext;
    ByteArray ciphertext;
    Poly1305Tag tag{};

    auto result = chacha20_poly1305_encrypt(
        key, nonce, ByteSpan(plaintext), {},
        MutableByteSpan(ciphertext), tag);

    REQUIRE(result == ErrorCode::SUCCESS);

    ByteArray decrypted;
    result = chacha20_poly1305_decrypt(
        key, nonce, ByteSpan(ciphertext), {},
        tag, MutableByteSpan(decrypted));

    REQUIRE(result == ErrorCode::SUCCESS);
    REQUIRE(decrypted.empty());
}