// ============================================================================
// SecureVault - Kyber1024 Post-Quantum Cipher Suite Tests
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Unit tests for Kyber1024 key encapsulation mechanism (KEM).
//   Tests key generation, encapsulation/decapsulation round-trip,
//   and key serialization.
// ============================================================================

#include "catch2/catch_test_macros.hpp"

#include "cipher_suites/kyber1024.h"

using namespace securevault;
using namespace securevault::crypto;

// ============================================================================
// KEY GENERATION
// ============================================================================

TEST_CASE("Kyber1024 key generation", "[crypto][kyber]") {
    KyberKeyPair key_pair;

    auto result = kyber1024_generate_keypair(key_pair);

    REQUIRE(result == ErrorCode::SUCCESS);
    REQUIRE(key_pair.public_key.size() == KYBER1024_PUBLIC_KEY_SIZE);
    REQUIRE(key_pair.secret_key.size() == KYBER1024_SECRET_KEY_SIZE);

    // Keys should not be all zeros
    bool has_nonzero = false;
    for (uint8_t byte : key_pair.public_key) {
        if (byte != 0) {
            has_nonzero = true;
            break;
        }
    }
    REQUIRE(has_nonzero);
}

TEST_CASE("Kyber1024 key generation produces unique keys", "[crypto][kyber]") {
    KyberKeyPair key_pair1;
    KyberKeyPair key_pair2;

    auto result1 = kyber1024_generate_keypair(key_pair1);
    auto result2 = kyber1024_generate_keypair(key_pair2);

    REQUIRE(result1 == ErrorCode::SUCCESS);
    REQUIRE(result2 == ErrorCode::SUCCESS);

    // Public keys should differ
    REQUIRE(key_pair1.public_key != key_pair2.public_key);
}

// ============================================================================
// ENCAPSULATION / DECAPSULATION
// ============================================================================

TEST_CASE("Kyber1024 encapsulate/decapsulate round-trip", "[crypto][kyber]") {
    KyberKeyPair key_pair;
    auto result = kyber1024_generate_keypair(key_pair);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Encapsulate
    KyberEncapsulation encapsulation;
    result = kyber1024_encapsulate(key_pair.public_key, encapsulation);
    REQUIRE(result == ErrorCode::SUCCESS);
    REQUIRE(encapsulation.ciphertext.size() == KYBER1024_CIPHERTEXT_SIZE);
    REQUIRE(encapsulation.shared_secret.size() == KYBER1024_SHARED_SECRET_SIZE);

    // Decapsulate
    std::array<uint8_t, KYBER1024_SHARED_SECRET_SIZE> shared_secret{};
    result = kyber1024_decapsulate(key_pair.secret_key, encapsulation.ciphertext,
                                   shared_secret);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Shared secrets should match
    REQUIRE(shared_secret == encapsulation.shared_secret);
}

TEST_CASE("Kyber1024 decapsulation with wrong key fails", "[crypto][kyber]") {
    KyberKeyPair key_pair1;
    KyberKeyPair key_pair2;
    auto result1 = kyber1024_generate_keypair(key_pair1);
    auto result2 = kyber1024_generate_keypair(key_pair2);
    REQUIRE(result1 == ErrorCode::SUCCESS);
    REQUIRE(result2 == ErrorCode::SUCCESS);

    // Encapsulate with key1 public key
    KyberEncapsulation encapsulation;
    result1 = kyber1024_encapsulate(key_pair1.public_key, encapsulation);
    REQUIRE(result1 == ErrorCode::SUCCESS);

    // Decapsulate with key2 secret key (wrong key)
    std::array<uint8_t, KYBER1024_SHARED_SECRET_SIZE> shared_secret{};
    result2 = kyber1024_decapsulate(key_pair2.secret_key, encapsulation.ciphertext,
                                    shared_secret);
    REQUIRE(result2 == ErrorCode::SUCCESS);

    // Shared secrets should NOT match (implicit rejection)
    REQUIRE(shared_secret != encapsulation.shared_secret);
}

TEST_CASE("Kyber1024 decapsulation with corrupted ciphertext", "[crypto][kyber]") {
    KyberKeyPair key_pair;
    auto result = kyber1024_generate_keypair(key_pair);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Encapsulate
    KyberEncapsulation encapsulation;
    result = kyber1024_encapsulate(key_pair.public_key, encapsulation);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Corrupt ciphertext
    Kyber1024Ciphertext corrupted = encapsulation.ciphertext;
    corrupted[0] ^= 0xFF;

    // Decapsulate with corrupted ciphertext
    std::array<uint8_t, KYBER1024_SHARED_SECRET_SIZE> shared_secret{};
    result = kyber1024_decapsulate(key_pair.secret_key, corrupted, shared_secret);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Shared secrets should NOT match (implicit rejection)
    REQUIRE(shared_secret != encapsulation.shared_secret);
}

// ============================================================================
// KEY SERIALIZATION
// ============================================================================

TEST_CASE("Kyber1024 public key serialization", "[crypto][kyber]") {
    KyberKeyPair key_pair;
    auto result = kyber1024_generate_keypair(key_pair);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Serialize
    ByteArray serialized;
    kyber1024_public_key_to_bytes(key_pair.public_key, serialized);
    REQUIRE(serialized.size() == KYBER1024_PUBLIC_KEY_SIZE);

    // Deserialize
    Kyber1024PublicKey deserialized{};
    result = kyber1024_public_key_from_bytes(ByteSpan(serialized), deserialized);
    REQUIRE(result == ErrorCode::SUCCESS);
    REQUIRE(deserialized == key_pair.public_key);
}

TEST_CASE("Kyber1024 secret key serialization", "[crypto][kyber]") {
    KyberKeyPair key_pair;
    auto result = kyber1024_generate_keypair(key_pair);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Serialize
    ByteArray serialized;
    kyber1024_secret_key_to_bytes(key_pair.secret_key, serialized);
    REQUIRE(serialized.size() == KYBER1024_SECRET_KEY_SIZE);

    // Deserialize
    Kyber1024SecretKey deserialized{};
    result = kyber1024_secret_key_from_bytes(ByteSpan(serialized), deserialized);
    REQUIRE(result == ErrorCode::SUCCESS);
    REQUIRE(deserialized == key_pair.secret_key);
}

TEST_CASE("Kyber1024 serialization invalid size", "[crypto][kyber]") {
    Kyber1024PublicKey public_key{};
    ByteArray too_short(100);  // Wrong size

    auto result = kyber1024_public_key_from_bytes(ByteSpan(too_short), public_key);
    REQUIRE(result == ErrorCode::INVALID_ARGUMENT);

    Kyber1024SecretKey secret_key{};
    ByteArray too_long(KYBER1024_SECRET_KEY_SIZE + 10);  // Wrong size

    result = kyber1024_secret_key_from_bytes(ByteSpan(too_long), secret_key);
    REQUIRE(result == ErrorCode::INVALID_ARGUMENT);
}

// ============================================================================
// FULL KEM FLOW
// ============================================================================

TEST_CASE("Kyber1024 full KEM flow with serialization", "[crypto][kyber]") {
    // Alice generates key pair
    KyberKeyPair alice_keys;
    auto result = kyber1024_generate_keypair(alice_keys);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Alice serializes public key and sends to Bob
    ByteArray alice_pk_bytes;
    kyber1024_public_key_to_bytes(alice_keys.public_key, alice_pk_bytes);

    // Bob deserializes Alice's public key
    Kyber1024PublicKey alice_pk{};
    result = kyber1024_public_key_from_bytes(ByteSpan(alice_pk_bytes), alice_pk);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Bob encapsulates shared secret
    KyberEncapsulation bob_encapsulation;
    result = kyber1024_encapsulate(alice_pk, bob_encapsulation);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Bob sends ciphertext to Alice
    Kyber1024Ciphertext bob_ct = bob_encapsulation.ciphertext;

    // Alice decapsulates shared secret
    std::array<uint8_t, KYBER1024_SHARED_SECRET_SIZE> alice_shared{};
    result = kyber1024_decapsulate(alice_keys.secret_key, bob_ct, alice_shared);
    REQUIRE(result == ErrorCode::SUCCESS);

    // Both shared secrets should match
    REQUIRE(alice_shared == bob_encapsulation.shared_secret);
}