// ============================================================================
// SecureVault - Kyber1024 Post-Quantum Cipher Suite
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Kyber1024 post-quantum key encapsulation mechanism (KEM).
//   NIST-selected CRYSTALS-Kyber, security level 5 (AES-256 equivalent).
//   Provides quantum-resistant key exchange.
// ============================================================================

#ifndef SECUREVAULT_KYBER1024_H
#define SECUREVAULT_KYBER1024_H

#include <cstdint>
#include <array>
#include <vector>

#include "common_types.h"
#include "error_codes.h"

namespace securevault {
namespace crypto {

// ============================================================================
// KYBER1024 CONSTANTS
// ============================================================================

/// Kyber1024 public key size in bytes
constexpr size_t KYBER1024_PUBLIC_KEY_SIZE = 1568;

/// Kyber1024 secret key size in bytes
constexpr size_t KYBER1024_SECRET_KEY_SIZE = 3168;

/// Kyber1024 ciphertext size in bytes
constexpr size_t KYBER1024_CIPHERTEXT_SIZE = 1568;

/// Kyber1024 shared secret size in bytes
constexpr size_t KYBER1024_SHARED_SECRET_SIZE = 32;

// ============================================================================
// KYBER1024 KEY TYPES
// ============================================================================

/// Kyber1024 key pair
struct KyberKeyPair {
    /// Public key (1568 bytes)
    Kyber1024PublicKey public_key{};

    /// Secret key (3168 bytes)
    Kyber1024SecretKey secret_key{};
};

/// Result of Kyber1024 encapsulation
struct KyberEncapsulation {
    /// Ciphertext (1568 bytes)
    Kyber1024Ciphertext ciphertext{};

    /// Shared secret (32 bytes)
    std::array<uint8_t, KYBER1024_SHARED_SECRET_SIZE> shared_secret{};
};

// ============================================================================
// KYBER1024 OPERATIONS
// ============================================================================

/// Generate a Kyber1024 key pair
/// @param key_pair Output key pair
/// @return ErrorCode::SUCCESS on success
ErrorCode kyber1024_generate_keypair(
    KyberKeyPair& key_pair
);

/// Encapsulate a shared secret with Kyber1024 public key
/// @param public_key Kyber1024 public key (1568 bytes)
/// @param encapsulation Output ciphertext + shared secret
/// @return ErrorCode::SUCCESS on success
ErrorCode kyber1024_encapsulate(
    const Kyber1024PublicKey& public_key,
    KyberEncapsulation& encapsulation
);

/// Decapsulate a shared secret with Kyber1024 secret key
/// @param secret_key Kyber1024 secret key (3168 bytes)
/// @param ciphertext Kyber1024 ciphertext (1568 bytes)
/// @param shared_secret Output 32-byte shared secret
/// @return ErrorCode::SUCCESS on success
ErrorCode kyber1024_decapsulate(
    const Kyber1024SecretKey& secret_key,
    const Kyber1024Ciphertext& ciphertext,
    std::array<uint8_t, KYBER1024_SHARED_SECRET_SIZE>& shared_secret
);

// ============================================================================
// KYBER1024 KEY SERIALIZATION
// ============================================================================

/// Serialize Kyber1024 public key to bytes
/// @param public_key Kyber1024 public key
/// @param output Output byte array (1568 bytes)
void kyber1024_public_key_to_bytes(
    const Kyber1024PublicKey& public_key,
    ByteArray& output
);

/// Deserialize Kyber1024 public key from bytes
/// @param input Input byte array (1568 bytes)
/// @param public_key Output Kyber1024 public key
/// @return ErrorCode::SUCCESS on success
ErrorCode kyber1024_public_key_from_bytes(
    ByteSpan input,
    Kyber1024PublicKey& public_key
);

/// Serialize Kyber1024 secret key to bytes
/// @param secret_key Kyber1024 secret key
/// @param output Output byte array (3168 bytes)
void kyber1024_secret_key_to_bytes(
    const Kyber1024SecretKey& secret_key,
    ByteArray& output
);

/// Deserialize Kyber1024 secret key from bytes
/// @param input Input byte array (3168 bytes)
/// @param secret_key Output Kyber1024 secret key
/// @return ErrorCode::SUCCESS on success
ErrorCode kyber1024_secret_key_from_bytes(
    ByteSpan input,
    Kyber1024SecretKey& secret_key
);

} // namespace crypto
} // namespace securevault

#endif // SECUREVAULT_KYBER1024_H