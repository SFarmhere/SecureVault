// ============================================================================
// SecureVault - RSA Encryption
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   RSA-2048/4096 encryption, decryption, and digital signatures.
//   Uses OAEP padding for encryption and PSS padding for signatures.
//   All operations are constant-time to prevent side-channel attacks.
// ============================================================================

#ifndef SECUREVAULT_RSA_H
#define SECUREVAULT_RSA_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>

#include "common_types.h"
#include "error_codes.h"

namespace securevault {
namespace crypto {

// ============================================================================
// RSA KEY TYPES
// ============================================================================

/// RSA public key
struct RsaPublicKey {
    /// Modulus (n) in big-endian byte order
    std::vector<uint8_t> modulus;

    /// Public exponent (e), typically 65537
    uint32_t exponent = 65537;

    /// Key size in bits (2048 or 4096)
    uint32_t bits = 2048;

    /// Whether the key is valid
    bool is_valid() const {
        return !modulus.empty() && (bits == 2048 || bits == 4096);
    }
};

/// RSA private key
struct RsaPrivateKey {
    /// Modulus (n) in big-endian byte order
    std::vector<uint8_t> modulus;

    /// Public exponent (e)
    uint32_t public_exponent = 65537;

    /// Private exponent (d) in big-endian byte order
    std::vector<uint8_t> private_exponent;

    /// First prime factor (p)
    std::vector<uint8_t> prime_p;

    /// Second prime factor (q)
    std::vector<uint8_t> prime_q;

    /// CRT exponent d mod (p-1)
    std::vector<uint8_t> dmp1;

    /// CRT exponent d mod (q-1)
    std::vector<uint8_t> dmq1;

    /// CRT coefficient q^-1 mod p
    std::vector<uint8_t> iqmp;

    /// Key size in bits (2048 or 4096)
    uint32_t bits = 2048;

    /// Whether the key is valid
    bool is_valid() const {
        return !modulus.empty() && !private_exponent.empty() &&
               (bits == 2048 || bits == 4096);
    }
};

/// RSA key pair
struct RsaKeyPair {
    RsaPublicKey public_key;
    RsaPrivateKey private_key;
};

// ============================================================================
// RSA OPERATIONS
// ============================================================================

/// Generate an RSA key pair
/// @param bits Key size in bits (2048 or 4096)
/// @param key_pair Output key pair
/// @return ErrorCode::SUCCESS on success
ErrorCode rsa_generate_keypair(
    uint32_t bits,
    RsaKeyPair& key_pair
);

/// Encrypt data with RSA public key (OAEP-SHA256 padding)
/// @param public_key RSA public key
/// @param plaintext Data to encrypt (max size = bits/8 - 66 bytes for SHA-256 OAEP)
/// @param ciphertext Output ciphertext (size = bits/8 bytes)
/// @return ErrorCode::SUCCESS on success
ErrorCode rsa_encrypt_oaep(
    const RsaPublicKey& public_key,
    ByteSpan plaintext,
    MutableByteSpan ciphertext
);

/// Decrypt data with RSA private key (OAEP-SHA256 padding)
/// @param private_key RSA private key
/// @param ciphertext Data to decrypt (size = bits/8 bytes)
/// @param plaintext Output plaintext
/// @return ErrorCode::SUCCESS on success
ErrorCode rsa_decrypt_oaep(
    const RsaPrivateKey& private_key,
    ByteSpan ciphertext,
    MutableByteSpan plaintext
);

/// Sign data with RSA private key (PSS-SHA256 padding)
/// @param private_key RSA private key
/// @param data Data to sign
/// @param signature Output signature (size = bits/8 bytes)
/// @return ErrorCode::SUCCESS on success
ErrorCode rsa_sign_pss(
    const RsaPrivateKey& private_key,
    ByteSpan data,
    MutableByteSpan signature
);

/// Verify RSA signature (PSS-SHA256 padding)
/// @param public_key RSA public key
/// @param data Data that was signed
/// @param signature Signature to verify (size = bits/8 bytes)
/// @return ErrorCode::SUCCESS if valid, SIGNATURE_INVALID otherwise
ErrorCode rsa_verify_pss(
    const RsaPublicKey& public_key,
    ByteSpan data,
    ByteSpan signature
);

// ============================================================================
// KEY SERIALIZATION
// ============================================================================

/// Export RSA public key to DER-encoded SubjectPublicKeyInfo
/// @param public_key RSA public key
/// @param der Output DER-encoded key
/// @return ErrorCode::SUCCESS on success
ErrorCode rsa_public_key_to_der(
    const RsaPublicKey& public_key,
    ByteArray& der
);

/// Import RSA public key from DER-encoded SubjectPublicKeyInfo
/// @param der DER-encoded key
/// @param public_key Output RSA public key
/// @return ErrorCode::SUCCESS on success
ErrorCode rsa_public_key_from_der(
    ByteSpan der,
    RsaPublicKey& public_key
);

/// Export RSA private key to PKCS#8 DER-encoded format
/// @param private_key RSA private key
/// @param der Output DER-encoded key
/// @return ErrorCode::SUCCESS on success
ErrorCode rsa_private_key_to_der(
    const RsaPrivateKey& private_key,
    ByteArray& der
);

/// Import RSA private key from PKCS#8 DER-encoded format
/// @param der DER-encoded key
/// @param private_key Output RSA private key
/// @return ErrorCode::SUCCESS on success
ErrorCode rsa_private_key_from_der(
    ByteSpan der,
    RsaPrivateKey& private_key
);

} // namespace crypto
} // namespace securevault

#endif // SECUREVAULT_RSA_H