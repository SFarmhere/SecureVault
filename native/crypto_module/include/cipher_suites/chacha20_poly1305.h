// ============================================================================
// SecureVault - ChaCha20-Poly1305 Cipher Suite
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   ChaCha20-Poly1305 authenticated encryption cipher suite.
//   Alternative symmetric cipher, faster on CPUs without AES-NI.
// ============================================================================

#ifndef SECUREVAULT_CHACHA20_POLY1305_H
#define SECUREVAULT_CHACHA20_POLY1305_H

#include <cstdint>
#include <array>
#include <vector>

#include "common_types.h"
#include "error_codes.h"

namespace securevault {
namespace crypto {

// ============================================================================
// CHACHA20-POLY1305 CONSTANTS
// ============================================================================

/// ChaCha20 block size in bytes
constexpr size_t CHACHA20_BLOCK_SIZE = 64;

/// ChaCha20 key size in bytes (256-bit)
constexpr size_t CHACHA20_KEY_SIZE = 32;

/// ChaCha20 nonce size in bytes (96-bit)
constexpr size_t CHACHA20_NONCE_SIZE = 12;

/// Poly1305 tag size in bytes
constexpr size_t POLY1305_TAG_SIZE = 16;

// ============================================================================
// CHACHA20-POLY1305 OPERATIONS
// ============================================================================

/// Encrypt data with ChaCha20-Poly1305
/// @param key 256-bit ChaCha20 key
/// @param nonce 12-byte nonce
/// @param plaintext Data to encrypt
/// @param aad Additional authenticated data (optional)
/// @param output Output buffer for ciphertext (size = plaintext.size())
/// @param tag Output buffer for 16-byte Poly1305 tag
/// @return ErrorCode::SUCCESS on success
ErrorCode chacha20_poly1305_encrypt(
    const ChaCha20Key& key,
    const ChaCha20Nonce& nonce,
    ByteSpan plaintext,
    ByteSpan aad,
    MutableByteSpan output,
    Poly1305Tag& tag
);

/// Decrypt data with ChaCha20-Poly1305
/// @param key 256-bit ChaCha20 key
/// @param nonce 12-byte nonce
/// @param ciphertext Data to decrypt
/// @param aad Additional authenticated data (optional)
/// @param tag 16-byte Poly1305 tag
/// @param output Output buffer for plaintext (size = ciphertext.size())
/// @return ErrorCode::SUCCESS on success, TAG_MISMATCH if authentication fails
ErrorCode chacha20_poly1305_decrypt(
    const ChaCha20Key& key,
    const ChaCha20Nonce& nonce,
    ByteSpan ciphertext,
    ByteSpan aad,
    const Poly1305Tag& tag,
    MutableByteSpan output
);

// ============================================================================
// CHACHA20 STREAM CIPHER (low-level)
// ============================================================================

/// Generate ChaCha20 keystream block
/// @param key 256-bit ChaCha20 key
/// @param nonce 12-byte nonce
/// @param counter 32-bit block counter
/// @param output Output buffer for 64-byte keystream block
void chacha20_block(
    const ChaCha20Key& key,
    const ChaCha20Nonce& nonce,
    uint32_t counter,
    std::array<uint8_t, CHACHA20_BLOCK_SIZE>& output
);

/// XOR data with ChaCha20 keystream
/// @param key 256-bit ChaCha20 key
/// @param nonce 12-byte nonce
/// @param counter Initial block counter
/// @param input Input data
/// @param output Output buffer (size = input.size())
void chacha20_xor(
    const ChaCha20Key& key,
    const ChaCha20Nonce& nonce,
    uint32_t counter,
    ByteSpan input,
    MutableByteSpan output
);

// ============================================================================
// POLY1305 MAC (low-level)
// ============================================================================

/// Compute Poly1305 MAC
/// @param key 32-byte Poly1305 key
/// @param data Data to authenticate
/// @param tag Output 16-byte MAC
void poly1305_mac(
    const std::array<uint8_t, 32>& key,
    ByteSpan data,
    Poly1305Tag& tag
);

} // namespace crypto
} // namespace securevault

#endif // SECUREVAULT_CHACHA20_POLY1305_H