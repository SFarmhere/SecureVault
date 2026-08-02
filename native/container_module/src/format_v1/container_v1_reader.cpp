// ============================================================================
// SecureVault - Container Format v1 Reader
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Reads and validates format v1 encrypted containers.
//   Handles header parsing, key unwrapping, metadata decryption,
//   and data block reading.
// ============================================================================

#include "format_v1.h"
#include "metadata.h"
#include "container_api.h"
#include "logging.h"
#include "crypto_api.h"

#include <cstring>
#include <fstream>
#include <sstream>

namespace securevault {
namespace container {

// ============================================================================
// READER HELPERS
// ============================================================================

namespace {

/// Read uint32_t in big-endian order
uint32_t read_u32_be(std::istream& in) {
    uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
        value = (value << 8) | static_cast<uint8_t>(in.get());
    }
    return value;
}

/// Read uint64_t in big-endian order
uint64_t read_u64_be(std::istream& in) {
    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value = (value << 8) | static_cast<uint8_t>(in.get());
    }
    return value;
}

/// Derive container key from password (same as writer)
ErrorCode derive_container_key(
    const std::string& password,
    const std::array<uint8_t, 16>& salt,
    Aes256Key& key
) {
    if (password.empty()) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    Pbkdf2Params params;
    params.iterations = 600000;
    params.hash_length = 32;
    params.hash_algorithm = HashAlgorithm::SHA256;
    std::copy(salt.begin(), salt.end(), params.salt.begin());

    auto& ctx = crypto::CryptoContext::instance();
    auto result = ctx.derive_pbkdf2(
        ByteSpan(reinterpret_cast<const uint8_t*>(password.data()), password.size()),
        params
    );

    if (!result.success) {
        return static_cast<ErrorCode>(result.error_code);
    }

    std::copy(result.value.begin(), result.value.end(), key.begin());
    return ErrorCode::SUCCESS;
}

} // anonymous namespace

// ============================================================================
// CONTAINER READER
// ============================================================================

/// Open and read a format v1 container
/// @param path Container file path
/// @param password Container password
/// @param header Output parsed header
/// @param container_key Output decrypted container key
/// @param metadata Output decrypted container metadata
/// @return ErrorCode::SUCCESS on success
ErrorCode open_container_v1(
    const std::filesystem::path& path,
    const std::string& password,
    ContainerV1Header& header,
    Aes256Key& container_key,
    ContainerMetadata& metadata
) {
    // Open file
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return ErrorCode::FILE_NOT_FOUND;
    }

    // Read header
    std::array<uint8_t, CONTAINER_V1_HEADER_SIZE> header_buffer{};
    file.read(reinterpret_cast<char*>(header_buffer.data()), CONTAINER_V1_HEADER_SIZE);
    if (file.gcount() != CONTAINER_V1_HEADER_SIZE) {
        return static_cast<ErrorCode>(ContainerError::CONTAINER_HEADER_CORRUPTED);
    }

    auto header_result = header.deserialize(
        ByteSpan(header_buffer.data(), header_buffer.size()));
    if (header_result != ErrorCode::SUCCESS) {
        return header_result;
    }

    // Read key blob
    // Format: [method 4B][salt 16B][iv 12B][encrypted_key N B][tag 16B]
    uint32_t wrapping_method = read_u32_be(file);

    std::array<uint8_t, 16> salt{};
    file.read(reinterpret_cast<char*>(salt.data()), salt.size());

    std::array<uint8_t, 12> iv{};
    file.read(reinterpret_cast<char*>(iv.data()), iv.size());

    // Determine encrypted key size
    size_t encrypted_key_size = 0;
    if (wrapping_method == 0) {
        // Password-derived: AES-256-GCM encrypted 32-byte key
        encrypted_key_size = 32;
    } else if (wrapping_method == 1) {
        // RSA-OAEP: key_size bytes
        encrypted_key_size = header.rsa_key_bits / 8;
    } else {
        return ErrorCode::INVALID_FORMAT;
    }

    std::vector<uint8_t> encrypted_key(encrypted_key_size);
    file.read(reinterpret_cast<char*>(encrypted_key.data()),
              static_cast<std::streamsize>(encrypted_key_size));

    std::array<uint8_t, 16> tag{};
    file.read(reinterpret_cast<char*>(tag.data()), tag.size());

    // Unwrap the container key
    if (wrapping_method == 0) {
        // Password-derived: derive KEK and decrypt
        Aes256Key kek{};
        auto derive_result = derive_container_key(password, salt, kek);
        if (derive_result != ErrorCode::SUCCESS) {
            return derive_result;
        }

        // Reconstruct encrypted format: [iv 12B][ciphertext 32B][tag 16B]
        ByteArray encrypted;
        encrypted.reserve(12 + 32 + 16);
        encrypted.insert(encrypted.end(), iv.begin(), iv.end());
        encrypted.insert(encrypted.end(), encrypted_key.begin(), encrypted_key.end());
        encrypted.insert(encrypted.end(), tag.begin(), tag.end());

        auto& ctx = crypto::CryptoContext::instance();
        auto result = ctx.aes_gcm_decrypt(kek, ByteSpan(encrypted));
        if (!result.success) {
            return static_cast<ErrorCode>(result.error_code);
        }

        if (result.value.size() != 32) {
            return static_cast<ErrorCode>(CryptoError::DECRYPTION_FAILED);
        }
        std::copy(result.value.begin(), result.value.end(), container_key.begin());
    } else if (wrapping_method == 1) {
        // RSA-OAEP unwrapping
        // Note: Requires the private key, which is passed separately
        return ErrorCode::NOT_IMPLEMENTED;
    }

    // Read metadata length
    uint64_t metadata_size = read_u64_be(file);
    if (metadata_size > CONTAINER_MAX_METADATA_SIZE) {
        return static_cast<ErrorCode>(ContainerError::CONTAINER_METADATA_CORRUPTED);
    }

    // Read encrypted metadata
    std::vector<uint8_t> encrypted_metadata(static_cast<size_t>(metadata_size));
    file.read(reinterpret_cast<char*>(encrypted_metadata.data()),
              static_cast<std::streamsize>(encrypted_metadata.size()));

    // Decrypt metadata
    auto& ctx = crypto::CryptoContext::instance();
    auto meta_result = ctx.aes_gcm_decrypt(container_key, ByteSpan(encrypted_metadata));
    if (!meta_result.success) {
        return static_cast<ErrorCode>(meta_result.error_code);
    }

    // Parse metadata
    auto parse_result = deserialize_container_metadata(
        ByteSpan(meta_result.value), metadata);
    if (parse_result != ErrorCode::SUCCESS) {
        return parse_result;
    }

    file.close();

    LOG_INFO("container", "v1_reader", "Opened container {} ({} files, {} bytes used)",
             header.container_id, metadata.file_count, metadata.used_size);

    return ErrorCode::SUCCESS;
}

// ============================================================================
// FILE EXTRACTION
// ============================================================================

/// Extract a file from a format v1 container
/// @param path Container file path
/// @param container_key Container decryption key
/// @param file_metadata File metadata
/// @param output_path Path to write the extracted file
/// @return ErrorCode::SUCCESS on success
ErrorCode extract_file_v1(
    const std::filesystem::path& path,
    const Aes256Key& container_key,
    const ContainerFileMetadata& file_metadata,
    const std::filesystem::path& output_path
) {
    // Open container file
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return ErrorCode::FILE_NOT_FOUND;
    }

    // Skip header
    file.seekg(CONTAINER_V1_HEADER_SIZE, std::ios::beg);

    // Skip key blob
    uint32_t wrapping_method = read_u32_be(file);
    file.seekg(16, std::ios::cur);  // salt
    file.seekg(12, std::ios::cur);  // iv
    size_t key_size = (wrapping_method == 1) ? 256 : 32;
    file.seekg(static_cast<std::streamoff>(key_size), std::ios::cur);
    file.seekg(16, std::ios::cur);  // tag

    // Skip metadata
    uint64_t metadata_size = read_u64_be(file);
    file.seekg(static_cast<std::streamoff>(metadata_size), std::ios::cur);

    // Read data blocks
    auto& ctx = crypto::CryptoContext::instance();
    std::ofstream output(output_path, std::ios::binary);
    if (!output.is_open()) {
        return ErrorCode::FILE_ACCESS_DENIED;
    }

    for (uint64_t block_index : file_metadata.block_indices) {
        // Read block header
        uint64_t index = read_u64_be(file);
        uint64_t original_size = read_u64_be(file);
        uint64_t stored_size = read_u64_be(file);
        uint32_t compression = read_u32_be(file);

        std::array<uint8_t, 12> block_iv{};
        file.read(reinterpret_cast<char*>(block_iv.data()), block_iv.size());

        std::vector<uint8_t> encrypted_block(static_cast<size_t>(stored_size));
        file.read(reinterpret_cast<char*>(encrypted_block.data()),
                  static_cast<std::streamsize>(stored_size));

        std::array<uint8_t, 16> block_tag{};
        file.read(reinterpret_cast<char*>(block_tag.data()), block_tag.size());

        // Decrypt block
        ByteArray encrypted;
        encrypted.reserve(12 + stored_size + 16);
        encrypted.insert(encrypted.end(), block_iv.begin(), block_iv.end());
        encrypted.insert(encrypted.end(), encrypted_block.begin(), encrypted_block.end());
        encrypted.insert(encrypted.end(), block_tag.begin(), block_tag.end());

        auto result = ctx.aes_gcm_decrypt(container_key, ByteSpan(encrypted));
        if (!result.success) {
            output.close();
            return static_cast<ErrorCode>(result.error_code);
        }

        // Write decrypted block
        output.write(reinterpret_cast<const char*>(result.value.data()),
                     static_cast<std::streamsize>(result.value.size()));
    }

    output.close();
    file.close();

    return ErrorCode::SUCCESS;
}

} // namespace container
} // namespace securevault