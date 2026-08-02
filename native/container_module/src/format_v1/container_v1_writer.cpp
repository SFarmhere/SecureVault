// ============================================================================
// SecureVault - Container Format v1 Writer
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Creates and writes format v1 encrypted containers.
//   Handles header serialization, key wrapping, metadata encryption,
//   and data block writing.
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
// CRC32 IMPLEMENTATION
// ============================================================================

namespace {

/// CRC32 lookup table
std::array<uint32_t, 256> crc32_table() {
    std::array<uint32_t, 256> table{};
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t crc = i;
        for (uint32_t j = 0; j < 8; ++j) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320 : crc >> 1;
        }
        table[i] = crc;
    }
    return table;
}

/// Compute CRC32 checksum
uint32_t crc32(const uint8_t* data, size_t length) {
    static const auto table = crc32_table();
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc = (crc >> 8) ^ table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFF;
}

/// Write uint32_t in big-endian order
void write_u32_be(std::ostream& out, uint32_t value) {
    out.put(static_cast<char>((value >> 24) & 0xFF));
    out.put(static_cast<char>((value >> 16) & 0xFF));
    out.put(static_cast<char>((value >> 8) & 0xFF));
    out.put(static_cast<char>(value & 0xFF));
}

/// Write uint64_t in big-endian order
void write_u64_be(std::ostream& out, uint64_t value) {
    for (int i = 7; i >= 0; --i) {
        out.put(static_cast<char>((value >> (i * 8)) & 0xFF));
    }
}

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

} // anonymous namespace

// ============================================================================
// HEADER SERIALIZATION
// ============================================================================

ErrorCode ContainerV1Header::serialize(MutableByteSpan output) const {
    if (output.size < CONTAINER_V1_HEADER_SIZE) {
        return ErrorCode::BUFFER_TOO_SMALL;
    }

    std::ostringstream oss(std::ios::binary);

    // Magic
    oss.write(reinterpret_cast<const char*>(magic.data()), magic.size());

    // Version
    write_u32_be(oss, version);

    // Container ID
    oss.write(reinterpret_cast<const char*>(container_id.data()), container_id.size());

    // Security level
    write_u32_be(oss, static_cast<uint32_t>(security_level));

    // KDF algorithm
    write_u32_be(oss, static_cast<uint32_t>(kdf_algorithm));

    // KDF params
    oss.write(reinterpret_cast<const char*>(kdf_params.data()), kdf_params.size());

    // Key wrapping method
    write_u32_be(oss, key_wrapping_method);

    // RSA key bits
    write_u32_be(oss, rsa_key_bits);

    // Compression
    write_u32_be(oss, static_cast<uint32_t>(compression));

    // Deduplication
    write_u32_be(oss, deduplication_enabled);

    // WAL
    write_u32_be(oss, wal_enabled);

    // Block size
    write_u32_be(oss, block_size);

    // Sizes
    write_u64_be(oss, total_size);
    write_u64_be(oss, used_size);

    // File count
    write_u32_be(oss, file_count);

    // Timestamps
    write_u64_be(oss, created_at);
    write_u64_be(oss, modified_at);

    // Reserved
    oss.write(reinterpret_cast<const char*>(reserved.data()), reserved.size());

    // Compute checksum of everything so far
    std::string header_bytes = oss.str();
    uint32_t checksum = crc32(
        reinterpret_cast<const uint8_t*>(header_bytes.data()),
        header_bytes.size());

    // Write checksum
    write_u32_be(oss, checksum);

    // Pad to header size
    std::string result = oss.str();
    if (result.size() < CONTAINER_V1_HEADER_SIZE) {
        result.resize(CONTAINER_V1_HEADER_SIZE, '\0');
    }

    std::memcpy(output.data, result.data(), CONTAINER_V1_HEADER_SIZE);
    return ErrorCode::SUCCESS;
}

ErrorCode ContainerV1Header::deserialize(ByteSpan input) {
    if (input.size < CONTAINER_V1_HEADER_SIZE) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    std::istringstream iss(std::string(
        reinterpret_cast<const char*>(input.data), CONTAINER_V1_HEADER_SIZE),
        std::ios::binary);

    // Magic
    iss.read(reinterpret_cast<char*>(magic.data()), magic.size());

    // Version
    version = read_u32_be(iss);

    // Container ID
    iss.read(reinterpret_cast<char*>(container_id.data()), container_id.size());

    // Security level
    security_level = static_cast<SecurityLevel>(read_u32_be(iss));

    // KDF algorithm
    kdf_algorithm = static_cast<KdfAlgorithm>(read_u32_be(iss));

    // KDF params
    iss.read(reinterpret_cast<char*>(kdf_params.data()), kdf_params.size());

    // Key wrapping method
    key_wrapping_method = read_u32_be(iss);

    // RSA key bits
    rsa_key_bits = read_u32_be(iss);

    // Compression
    compression = static_cast<CompressionAlgorithm>(read_u32_be(iss));

    // Deduplication
    deduplication_enabled = read_u32_be(iss);

    // WAL
    wal_enabled = read_u32_be(iss);

    // Block size
    block_size = read_u32_be(iss);

    // Sizes
    total_size = read_u64_be(iss);
    used_size = read_u64_be(iss);

    // File count
    file_count = read_u32_be(iss);

    // Timestamps
    created_at = read_u64_be(iss);
    modified_at = read_u64_be(iss);

    // Reserved
    iss.read(reinterpret_cast<char*>(reserved.data()), reserved.size());

    // Checksum
    header_checksum = read_u32_be(iss);

    return validate();
}

ErrorCode ContainerV1Header::validate() const {
    if (magic != CONTAINER_V1_MAGIC) {
        return static_cast<ErrorCode>(ContainerError::CONTAINER_FORMAT_INVALID);
    }
    if (version != CONTAINER_V1_VERSION) {
        return static_cast<ErrorCode>(ContainerError::CONTAINER_VERSION_UNSUPPORTED);
    }

    // Verify checksum
    uint32_t expected = compute_checksum();
    if (expected != header_checksum) {
        return static_cast<ErrorCode>(ContainerError::CONTAINER_HEADER_CORRUPTED);
    }

    return ErrorCode::SUCCESS;
}

uint32_t ContainerV1Header::compute_checksum() const {
    // Serialize without checksum and compute CRC32
    ContainerV1Header copy = *this;
    copy.header_checksum = 0;

    std::array<uint8_t, CONTAINER_V1_HEADER_SIZE> buffer{};
    MutableByteSpan span(buffer.data(), buffer.size());
    if (copy.serialize(span) != ErrorCode::SUCCESS) {
        return 0;
    }

    return crc32(buffer.data(), CONTAINER_V1_HEADER_SIZE - 4);
}

// ============================================================================
// KEY BLOB SERIALIZATION
// ============================================================================

void ContainerV1KeyBlob::serialize(ByteArray& output) const {
    output.clear();
    output.reserve(4 + 16 + 12 + encrypted_key.size() + 16);

    // Wrapping method
    output.push_back(static_cast<uint8_t>((wrapping_method >> 24) & 0xFF));
    output.push_back(static_cast<uint8_t>((wrapping_method >> 16) & 0xFF));
    output.push_back(static_cast<uint8_t>((wrapping_method >> 8) & 0xFF));
    output.push_back(static_cast<uint8_t>(wrapping_method & 0xFF));

    // Salt
    output.insert(output.end(), salt.begin(), salt.end());

    // IV
    output.insert(output.end(), iv.begin(), iv.end());

    // Encrypted key
    output.insert(output.end(), encrypted_key.begin(), encrypted_key.end());

    // Tag
    output.insert(output.end(), tag.begin(), tag.end());
}

ErrorCode ContainerV1KeyBlob::deserialize(ByteSpan input) {
    if (input.size < 4 + 16 + 12 + 16) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    size_t offset = 0;

    // Wrapping method
    wrapping_method = (static_cast<uint32_t>(input.data[offset]) << 24) |
                      (static_cast<uint32_t>(input.data[offset + 1]) << 16) |
                      (static_cast<uint32_t>(input.data[offset + 2]) << 8) |
                      static_cast<uint32_t>(input.data[offset + 3]);
    offset += 4;

    // Salt
    std::copy(input.data + offset, input.data + offset + 16, salt.begin());
    offset += 16;

    // IV
    std::copy(input.data + offset, input.data + offset + 12, iv.begin());
    offset += 12;

    // Encrypted key (rest minus tag)
    size_t key_size = input.size - offset - 16;
    encrypted_key.assign(input.data + offset, input.data + offset + key_size);
    offset += key_size;

    // Tag
    std::copy(input.data + offset, input.data + offset + 16, tag.begin());

    return ErrorCode::SUCCESS;
}

// ============================================================================
// CONTAINER WRITER (HIGH-LEVEL)
// ============================================================================

namespace {

/// Internal container writer state
struct ContainerWriter {
    std::ofstream file;
    ContainerV1Header header;
    ContainerV1KeyBlob key_blob;
    Aes256Key container_key{};
    bool key_initialized = false;

    ~ContainerWriter() {
        if (file.is_open()) {
            file.close();
        }
    }
};

/// Derive container key from password
ErrorCode derive_container_key(
    const std::string& password,
    const std::array<uint8_t, 16>& salt,
    Aes256Key& key
) {
    if (password.empty()) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    // Use PBKDF2-HMAC-SHA256 with 600k iterations
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
// PUBLIC WRITER FUNCTIONS
// ============================================================================

/// Create a new format v1 container file
/// @param path Container file path
/// @param options Container creation options
/// @param container_id Output container ID
/// @return ErrorCode::SUCCESS on success
ErrorCode create_container_v1(
    const std::filesystem::path& path,
    const ContainerCreateOptions& options,
    ContainerId& container_id
) {
    if (options.size == 0) {
        return ErrorCode::INVALID_ARGUMENT;
    }
    if (options.password.empty() && !options.wrapping_key.has_value()) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    // Generate container ID
    container_id = ContainerId::generate();

    // Create writer state
    ContainerWriter writer;
    writer.file.open(path, std::ios::binary | std::ios::out | std::ios::trunc);
    if (!writer.file.is_open()) {
        return ErrorCode::FILE_ACCESS_DENIED;
    }

    // Initialize header
    writer.header.container_id = container_id.bytes;
    writer.header.security_level = options.security_level;
    writer.header.compression = options.compression;
    writer.header.deduplication_enabled = options.enable_deduplication ? 1 : 0;
    writer.header.wal_enabled = options.enable_wal ? 1 : 0;
    writer.header.block_size = options.chunk_size;
    writer.header.total_size = options.size;
    writer.header.used_size = 0;
    writer.header.file_count = 0;
    writer.header.created_at = Platform::now_ns();
    writer.header.modified_at = writer.header.created_at;

    // Generate random salt
    auto& ctx = crypto::CryptoContext::instance();
    auto salt_result = ctx.random_bytes(16);
    if (!salt_result.success) {
        return static_cast<ErrorCode>(salt_result.error_code);
    }
    std::copy(salt_result.value.begin(), salt_result.value.end(),
              writer.key_blob.salt.begin());

    // Generate container key
    auto key_result = ctx.random_bytes(32);
    if (!key_result.success) {
        return static_cast<ErrorCode>(key_result.error_code);
    }
    std::copy(key_result.value.begin(), key_result.value.end(),
              writer.container_key.begin());
    writer.key_initialized = true;

    // Wrap the container key
    if (options.wrapping_key.has_value()) {
        // RSA-OAEP wrapping
        writer.header.key_wrapping_method = 1;
        writer.header.rsa_key_bits = options.wrapping_key->bits;

        auto enc_result = ctx.rsa_encrypt(
            *options.wrapping_key,
            ByteSpan(writer.container_key.data(), writer.container_key.size())
        );
        if (!enc_result.success) {
            return static_cast<ErrorCode>(enc_result.error_code);
        }
        writer.key_blob.encrypted_key = std::move(enc_result.value);
        writer.key_blob.wrapping_method = 1;
    } else {
        // Password-derived wrapping
        writer.header.key_wrapping_method = 0;
        writer.header.kdf_algorithm = KdfAlgorithm::PBKDF2_HMAC_SHA256;

        // Derive KEK from password
        Aes256Key kek{};
        auto derive_result = derive_container_key(options.password, writer.key_blob.salt, kek);
        if (derive_result != ErrorCode::SUCCESS) {
            return derive_result;
        }

        // Generate IV for key encryption
        auto iv = ctx.random_gcm_iv();
        writer.key_blob.iv = iv;

        // Encrypt container key with KEK
        auto enc_result = ctx.aes_gcm_encrypt(
            kek,
            ByteSpan(writer.container_key.data(), writer.container_key.size())
        );
        if (!enc_result.success) {
            return static_cast<ErrorCode>(enc_result.error_code);
        }

        // Parse encrypted output: [IV 12B][ciphertext 32B][tag 16B]
        if (enc_result.value.size() != 12 + 32 + 16) {
            return static_cast<ErrorCode>(CryptoError::ENCRYPTION_FAILED);
        }
        std::copy(enc_result.value.begin(), enc_result.value.begin() + 12,
                  writer.key_blob.iv.begin());
        writer.key_blob.encrypted_key.assign(
            enc_result.value.begin() + 12, enc_result.value.begin() + 44);
        std::copy(enc_result.value.begin() + 44, enc_result.value.end(),
                  writer.key_blob.tag.begin());
        writer.key_blob.wrapping_method = 0;
    }

    // Write header
    std::array<uint8_t, CONTAINER_V1_HEADER_SIZE> header_buffer{};
    MutableByteSpan header_span(header_buffer.data(), header_buffer.size());
    auto header_result = writer.header.serialize(header_span);
    if (header_result != ErrorCode::SUCCESS) {
        return header_result;
    }
    writer.file.write(reinterpret_cast<const char*>(header_buffer.data()),
                      CONTAINER_V1_HEADER_SIZE);

    // Write key blob
    ByteArray key_blob_bytes;
    writer.key_blob.serialize(key_blob_bytes);
    writer.file.write(reinterpret_cast<const char*>(key_blob_bytes.data()),
                      static_cast<std::streamsize>(key_blob_bytes.size()));

    // Write empty metadata (encrypted)
    ContainerMetadata metadata;
    metadata.container_id = container_id.bytes;
    metadata.format = ContainerFormat::V1;
    metadata.security_level = options.security_level;
    metadata.total_size = options.size;
    metadata.used_size = 0;
    metadata.file_count = 0;
    metadata.compression = options.compression;
    metadata.deduplication_enabled = options.enable_deduplication;
    metadata.wal_enabled = options.enable_wal;
    metadata.created_at = writer.header.created_at;
    metadata.modified_at = writer.header.created_at;

    ByteArray metadata_json;
    auto meta_result = serialize_container_metadata(metadata, metadata_json);
    if (meta_result != ErrorCode::SUCCESS) {
        return meta_result;
    }

    ByteArray encrypted_metadata;
    auto enc_meta_result = encrypt_metadata(
        ByteSpan(metadata_json), writer.container_key, encrypted_metadata);
    if (enc_meta_result != ErrorCode::SUCCESS) {
        return enc_meta_result;
    }

    // Write metadata length + encrypted metadata
    write_u64_be(writer.file, encrypted_metadata.size());
    writer.file.write(reinterpret_cast<const char*>(encrypted_metadata.data()),
                      static_cast<std::streamsize>(encrypted_metadata.size()));

    // Write footer
    ContainerV1Footer footer;
    footer.container_id = container_id.bytes;

    // Compute HMAC of everything written so far
    writer.file.flush();
    auto file_size = writer.file.tellp();
    writer.file.close();

    // Read the file back for HMAC computation
    std::ifstream read_file(path, std::ios::binary);
    if (!read_file.is_open()) {
        return ErrorCode::FILE_ACCESS_DENIED;
    }
    std::vector<uint8_t> file_data(static_cast<size_t>(file_size));
    read_file.read(reinterpret_cast<char*>(file_data.data()),
                   static_cast<std::streamsize>(file_data.size()));
    read_file.close();

    // Reopen for writing footer
    writer.file.open(path, std::ios::binary | std::ios::out | std::ios::app);
    if (!writer.file.is_open()) {
        return ErrorCode::FILE_ACCESS_DENIED;
    }

    auto& crypto_ctx = crypto::CryptoContext::instance();
    auto hmac_result = crypto_ctx.hmac(
        ByteSpan(writer.container_key.data(), writer.container_key.size()),
        ByteSpan(file_data)
    );
    if (!hmac_result.success) {
        return static_cast<ErrorCode>(hmac_result.error_code);
    }
    std::copy(hmac_result.value.begin(), hmac_result.value.end(), footer.hmac.begin());

    // Write footer
    writer.file.write(reinterpret_cast<const char*>(footer.magic.data()), footer.magic.size());
    writer.file.write(reinterpret_cast<const char*>(footer.hmac.data()), footer.hmac.size());
    writer.file.write(reinterpret_cast<const char*>(footer.container_id.data()), footer.container_id.size());
    writer.file.write(reinterpret_cast<const char*>(footer.reserved.data()), footer.reserved.size());

    writer.file.flush();
    writer.file.close();

    LOG_INFO("container", "v1_writer", "Created container {} ({} bytes)",
             container_id.to_hex(), options.size);

    return ErrorCode::SUCCESS;
}

} // namespace container
} // namespace securevault