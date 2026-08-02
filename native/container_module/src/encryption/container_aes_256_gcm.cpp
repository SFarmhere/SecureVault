// ============================================================================
// SecureVault - Container AES-256-GCM Encryption
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Container-level AES-256-GCM encryption helpers.
//   Provides metadata encryption/decryption and ContainerId utilities.
// ============================================================================

#include "metadata.h"
#include "container_api.h"
#include "crypto_api.h"
#include "logging.h"

#include <cstring>
#include <sstream>
#include <iomanip>

namespace securevault {
namespace container {

// ============================================================================
// CONTAINER ID
// ============================================================================

ContainerId ContainerId::generate() {
    ContainerId id;
    auto& ctx = crypto::CryptoContext::instance();
    auto result = ctx.random_bytes(16);
    if (result.success) {
        std::copy(result.value.begin(), result.value.end(), id.bytes.begin());
    }
    return id;
}

std::string ContainerId::to_hex() const {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

std::optional<ContainerId> ContainerId::from_hex(const std::string& hex) {
    if (hex.size() != 32) {
        return std::nullopt;
    }

    ContainerId id;
    for (size_t i = 0; i < 16; ++i) {
        auto hex_byte = hex.substr(i * 2, 2);
        try {
            id.bytes[i] = static_cast<uint8_t>(std::stoul(hex_byte, nullptr, 16));
        } catch (...) {
            return std::nullopt;
        }
    }
    return id;
}

// ============================================================================
// METADATA ENCRYPTION
// ============================================================================

ErrorCode encrypt_metadata(
    ByteSpan plaintext,
    const Aes256Key& key,
    ByteArray& output
) {
    auto& ctx = crypto::CryptoContext::instance();
    auto result = ctx.aes_gcm_encrypt(key, plaintext);
    if (!result.success) {
        return static_cast<ErrorCode>(result.error_code);
    }
    output = std::move(result.value);
    return ErrorCode::SUCCESS;
}

ErrorCode decrypt_metadata(
    ByteSpan encrypted,
    const Aes256Key& key,
    ByteArray& output
) {
    auto& ctx = crypto::CryptoContext::instance();
    auto result = ctx.aes_gcm_decrypt(key, encrypted);
    if (!result.success) {
        return static_cast<ErrorCode>(result.error_code);
    }
    output = std::move(result.value);
    return ErrorCode::SUCCESS;
}

// ============================================================================
// METADATA SERIALIZATION (simple JSON-like format)
// ============================================================================

namespace {

/// Escape a string for JSON
std::string json_escape(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    for (char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:   output += c; break;
        }
    }
    return output;
}

/// Write a hex string for byte arrays
std::string bytes_to_hex(const uint8_t* data, size_t size) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

/// Parse hex string to bytes
bool hex_to_bytes(const std::string& hex, uint8_t* output, size_t size) {
    if (hex.size() != size * 2) return false;
    for (size_t i = 0; i < size; ++i) {
        try {
            output[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
        } catch (...) {
            return false;
        }
    }
    return true;
}

} // anonymous namespace

ErrorCode serialize_container_metadata(
    const ContainerMetadata& metadata,
    ByteArray& output
) {
    std::ostringstream json;
    json << "{";
    json << "\"version\":" << metadata.version << ",";
    json << "\"container_id\":\"" << bytes_to_hex(metadata.container_id.data(), metadata.container_id.size()) << "\",";
    json << "\"format\":" << static_cast<uint32_t>(metadata.format) << ",";
    json << "\"security_level\":" << static_cast<uint32_t>(metadata.security_level) << ",";
    json << "\"created_at\":" << metadata.created_at << ",";
    json << "\"modified_at\":" << metadata.modified_at << ",";
    json << "\"total_size\":" << metadata.total_size << ",";
    json << "\"used_size\":" << metadata.used_size << ",";
    json << "\"file_count\":" << metadata.file_count << ",";
    json << "\"compression\":" << static_cast<uint32_t>(metadata.compression) << ",";
    json << "\"deduplication_enabled\":" << (metadata.deduplication_enabled ? "true" : "false") << ",";
    json << "\"wal_enabled\":" << (metadata.wal_enabled ? "true" : "false") << ",";
    json << "\"is_hidden\":" << (metadata.is_hidden ? "true" : "false");

    // Custom fields
    if (!metadata.custom_fields.empty()) {
        json << ",\"custom_fields\":{";
        bool first = true;
        for (const auto& [key, value] : metadata.custom_fields) {
            if (!first) json << ",";
            json << "\"" << json_escape(key) << "\":\"" << json_escape(value) << "\"";
            first = false;
        }
        json << "}";
    }

    json << "}";

    std::string json_str = json.str();
    output.assign(json_str.begin(), json_str.end());
    return ErrorCode::SUCCESS;
}

ErrorCode deserialize_container_metadata(
    ByteSpan input,
    ContainerMetadata& metadata
) {
    std::string json(reinterpret_cast<const char*>(input.data), input.size);

    // Simple JSON parser for our known format
    auto find_value = [&json](const std::string& key) -> std::string {
        auto pos = json.find("\"" + key + "\":");
        if (pos == std::string::npos) return "";
        pos += key.size() + 3;
        auto end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    };

    auto find_string = [&json](const std::string& key) -> std::string {
        auto pos = json.find("\"" + key + "\":\"");
        if (pos == std::string::npos) return "";
        pos += key.size() + 4;
        auto end = json.find("\"", pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    };

    try {
        metadata.version = static_cast<uint32_t>(std::stoul(find_value("version")));

        auto id_hex = find_string("container_id");
        if (!id_hex.empty()) {
            hex_to_bytes(id_hex, metadata.container_id.data(), metadata.container_id.size());
        }

        metadata.format = static_cast<ContainerFormat>(std::stoul(find_value("format")));
        metadata.security_level = static_cast<SecurityLevel>(std::stoul(find_value("security_level")));
        metadata.created_at = std::stoull(find_value("created_at"));
        metadata.modified_at = std::stoull(find_value("modified_at"));
        metadata.total_size = std::stoull(find_value("total_size"));
        metadata.used_size = std::stoull(find_value("used_size"));
        metadata.file_count = static_cast<uint32_t>(std::stoul(find_value("file_count")));
        metadata.compression = static_cast<CompressionAlgorithm>(std::stoul(find_value("compression")));
        metadata.deduplication_enabled = find_value("deduplication_enabled") == "true";
        metadata.wal_enabled = find_value("wal_enabled") == "true";
        metadata.is_hidden = find_value("is_hidden") == "true";
    } catch (...) {
        return static_cast<ErrorCode>(ContainerError::CONTAINER_METADATA_CORRUPTED);
    }

    return ErrorCode::SUCCESS;
}

ErrorCode serialize_file_metadata(
    const ContainerFileMetadata& metadata,
    ByteArray& output
) {
    std::ostringstream json;
    json << "{";
    json << "\"path\":\"" << json_escape(metadata.path) << "\",";
    json << "\"original_size\":" << metadata.original_size << ",";
    json << "\"stored_size\":" << metadata.stored_size << ",";
    json << "\"compression\":" << static_cast<uint32_t>(metadata.compression) << ",";
    json << "\"encrypted\":" << (metadata.encrypted ? "true" : "false") << ",";
    json << "\"created_at\":" << metadata.created_at << ",";
    json << "\"modified_at\":" << metadata.modified_at << ",";
    json << "\"original_hash\":\"" << bytes_to_hex(metadata.original_hash.data(), metadata.original_hash.size()) << "\",";
    json << "\"stored_hash\":\"" << bytes_to_hex(metadata.stored_hash.data(), metadata.stored_hash.size()) << "\",";
    json << "\"block_indices\":[";
    for (size_t i = 0; i < metadata.block_indices.size(); ++i) {
        if (i > 0) json << ",";
        json << metadata.block_indices[i];
    }
    json << "]";
    json << "}";

    std::string json_str = json.str();
    output.assign(json_str.begin(), json_str.end());
    return ErrorCode::SUCCESS;
}

ErrorCode deserialize_file_metadata(
    ByteSpan input,
    ContainerFileMetadata& metadata
) {
    std::string json(reinterpret_cast<const char*>(input.data), input.size);

    auto find_value = [&json](const std::string& key) -> std::string {
        auto pos = json.find("\"" + key + "\":");
        if (pos == std::string::npos) return "";
        pos += key.size() + 3;
        auto end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    };

    auto find_string = [&json](const std::string& key) -> std::string {
        auto pos = json.find("\"" + key + "\":\"");
        if (pos == std::string::npos) return "";
        pos += key.size() + 4;
        auto end = json.find("\"", pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    };

    try {
        metadata.path = find_string("path");
        metadata.original_size = std::stoull(find_value("original_size"));
        metadata.stored_size = std::stoull(find_value("stored_size"));
        metadata.compression = static_cast<CompressionAlgorithm>(std::stoul(find_value("compression")));
        metadata.encrypted = find_value("encrypted") == "true";
        metadata.created_at = std::stoull(find_value("created_at"));
        metadata.modified_at = std::stoull(find_value("modified_at"));

        auto orig_hash = find_string("original_hash");
        if (!orig_hash.empty()) {
            hex_to_bytes(orig_hash, metadata.original_hash.data(), metadata.original_hash.size());
        }
        auto stored_hash = find_string("stored_hash");
        if (!stored_hash.empty()) {
            hex_to_bytes(stored_hash, metadata.stored_hash.data(), metadata.stored_hash.size());
        }

        // Parse block indices
        auto pos = json.find("\"block_indices\":[");
        if (pos != std::string::npos) {
            pos += 17;
            auto end = json.find("]", pos);
            if (end != std::string::npos) {
                std::string indices = json.substr(pos, end - pos);
                std::istringstream iss(indices);
                std::string token;
                while (std::getline(iss, token, ',')) {
                    if (!token.empty()) {
                        metadata.block_indices.push_back(std::stoull(token));
                    }
                }
            }
        }
    } catch (...) {
        return static_cast<ErrorCode>(ContainerError::CONTAINER_METADATA_CORRUPTED);
    }

    return ErrorCode::SUCCESS;
}

ErrorCode serialize_file_metadata_list(
    const std::vector<ContainerFileMetadata>& files,
    ByteArray& output
) {
    std::ostringstream json;
    json << "[";
    for (size_t i = 0; i < files.size(); ++i) {
        if (i > 0) json << ",";
        ByteArray file_json;
        auto result = serialize_file_metadata(files[i], file_json);
        if (result != ErrorCode::SUCCESS) return result;
        json << std::string(file_json.begin(), file_json.end());
    }
    json << "]";

    std::string json_str = json.str();
    output.assign(json_str.begin(), json_str.end());
    return ErrorCode::SUCCESS;
}

ErrorCode deserialize_file_metadata_list(
    ByteSpan input,
    std::vector<ContainerFileMetadata>& files
) {
    std::string json(reinterpret_cast<const char*>(input.data), input.size);
    files.clear();

    // Parse array of file metadata objects
    size_t pos = 0;
    while (pos < json.size()) {
        auto start = json.find("{", pos);
        if (start == std::string::npos) break;
        auto end = json.find("}", start);
        if (end == std::string::npos) break;

        std::string obj = json.substr(start, end - start + 1);
        ByteArray obj_bytes(obj.begin(), obj.end());

        ContainerFileMetadata metadata;
        auto result = deserialize_file_metadata(ByteSpan(obj_bytes), metadata);
        if (result != ErrorCode::SUCCESS) return result;

        files.push_back(std::move(metadata));
        pos = end + 1;
    }

    return ErrorCode::SUCCESS;
}

} // namespace container
} // namespace securevault