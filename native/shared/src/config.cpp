// ============================================================================
// SecureVault - Configuration Management Implementation
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
// ============================================================================

#include "config.h"
#include "platform.h"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>

namespace securevault {

// ============================================================================
// STATIC MEMBERS
// ============================================================================

static Config* g_config_instance = nullptr;

// ============================================================================
// CONFIG NODE
// ============================================================================

ConfigValueType ConfigNode::type() const noexcept {
    if (value.has_value()) {
        if (value.type() == typeid(bool)) return ConfigValueType::BOOL;
        if (value.type() == typeid(int64_t) || value.type() == typeid(int32_t) ||
            value.type() == typeid(uint32_t) || value.type() == typeid(uint64_t)) {
            return ConfigValueType::INT;
        }
        if (value.type() == typeid(double) || value.type() == typeid(float)) {
            return ConfigValueType::DOUBLE;
        }
        if (value.type() == typeid(std::string) || value.type() == typeid(const char*)) {
            return ConfigValueType::STRING;
        }
        if (value.type() == typeid(std::vector<std::string>)) {
            return ConfigValueType::ARRAY;
        }
        return ConfigValueType::OBJECT;
    }
    return ConfigValueType::NULL_TYPE;
}

// ============================================================================
// CONFIGURATION MANAGER
// ============================================================================

Config& Config::instance() {
    static Config config;
    return config;
}

Config::Config() = default;
Config::~Config() = default;

ErrorCode Config::initialize(
    std::filesystem::path config_path,
    bool encrypt_sensitive) {

    auto& config = instance();
    if (!config.config_path_.empty()) {
        return ErrorCode::ALREADY_INITIALIZED;
    }

    config.config_path_ = std::move(config_path);
    config.encrypt_sensitive_ = encrypt_sensitive;

    // Load built-in defaults first
    config.load_builtin_defaults();

    // Load from file if it exists
    if (std::filesystem::exists(config.config_path_)) {
        auto result = config.reload();
        if (result != ErrorCode::SUCCESS) {
            return result;
        }
    } else {
        // Create default config file
        auto result = config.save();
        if (result != ErrorCode::SUCCESS) {
            return result;
        }
    }

    // Apply environment variable overrides
    config.apply_env_overrides();

    return ErrorCode::SUCCESS;
}

ErrorCode Config::initialize_default() {
    auto& config = instance();
    if (!config.config_path_.empty()) {
        return ErrorCode::ALREADY_INITIALIZED;
    }

    config.config_path_ = default_config_path();
    config.encrypt_sensitive_ = true;

    config.load_builtin_defaults();
    config.apply_env_overrides();

    return ErrorCode::SUCCESS;
}

void Config::shutdown() {
    auto& config = instance();
    if (!config.config_path_.empty()) {
        config.save();
    }
    config.values_.clear();
    config.schema_.clear();
    config.config_path_.clear();
}

ErrorCode Config::reload() {
    if (config_path_.empty()) {
        return ErrorCode::NOT_INITIALIZED;
    }

    std::ifstream file(config_path_);
    if (!file.is_open()) {
        return ErrorCode::FILE_NOT_FOUND;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    return from_json(buffer.str());
}

ErrorCode Config::save() {
    if (config_path_.empty()) {
        return ErrorCode::NOT_INITIALIZED;
    }

    // Create parent directory if needed
    auto dir = config_path_.parent_path();
    if (!dir.empty() && !std::filesystem::exists(dir)) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            return ErrorCode::IO_ERROR;
        }
    }

    std::ofstream file(config_path_, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        return ErrorCode::FILE_ACCESS_DENIED;
    }

    file << to_json(true);
    file.flush();
    file.close();

    modified_ = false;
    return ErrorCode::SUCCESS;
}

// ============================================================================
// GETTERS
// ============================================================================

bool Config::get_bool(const std::string& key, bool default_value) const {
    const auto* val = get_value(key);
    if (!val) return default_value;
    if (val->type() == typeid(bool)) return std::any_cast<bool>(*val);
    if (val->type() == typeid(int64_t)) return std::any_cast<int64_t>(*val) != 0;
    if (val->type() == typeid(std::string)) {
        auto s = std::any_cast<std::string>(*val);
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s == "true" || s == "1" || s == "yes" || s == "on";
    }
    return default_value;
}

int64_t Config::get_int(const std::string& key, int64_t default_value) const {
    const auto* val = get_value(key);
    if (!val) return default_value;
    if (val->type() == typeid(int64_t)) return std::any_cast<int64_t>(*val);
    if (val->type() == typeid(int32_t)) return std::any_cast<int32_t>(*val);
    if (val->type() == typeid(uint32_t)) return std::any_cast<uint32_t>(*val);
    if (val->type() == typeid(uint64_t)) return static_cast<int64_t>(std::any_cast<uint64_t>(*val));
    if (val->type() == typeid(double)) return static_cast<int64_t>(std::any_cast<double>(*val));
    if (val->type() == typeid(bool)) return std::any_cast<bool>(*val) ? 1 : 0;
    if (val->type() == typeid(std::string)) {
        try {
            return std::stoll(std::any_cast<std::string>(*val));
        } catch (...) {
            return default_value;
        }
    }
    return default_value;
}

double Config::get_double(const std::string& key, double default_value) const {
    const auto* val = get_value(key);
    if (!val) return default_value;
    if (val->type() == typeid(double)) return std::any_cast<double>(*val);
    if (val->type() == typeid(float)) return std::any_cast<float>(*val);
    if (val->type() == typeid(int64_t)) return static_cast<double>(std::any_cast<int64_t>(*val));
    if (val->type() == typeid(std::string)) {
        try {
            return std::stod(std::any_cast<std::string>(*val));
        } catch (...) {
            return default_value;
        }
    }
    return default_value;
}

std::string Config::get_string(const std::string& key, const std::string& default_value) const {
    const auto* val = get_value(key);
    if (!val) return default_value;
    if (val->type() == typeid(std::string)) return std::any_cast<std::string>(*val);
    if (val->type() == typeid(const char*)) return std::any_cast<const char*>(*val);
    if (val->type() == typeid(bool)) return std::any_cast<bool>(*val) ? "true" : "false";
    if (val->type() == typeid(int64_t)) return std::to_string(std::any_cast<int64_t>(*val));
    if (val->type() == typeid(double)) {
        std::ostringstream ss;
        ss << std::any_cast<double>(*val);
        return ss.str();
    }
    return default_value;
}

SecurityLevel Config::get_security_level(const std::string& key, SecurityLevel default_value) const {
    auto s = get_string(key);
    if (s.empty()) return default_value;

    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    if (s == "ORIGINAL") return SecurityLevel::ORIGINAL;
    if (s == "INDIVIDUAL") return SecurityLevel::INDIVIDUAL;
    if (s == "CONTAINER") return SecurityLevel::CONTAINER;
    if (s == "HYPER") return SecurityLevel::HYPER;

    // Try numeric
    try {
        auto v = std::stoul(s);
        if (v <= static_cast<uint32_t>(SecurityLevel::MAX)) {
            return static_cast<SecurityLevel>(v);
        }
    } catch (...) {}

    return default_value;
}

LogLevel Config::get_log_level(const std::string& key, LogLevel default_value) const {
    auto s = get_string(key);
    if (s.empty()) return default_value;

    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::toupper(c)); });

    if (s == "EMERGENCY") return LogLevel::EMERGENCY;
    if (s == "ALERT") return LogLevel::ALERT;
    if (s == "CRITICAL") return LogLevel::CRITICAL;
    if (s == "ERROR") return LogLevel::ERROR;
    if (s == "WARNING") return LogLevel::WARNING;
    if (s == "NOTICE") return LogLevel::NOTICE;
    if (s == "INFO") return LogLevel::INFO;
    if (s == "DEBUG") return LogLevel::DEBUG;
    if (s == "TRACE") return LogLevel::TRACE;

    return default_value;
}

bool Config::has_key(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return values_.find(key) != values_.end();
}

// ============================================================================
// SETTERS
// ============================================================================

void Config::set_bool(const std::string& key, bool value) {
    set_value(key, value);
}

void Config::set_int(const std::string& key, int64_t value) {
    set_value(key, value);
}

void Config::set_double(const std::string& key, double value) {
    set_value(key, value);
}

void Config::set_string(const std::string& key, const std::string& value) {
    set_value(key, value);
}

// ============================================================================
// CONFIGURATION SCHEMA
// ============================================================================

void Config::register_key(const std::string& key, ConfigNode node) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    schema_[key] = std::move(node);
}

std::optional<ConfigNode> Config::get_key_info(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = schema_.find(key);
    if (it == schema_.end()) return std::nullopt;
    return it->second;
}

std::map<std::string, ConfigNode> Config::all_keys() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return schema_;
}

// ============================================================================
// ENVIRONMENT OVERRIDES
// ============================================================================

void Config::apply_env_overrides() {
    std::unique_lock<std::shared_mutex> lock(mutex_);

    for (const auto& [key, node] : schema_) {
        if (!node.env_override) continue;

        std::string env_name = node.env_var_name.empty() ?
            key_to_env_var(key) : node.env_var_name;

        const char* env_val = std::getenv(env_name.c_str());
        if (!env_val) continue;

        // Override value based on schema type
        switch (node.type()) {
            case ConfigValueType::BOOL: {
                std::string s(env_val);
                std::transform(s.begin(), s.end(), s.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                values_[key] = (s == "true" || s == "1" || s == "yes" || s == "on");
                break;
            }
            case ConfigValueType::INT: {
                try {
                    values_[key] = std::stoll(env_val);
                } catch (...) {}
                break;
            }
            case ConfigValueType::DOUBLE: {
                try {
                    values_[key] = std::stod(env_val);
                } catch (...) {}
                break;
            }
            case ConfigValueType::STRING:
            default: {
                values_[key] = std::string(env_val);
                break;
            }
        }
    }
}

std::string Config::key_to_env_var(const std::string& key) {
    std::string env = "SECUREVAULT_";
    for (char c : key) {
        if (c == '.' || c == '-') {
            env += '_';
        } else {
            env += static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
    }
    return env;
}

// ============================================================================
// DEFAULTS
// ============================================================================

void Config::reset_to_defaults() {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    values_.clear();
    for (const auto& [key, node] : schema_) {
        if (!node.default_value.empty()) {
            // Parse default value based on type
            switch (node.type()) {
                case ConfigValueType::BOOL: {
                    std::string s = node.default_value;
                    std::transform(s.begin(), s.end(), s.begin(),
                        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                    values_[key] = (s == "true" || s == "1");
                    break;
                }
                case ConfigValueType::INT: {
                    try { values_[key] = std::stoll(node.default_value); }
                    catch (...) { values_[key] = int64_t{0}; }
                    break;
                }
                case ConfigValueType::DOUBLE: {
                    try { values_[key] = std::stod(node.default_value); }
                    catch (...) { values_[key] = 0.0; }
                    break;
                }
                case ConfigValueType::STRING:
                default: {
                    values_[key] = node.default_value;
                    break;
                }
            }
        }
    }
    modified_ = true;
}

void Config::load_builtin_defaults() {
    register_builtin_config_defaults(*this);
    reset_to_defaults();
}

// ============================================================================
// SERIALIZATION
// ============================================================================

std::string Config::to_json(bool pretty) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);

    std::ostringstream json;
    json << "{";

    bool first = true;
    for (const auto& [key, value] : values_) {
        if (!first) json << ",";
        first = false;

        if (pretty) json << "\n  ";
        json << "\"" << key << "\": ";

        if (value.type() == typeid(bool)) {
            json << (std::any_cast<bool>(value) ? "true" : "false");
        } else if (value.type() == typeid(int64_t)) {
            json << std::any_cast<int64_t>(value);
        } else if (value.type() == typeid(int32_t)) {
            json << std::any_cast<int32_t>(value);
        } else if (value.type() == typeid(uint32_t)) {
            json << std::any_cast<uint32_t>(value);
        } else if (value.type() == typeid(uint64_t)) {
            json << std::any_cast<uint64_t>(value);
        } else if (value.type() == typeid(double)) {
            json << std::fixed << std::setprecision(6) << std::any_cast<double>(value);
        } else if (value.type() == typeid(std::string)) {
            auto s = std::any_cast<std::string>(value);
            // Escape JSON special characters
            std::string escaped;
            for (char c : s) {
                switch (c) {
                    case '"':  escaped += "\\\""; break;
                    case '\\': escaped += "\\\\"; break;
                    case '\n': escaped += "\\n"; break;
                    case '\r': escaped += "\\r"; break;
                    case '\t': escaped += "\\t"; break;
                    default:   escaped += c; break;
                }
            }
            json << "\"" << escaped << "\"";
        } else {
            json << "null";
        }
    }

    if (pretty && !values_.empty()) json << "\n";
    json << "}";

    return json.str();
}

ErrorCode Config::from_json(const std::string& json) {
    // Minimal JSON parser for flat key-value config
    // Format: {"key": value, "key2": "value2", ...}

    std::unique_lock<std::shared_mutex> lock(mutex_);

    size_t pos = 0;
    // Skip whitespace and opening brace
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
           json[pos] == '\n' || json[pos] == '\r')) pos++;
    if (pos >= json.size() || json[pos] != '{') {
        return ErrorCode::INVALID_FORMAT;
    }
    pos++;

    while (pos < json.size()) {
        // Skip whitespace
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
               json[pos] == '\n' || json[pos] == '\r')) pos++;

        if (pos >= json.size()) break;

        // Check for closing brace
        if (json[pos] == '}') break;

        // Parse key
        if (json[pos] != '"') return ErrorCode::INVALID_FORMAT;
        pos++;
        std::string key;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                pos++;
                switch (json[pos]) {
                    case 'n': key += '\n'; break;
                    case 't': key += '\t'; break;
                    case 'r': key += '\r'; break;
                    case '"': key += '"'; break;
                    case '\\': key += '\\'; break;
                    default: key += json[pos]; break;
                }
            } else {
                key += json[pos];
            }
            pos++;
        }
        if (pos >= json.size()) return ErrorCode::INVALID_FORMAT;
        pos++; // Skip closing quote

        // Skip whitespace and colon
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
               json[pos] == '\n' || json[pos] == '\r')) pos++;
        if (pos >= json.size() || json[pos] != ':') return ErrorCode::INVALID_FORMAT;
        pos++;
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
               json[pos] == '\n' || json[pos] == '\r')) pos++;

        if (pos >= json.size()) return ErrorCode::INVALID_FORMAT;

        // Parse value
        if (json[pos] == '"') {
            // String value
            pos++;
            std::string value;
            while (pos < json.size() && json[pos] != '"') {
                if (json[pos] == '\\' && pos + 1 < json.size()) {
                    pos++;
                    switch (json[pos]) {
                        case 'n': value += '\n'; break;
                        case 't': value += '\t'; break;
                        case 'r': value += '\r'; break;
                        case '"': value += '"'; break;
                        case '\\': value += '\\'; break;
                        default: value += json[pos]; break;
                    }
                } else {
                    value += json[pos];
                }
                pos++;
            }
            if (pos >= json.size()) return ErrorCode::INVALID_FORMAT;
            pos++; // Skip closing quote
            values_[key] = value;
        } else if (json[pos] == 't' || json[pos] == 'f') {
            // Boolean
            if (json.compare(pos, 4, "true") == 0) {
                values_[key] = true;
                pos += 4;
            } else if (json.compare(pos, 5, "false") == 0) {
                values_[key] = false;
                pos += 5;
            } else {
                return ErrorCode::INVALID_FORMAT;
            }
        } else if (json[pos] == 'n') {
            // null
            if (json.compare(pos, 4, "null") == 0) {
                pos += 4;
            } else {
                return ErrorCode::INVALID_FORMAT;
            }
        } else {
            // Number
            size_t start = pos;
            bool is_double = false;
            while (pos < json.size() && json[pos] != ',' && json[pos] != '}') {
                if (json[pos] == '.' || json[pos] == 'e' || json[pos] == 'E') {
                    is_double = true;
                }
                pos++;
            }
            std::string num_str = json.substr(start, pos - start);
            try {
                if (is_double) {
                    values_[key] = std::stod(num_str);
                } else {
                    values_[key] = std::stoll(num_str);
                }
            } catch (...) {
                return ErrorCode::INVALID_FORMAT;
            }
        }

        // Skip whitespace
        while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' ||
               json[pos] == '\n' || json[pos] == '\r')) pos++;

        // Expect comma or closing brace
        if (pos < json.size() && json[pos] == ',') {
            pos++;
        } else if (pos < json.size() && json[pos] == '}') {
            break;
        } else {
            return ErrorCode::INVALID_FORMAT;
        }
    }

    modified_ = true;
    return ErrorCode::SUCCESS;
}

// ============================================================================
// DEFAULTS ACCESS
// ============================================================================

std::filesystem::path Config::default_config_path() {
    return Platform::app_data_directory() / "config.json";
}

std::filesystem::path Config::default_data_directory() {
    return Platform::app_data_directory() / "data";
}

std::filesystem::path Config::default_log_directory() {
    return Platform::app_data_directory() / "logs";
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

const std::any* Config::get_value(const std::string& key) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    auto it = values_.find(key);
    if (it == values_.end()) return nullptr;
    return &it->second;
}

void Config::set_value(const std::string& key, std::any value) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    values_[key] = std::move(value);
    modified_ = true;
}

ErrorCode Config::encrypt_sensitive_values() {
    // In a full implementation, sensitive values would be encrypted
    // using a machine-derived key. For now, this is a placeholder.
    return ErrorCode::NOT_IMPLEMENTED;
}

ErrorCode Config::decrypt_sensitive_values() {
    // In a full implementation, sensitive values would be decrypted
    // using a machine-derived key. For now, this is a placeholder.
    return ErrorCode::NOT_IMPLEMENTED;
}

// ============================================================================
// BUILT-IN DEFAULTS
// ============================================================================

void register_builtin_config_defaults(Config& config) {
    // ---- General ----
    ConfigNode version_node;
    version_node.description = "Configuration schema version";
    version_node.required = true;
    version_node.default_value = "2.0.0";
    config.register_key("version", version_node);

    // ---- Logging ----
    ConfigNode log_level_node;
    log_level_node.description = "Minimum log level";
    log_level_node.default_value = "INFO";
    log_level_node.allowed_values = {"EMERGENCY", "ALERT", "CRITICAL", "ERROR",
                                     "WARNING", "NOTICE", "INFO", "DEBUG", "TRACE"};
    config.register_key("logging.level", log_level_node);

    ConfigNode log_dir_node;
    log_dir_node.description = "Log directory";
    log_dir_node.default_value = Config::default_log_directory().string();
    config.register_key("logging.directory", log_dir_node);

    ConfigNode log_max_size_node;
    log_max_size_node.description = "Maximum log file size in bytes";
    log_max_size_node.default_value = "104857600";  // 100 MB
    log_max_size_node.min_value = 1024;
    log_max_size_node.max_value = 1073741824;  // 1 GB
    config.register_key("logging.max_file_size", log_max_size_node);

    ConfigNode log_max_files_node;
    log_max_files_node.description = "Maximum number of rotated log files";
    log_max_files_node.default_value = "10";
    log_max_files_node.min_value = 1;
    log_max_files_node.max_value = 100;
    config.register_key("logging.max_files", log_max_files_node);

    ConfigNode log_forensic_node;
    log_forensic_node.description = "Enable forensic signing of log entries";
    log_forensic_node.default_value = "true";
    config.register_key("logging.forensic_signing", log_forensic_node);

    // ---- Security ----
    ConfigNode default_level_node;
    default_level_node.description = "Default security level";
    default_level_node.default_value = "CONTAINER";
    default_level_node.allowed_values = {"ORIGINAL", "INDIVIDUAL", "CONTAINER", "HYPER"};
    config.register_key("security.default_level", default_level_node);

    ConfigNode max_level_node;
    max_level_node.description = "Maximum allowed security level";
    max_level_node.default_value = "HYPER";
    max_level_node.allowed_values = {"ORIGINAL", "INDIVIDUAL", "CONTAINER", "HYPER"};
    config.register_key("security.max_level", max_level_node);

    ConfigNode mfa_required_node;
    mfa_required_node.description = "Require MFA for sensitive operations";
    mfa_required_node.default_value = "false";
    config.register_key("security.mfa_required", mfa_required_node);

    ConfigNode anti_debug_node;
    anti_debug_node.description = "Enable anti-debug protection";
    anti_debug_node.default_value = "true";
    config.register_key("security.anti_debug", anti_debug_node);

    ConfigNode integrity_check_node;
    integrity_check_node.description = "Enable runtime integrity checking";
    integrity_check_node.default_value = "true";
    config.register_key("security.integrity_check", integrity_check_node);

    // ---- Crypto ----
    ConfigNode cipher_node;
    cipher_node.description = "Default cipher suite";
    cipher_node.default_value = "AES_256_GCM";
    cipher_node.allowed_values = {"AES_256_GCM", "CHACHA20_POLY1305", "KYBER1024",
                                  "RSA_2048", "RSA_4096", "GOST_2012"};
    config.register_key("crypto.default_cipher", cipher_node);

    ConfigNode kdf_node;
    kdf_node.description = "Default key derivation function";
    kdf_node.default_value = "ARGON2ID";
    kdf_node.allowed_values = {"ARGON2ID", "PBKDF2_HMAC_SHA256", "SCRYPT"};
    config.register_key("crypto.default_kdf", kdf_node);

    ConfigNode kdf_memory_node;
    kdf_memory_node.description = "KDF memory cost in KB";
    kdf_memory_node.default_value = "65536";  // 64 MB
    kdf_memory_node.min_value = 1024;
    kdf_memory_node.max_value = 1048576;
    config.register_key("crypto.kdf_memory_kb", kdf_memory_node);

    ConfigNode kdf_iterations_node;
    kdf_iterations_node.description = "KDF iteration count";
    kdf_iterations_node.default_value = "600000";
    kdf_iterations_node.min_value = 10000;
    kdf_iterations_node.max_value = 10000000;
    config.register_key("crypto.kdf_iterations", kdf_iterations_node);

    // ---- Container ----
    ConfigNode container_format_node;
    container_format_node.description = "Default container format";
    container_format_node.default_value = "V2";
    container_format_node.allowed_values = {"V1", "V2"};
    config.register_key("container.default_format", container_format_node);

    ConfigNode compression_node;
    compression_node.description = "Default compression algorithm";
    compression_node.default_value = "ZSTD";
    compression_node.allowed_values = {"NONE", "LZ4", "ZSTD"};
    config.register_key("container.compression", compression_node);

    ConfigNode dedup_node;
    dedup_node.description = "Enable block deduplication";
    dedup_node.default_value = "true";
    config.register_key("container.deduplication", dedup_node);

    ConfigNode chunk_size_node;
    chunk_size_node.description = "Deduplication chunk size in bytes";
    chunk_size_node.default_value = "65536";  // 64 KB
    chunk_size_node.min_value = 4096;
    chunk_size_node.max_value = 1048576;
    config.register_key("container.chunk_size", chunk_size_node);

    // ---- Storage ----
    ConfigNode data_dir_node;
    data_dir_node.description = "Data directory";
    data_dir_node.default_value = Config::default_data_directory().string();
    config.register_key("storage.data_directory", data_dir_node);

    ConfigNode max_file_size_node;
    max_file_size_node.description = "Maximum file size in bytes";
    max_file_size_node.default_value = "10737418240";  // 10 GB
    max_file_size_node.min_value = 1024;
    max_file_size_node.max_value = 1099511627776;  // 1 TB
    config.register_key("storage.max_file_size", max_file_size_node);

    // ---- Session ----
    ConfigNode session_timeout_node;
    session_timeout_node.description = "Session timeout in seconds";
    session_timeout_node.default_value = "900";  // 15 minutes
    session_timeout_node.min_value = 60;
    session_timeout_node.max_value = 86400;
    config.register_key("session.timeout_seconds", session_timeout_node);

    ConfigNode idle_timeout_node;
    idle_timeout_node.description = "Idle timeout in seconds";
    idle_timeout_node.default_value = "300";  // 5 minutes
    idle_timeout_node.min_value = 30;
    idle_timeout_node.max_value = 86400;
    config.register_key("session.idle_timeout_seconds", idle_timeout_node);

    ConfigNode max_attempts_node;
    max_attempts_node.description = "Maximum failed login attempts";
    max_attempts_node.default_value = "5";
    max_attempts_node.min_value = 1;
    max_attempts_node.max_value = 20;
    config.register_key("session.max_failed_attempts", max_attempts_node);

    // ---- Audit ----
    ConfigNode audit_enabled_node;
    audit_enabled_node.description = "Enable audit logging";
    audit_enabled_node.default_value = "true";
    config.register_key("audit.enabled", audit_enabled_node);

    ConfigNode audit_retention_node;
    audit_retention_node.description = "Audit log retention in days";
    audit_retention_node.default_value = "365";
    audit_retention_node.min_value = 1;
    audit_retention_node.max_value = 3650;
    config.register_key("audit.retention_days", audit_retention_node);

    // ---- Network ----
    ConfigNode api_port_node;
    api_port_node.description = "API server port";
    api_port_node.default_value = "8443";
    api_port_node.min_value = 1;
    api_port_node.max_value = 65535;
    config.register_key("network.api_port", api_port_node);

    ConfigNode tls_enabled_node;
    tls_enabled_node.description = "Enable TLS for API server";
    tls_enabled_node.default_value = "true";
    config.register_key("network.tls_enabled", tls_enabled_node);
}

} // namespace securevault