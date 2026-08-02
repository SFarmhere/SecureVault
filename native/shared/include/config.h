// ============================================================================
// SecureVault - Configuration Management
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Centralized configuration management for all SecureVault modules.
//   Supports JSON-based config files with encryption, environment variable
//   overrides, and runtime validation.
//
// DESIGN:
//   - Hierarchical: Module-specific config sections
//   - Overridable: File config → env vars → runtime API
//   - Encrypted: Sensitive values stored encrypted at rest
//   - Validated: Type checking and range validation on load
//   - Thread-safe: Read-copy-update pattern for concurrent access
// ============================================================================

#ifndef SECUREVAULT_CONFIG_H
#define SECUREVAULT_CONFIG_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <any>
#include <filesystem>
#include <mutex>
#include <shared_mutex>

#include "common_types.h"
#include "error_codes.h"

namespace securevault {

// ============================================================================
// CONFIG VALUE TYPES
// ============================================================================

/// Supported configuration value types stored in std::any
/// We use std::any instead of std::variant to avoid recursive variant issues
/// with nested arrays and objects.
enum class ConfigValueType : uint32_t {
    NULL_TYPE   = 0,
    BOOL        = 1,
    INT         = 2,
    DOUBLE      = 3,
    STRING      = 4,
    ARRAY       = 5,
    OBJECT      = 6
};

// ============================================================================
// CONFIG NODE
// ============================================================================

/// A single configuration node with metadata
struct ConfigNode {
    /// The configuration value (stored as std::any)
    std::any value;

    /// Human-readable description
    std::string description;

    /// Whether this value is required
    bool required = false;

    /// Whether this value is sensitive (will be encrypted at rest)
    bool sensitive = false;

    /// Whether this value can be overridden by environment variable
    bool env_override = true;

    /// Environment variable name (if env_override is true)
    std::string env_var_name;

    /// Default value as string
    std::string default_value;

    /// Validation regex pattern (for string values)
    std::string validation_pattern;

    /// Minimum value (for numeric types)
    std::optional<int64_t> min_value;

    /// Maximum value (for numeric types)
    std::optional<int64_t> max_value;

    /// Allowed values (for enum-like string values)
    std::vector<std::string> allowed_values;

    /// Get the type of the stored value
    ConfigValueType type() const noexcept;
};

// ============================================================================
// CONFIGURATION MANAGER
// ============================================================================

/// Thread-safe configuration manager with file persistence
class Config {
public:
    /// Get the global singleton instance
    static Config& instance();

    /// Initialize configuration from a file
    static ErrorCode initialize(
        std::filesystem::path config_path,
        bool encrypt_sensitive = true
    );

    /// Initialize with default configuration (no file)
    static ErrorCode initialize_default();

    /// Shutdown and save configuration
    static void shutdown();

    /// Reload configuration from file
    ErrorCode reload();

    /// Save current configuration to file
    ErrorCode save();

    // ========================================================================
    // GETTERS
    // ========================================================================

    bool get_bool(const std::string& key, bool default_value = false) const;
    int64_t get_int(const std::string& key, int64_t default_value = 0) const;
    double get_double(const std::string& key, double default_value = 0.0) const;
    std::string get_string(const std::string& key, const std::string& default_value = "") const;
    SecurityLevel get_security_level(const std::string& key, SecurityLevel default_value = SecurityLevel::CONTAINER) const;
    LogLevel get_log_level(const std::string& key, LogLevel default_value = LogLevel::INFO) const;
    bool has_key(const std::string& key) const;

    // ========================================================================
    // SETTERS
    // ========================================================================

    void set_bool(const std::string& key, bool value);
    void set_int(const std::string& key, int64_t value);
    void set_double(const std::string& key, double value);
    void set_string(const std::string& key, const std::string& value);

    // ========================================================================
    // CONFIGURATION SCHEMA
    // ========================================================================

    void register_key(const std::string& key, ConfigNode node);
    std::optional<ConfigNode> get_key_info(const std::string& key) const;
    std::map<std::string, ConfigNode> all_keys() const;

    // ========================================================================
    // ENVIRONMENT OVERRIDES
    // ========================================================================

    void apply_env_overrides();
    static std::string key_to_env_var(const std::string& key);

    // ========================================================================
    // DEFAULTS
    // ========================================================================

    void reset_to_defaults();
    void load_builtin_defaults();

    // ========================================================================
    // SERIALIZATION
    // ========================================================================

    std::string to_json(bool pretty = true) const;
    ErrorCode from_json(const std::string& json);

    // ========================================================================
    // DEFAULTS ACCESS
    // ========================================================================

    static std::filesystem::path default_config_path();
    static std::filesystem::path default_data_directory();
    static std::filesystem::path default_log_directory();

private:
    Config();
    ~Config();

    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;
    Config(Config&&) = delete;
    Config& operator=(Config&&) = delete;

    /// Internal: get a value by key path
    const std::any* get_value(const std::string& key) const;

    /// Internal: set a value by key path
    void set_value(const std::string& key, std::any value);

    /// Internal: encrypt sensitive values
    ErrorCode encrypt_sensitive_values();

    /// Internal: decrypt sensitive values
    ErrorCode decrypt_sensitive_values();

    // Configuration data
    std::map<std::string, std::any> values_;
    std::map<std::string, ConfigNode> schema_;
    mutable std::shared_mutex mutex_;

    // File path
    std::filesystem::path config_path_;
    bool encrypt_sensitive_ = true;
    bool modified_ = false;

    // Encryption key for sensitive values (derived from machine-specific data)
    std::vector<uint8_t> encryption_key_;
};

// ============================================================================
// BUILT-IN DEFAULTS
// ============================================================================

void register_builtin_config_defaults(Config& config);

} // namespace securevault

#endif // SECUREVAULT_CONFIG_H