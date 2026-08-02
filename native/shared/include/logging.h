// ============================================================================
// SecureVault - Logging System
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Thread-safe, asynchronous logging system with forensic-grade audit trail.
//   Supports multiple log levels, structured logging, and cryptographic
//   signing of log entries for non-repudiation.
//
// DESIGN:
//   - Asynchronous: Log entries are queued and written by a background thread
//   - Thread-safe: All public methods are safe to call from any thread
//   - Forensic: Each entry is timestamped and can be cryptographically signed
//   - Structured: JSON-formatted for machine parsing
//   - Rotating: Automatic log rotation with configurable size/age limits
//   - Multi-sink: Console, file, syslog, and audit database
// ============================================================================

#ifndef SECUREVAULT_LOGGING_H
#define SECUREVAULT_LOGGING_H

#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>
#include <thread>
#include <queue>
#include <condition_variable>
#include <fstream>
#include <filesystem>
#include <optional>
#include <sstream>

#include "common_types.h"
#include "error_codes.h"

namespace securevault {

// ============================================================================
// LOG LEVELS (defined in common_types.h as LogLevel)
// ============================================================================

/// Convert LogLevel to string representation
inline constexpr const char* log_level_to_string(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::EMERGENCY:   return "EMERGENCY";
        case LogLevel::ALERT:       return "ALERT";
        case LogLevel::CRITICAL:    return "CRITICAL";
        case LogLevel::ERROR:       return "ERROR";
        case LogLevel::WARNING:     return "WARNING";
        case LogLevel::NOTICE:      return "NOTICE";
        case LogLevel::INFO:        return "INFO";
        case LogLevel::DEBUG:       return "DEBUG";
        case LogLevel::TRACE:       return "TRACE";
        default:                    return "UNKNOWN";
    }
}

/// Convert LogLevel to RFC 5424 numeric severity
inline constexpr uint32_t log_level_to_rfc5424(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::EMERGENCY:   return 0;
        case LogLevel::ALERT:       return 1;
        case LogLevel::CRITICAL:    return 2;
        case LogLevel::ERROR:       return 3;
        case LogLevel::WARNING:     return 4;
        case LogLevel::NOTICE:      return 5;
        case LogLevel::INFO:        return 6;
        case LogLevel::DEBUG:       return 7;
        case LogLevel::TRACE:       return 7;  // RFC 5424 has no TRACE
        default:                    return 7;
    }
}

// ============================================================================
// LOG ENTRY
// ============================================================================

/// A single log entry with full context
struct LogEntry {
    /// Timestamp when the entry was created (nanoseconds since epoch)
    Timestamp timestamp = 0;

    /// Log severity level
    LogLevel level = LogLevel::INFO;

    /// Module name (e.g., "crypto_module", "pkcs11_module")
    std::string module;

    /// Component within the module (e.g., "aes_core", "session_manager")
    std::string component;

    /// Log message
    std::string message;

    /// Source file name
    std::string file;

    /// Source line number
    uint32_t line = 0;

    /// Source function name
    std::string function;

    /// Thread ID that created this entry
    uint64_t thread_id = 0;

    /// Correlation ID for tracing related entries
    std::string correlation_id;

    /// Optional structured data (JSON key-value pairs)
    std::string structured_data;

    /// Optional ECDSA signature for forensic audit
    std::vector<uint8_t> signature;

    /// Whether this entry has been cryptographically signed
    bool is_signed = false;
};

// ============================================================================
// LOG SINK INTERFACE
// ============================================================================

/// Abstract interface for log output destinations
class LogSink {
public:
    virtual ~LogSink() = default;

    /// Write a log entry to this sink
    /// @param entry The log entry to write
    /// @return ErrorCode::SUCCESS on success, error code otherwise
    virtual ErrorCode write(const LogEntry& entry) = 0;

    /// Flush any buffered entries
    /// @return ErrorCode::SUCCESS on success, error code otherwise
    virtual ErrorCode flush() = 0;

    /// Get the name of this sink for identification
    /// @return Sink name string
    virtual const char* name() const noexcept = 0;
};

// ============================================================================
// CONSOLE LOG SINK
// ============================================================================

/// Log sink that writes to stdout/stderr with optional color coding
class ConsoleLogSink : public LogSink {
public:
    /// Create a console log sink
    /// @param use_colors Enable ANSI color coding (default: true on terminal)
    explicit ConsoleLogSink(bool use_colors = true);

    ~ConsoleLogSink() override = default;

    ErrorCode write(const LogEntry& entry) override;
    ErrorCode flush() override;
    const char* name() const noexcept override { return "console"; }

private:
    bool use_colors_;
    std::mutex mutex_;

    /// Get ANSI color code for a log level
    const char* level_color(LogLevel level) const noexcept;

    /// Reset ANSI color
    static constexpr const char* color_reset = "\033[0m";
};

// ============================================================================
// FILE LOG SINK
// ============================================================================

/// Log sink that writes to a file with automatic rotation
class FileLogSink : public LogSink {
public:
    /// Create a file log sink
    /// @param base_path Base path for log files
    /// @param max_size_bytes Maximum file size before rotation (default: 100 MB)
    /// @param max_files Maximum number of rotated files to keep (default: 10)
    /// @param enable_compression Compress rotated files (default: true)
    explicit FileLogSink(
        std::filesystem::path base_path,
        uint64_t max_size_bytes = 100 * 1024 * 1024,
        uint32_t max_files = 10,
        bool enable_compression = true
    );

    ~FileLogSink() override;

    ErrorCode write(const LogEntry& entry) override;
    ErrorCode flush() override;
    const char* name() const noexcept override { return "file"; }

private:
    std::filesystem::path base_path_;
    uint64_t max_size_bytes_;
    uint32_t max_files_;
    bool enable_compression_;
    std::mutex mutex_;
    std::ofstream current_file_;
    uint64_t current_size_ = 0;
    uint32_t current_index_ = 0;

    /// Rotate the log file
    ErrorCode rotate();

    /// Open a new log file
    ErrorCode open_file(uint32_t index);

    /// Compress an old log file
    ErrorCode compress_file(const std::filesystem::path& path);

    /// Format a log entry as JSON
    std::string format_json(const LogEntry& entry);
};

// ============================================================================
// ASYNCHRONOUS LOGGER
// ============================================================================

/// Main logger class with asynchronous, multi-sink logging
class Logger {
public:
    /// Get the global singleton instance
    /// @return Reference to the global Logger instance
    static Logger& instance();

    /// Initialize the logger with default sinks
    /// @param min_level Minimum log level to record
    /// @param log_dir Directory for log files (empty = no file logging)
    /// @param app_name Application name for log identification
    /// @return ErrorCode::SUCCESS on success
    static ErrorCode initialize(
        LogLevel min_level = LogLevel::INFO,
        std::filesystem::path log_dir = "",
        const char* app_name = "SecureVault"
    );

    /// Shutdown the logger and flush all pending entries
    static void shutdown();

    /// Add a custom log sink
    /// @param sink Unique pointer to the sink
    void add_sink(std::unique_ptr<LogSink> sink);

    /// Remove all sinks
    void clear_sinks();

    /// Set the minimum log level
    void set_min_level(LogLevel level) noexcept;

    /// Get the current minimum log level
    LogLevel min_level() const noexcept;

    /// Log a message at the specified level
    /// @param level Log severity level
    /// @param module Module name
    /// @param component Component name
    /// @param message Log message
    /// @param file Source file name (use __FILE__)
    /// @param line Source line number (use __LINE__)
    /// @param function Source function name (use __func__)
    void log(
        LogLevel level,
        const char* module,
        const char* component,
        const char* message,
        const char* file = nullptr,
        uint32_t line = 0,
        const char* function = nullptr
    );

    /// Log a formatted message (printf-style)
    /// @param level Log severity level
    /// @param module Module name
    /// @param component Component name
    /// @param format Printf-style format string
    /// @param ... Format arguments
    void logf(
        LogLevel level,
        const char* module,
        const char* component,
        const char* format,
        ...
    );

    /// Check if a log level is enabled
    /// @param level The level to check
    /// @return true if this level would be logged
    bool is_enabled(LogLevel level) const noexcept;

    /// Flush all pending log entries synchronously
    void flush();

    /// Get the total number of entries logged
    uint64_t total_entries() const noexcept;

    /// Get the number of entries that failed to write
    uint64_t failed_entries() const noexcept;

    /// Enable or disable forensic signing of log entries
    /// @param enable Whether to enable signing
    void enable_forensic_signing(bool enable);

    /// Set the ECDSA signing key for forensic audit
    /// @param key_data Pointer to private key data
    /// @param key_size Size of key data in bytes
    /// @return ErrorCode::SUCCESS on success
    ErrorCode set_signing_key(const uint8_t* key_data, size_t key_size);

private:
    Logger();
    ~Logger();

    // Non-copyable, non-movable
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    Logger(Logger&&) = delete;
    Logger& operator=(Logger&&) = delete;

    /// Background worker thread function
    void worker_thread();

    /// Sign a log entry with ECDSA
    ErrorCode sign_entry(LogEntry& entry);

    /// Get current thread ID
    static uint64_t current_thread_id();

    // Configuration
    std::atomic<LogLevel> min_level_{LogLevel::INFO};
    std::atomic<bool> forensic_signing_{false};
    std::atomic<bool> running_{false};
    std::string app_name_;

    // Sinks
    std::vector<std::unique_ptr<LogSink>> sinks_;
    std::mutex sinks_mutex_;

    // Entry queue
    std::queue<LogEntry> queue_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;

    // Worker thread
    std::thread worker_;

    // Statistics
    std::atomic<uint64_t> total_entries_{0};
    std::atomic<uint64_t> failed_entries_{0};

    // Signing key (raw ECDSA P-256 private key)
    std::vector<uint8_t> signing_key_;
    std::mutex signing_mutex_;
};

// ============================================================================
// CONVENIENCE MACROS
// ============================================================================

// These macros provide convenient logging with automatic source location.
// They are no-ops if the logger is not initialized.

/// Log at EMERGENCY level
#define LOG_EMERGENCY(module, component, ...) \
    do { \
        auto& l = securevault::Logger::instance(); \
        if (l.is_enabled(securevault::LogLevel::EMERGENCY)) { \
            l.logf(securevault::LogLevel::EMERGENCY, module, component, __VA_ARGS__); \
        } \
    } while (0)

/// Log at ALERT level
#define LOG_ALERT(module, component, ...) \
    do { \
        auto& l = securevault::Logger::instance(); \
        if (l.is_enabled(securevault::LogLevel::ALERT)) { \
            l.logf(securevault::LogLevel::ALERT, module, component, __VA_ARGS__); \
        } \
    } while (0)

/// Log at CRITICAL level
#define LOG_CRITICAL(module, component, ...) \
    do { \
        auto& l = securevault::Logger::instance(); \
        if (l.is_enabled(securevault::LogLevel::CRITICAL)) { \
            l.logf(securevault::LogLevel::CRITICAL, module, component, __VA_ARGS__); \
        } \
    } while (0)

/// Log at ERROR level
#define LOG_ERROR(module, component, ...) \
    do { \
        auto& l = securevault::Logger::instance(); \
        if (l.is_enabled(securevault::LogLevel::ERROR)) { \
            l.logf(securevault::LogLevel::ERROR, module, component, __VA_ARGS__); \
        } \
    } while (0)

/// Log at WARNING level
#define LOG_WARNING(module, component, ...) \
    do { \
        auto& l = securevault::Logger::instance(); \
        if (l.is_enabled(securevault::LogLevel::WARNING)) { \
            l.logf(securevault::LogLevel::WARNING, module, component, __VA_ARGS__); \
        } \
    } while (0)

/// Log at NOTICE level
#define LOG_NOTICE(module, component, ...) \
    do { \
        auto& l = securevault::Logger::instance(); \
        if (l.is_enabled(securevault::LogLevel::NOTICE)) { \
            l.logf(securevault::LogLevel::NOTICE, module, component, __VA_ARGS__); \
        } \
    } while (0)

/// Log at INFO level
#define LOG_INFO(module, component, ...) \
    do { \
        auto& l = securevault::Logger::instance(); \
        if (l.is_enabled(securevault::LogLevel::INFO)) { \
            l.logf(securevault::LogLevel::INFO, module, component, __VA_ARGS__); \
        } \
    } while (0)

/// Log at DEBUG level
#define LOG_DEBUG(module, component, ...) \
    do { \
        auto& l = securevault::Logger::instance(); \
        if (l.is_enabled(securevault::LogLevel::DEBUG)) { \
            l.logf(securevault::LogLevel::DEBUG, module, component, __VA_ARGS__); \
        } \
    } while (0)

/// Log at TRACE level
#define LOG_TRACE(module, component, ...) \
    do { \
        auto& l = securevault::Logger::instance(); \
        if (l.is_enabled(securevault::LogLevel::TRACE)) { \
            l.logf(securevault::LogLevel::TRACE, module, component, __VA_ARGS__); \
        } \
    } while (0)

// ============================================================================
// AUDIT LOGGER (FORENSIC)
// ============================================================================

/// Specialized logger for forensic audit trail
/// All entries are automatically signed and stored in append-only format
class AuditLogger {
public:
    /// Initialize the audit logger
    /// @param audit_path Path to the audit log file
    /// @param signing_key Pointer to ECDSA P-256 private key
    /// @param key_size Size of signing key in bytes
    /// @return ErrorCode::SUCCESS on success
    static ErrorCode initialize(
        std::filesystem::path audit_path,
        const uint8_t* signing_key,
        size_t key_size
    );

    /// Record an audit event
    /// @param event_type Type of event (e.g., "FILE_ENCRYPT", "CONTAINER_CREATE")
    /// @param user_id User identifier
    /// @param details Event details in JSON format
    /// @param severity Event severity
    static void record(
        const char* event_type,
        const char* user_id,
        const char* details,
        LogLevel severity = LogLevel::INFO
    );

    /// Verify the integrity of the entire audit log
    /// @param audit_path Path to the audit log file
    /// @param public_key Pointer to ECDSA P-256 public key
    /// @param key_size Size of public key in bytes
    /// @return true if the audit log is intact and properly signed
    static bool verify_integrity(
        const std::filesystem::path& audit_path,
        const uint8_t* public_key,
        size_t key_size
    );

    /// Export audit log in a portable format
    /// @param output_path Path for the exported file
    /// @param start_time Optional start time filter
    /// @param end_time Optional end time filter
    /// @return ErrorCode::SUCCESS on success
    static ErrorCode export_log(
        std::filesystem::path output_path,
        std::optional<Timestamp> start_time = std::nullopt,
        std::optional<Timestamp> end_time = std::nullopt
    );

private:
    AuditLogger() = default;

    static std::unique_ptr<AuditLogger> instance_;
    std::filesystem::path audit_path_;
    std::ofstream audit_file_;
    std::mutex mutex_;
    std::vector<uint8_t> signing_key_;
};

} // namespace securevault

#endif // SECUREVAULT_LOGGING_H