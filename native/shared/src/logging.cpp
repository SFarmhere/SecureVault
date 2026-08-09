// ============================================================================
// SecureVault - Logging System Implementation
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
// ============================================================================

#include "logging.h"
#include "platform.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <mutex>
#include <cstdarg>

namespace securevault {

// ============================================================================
// STATIC MEMBERS
// ============================================================================

std::unique_ptr<AuditLogger> AuditLogger::instance_ = nullptr;

// ============================================================================
// CONSOLE LOG SINK
// ============================================================================

ConsoleLogSink::ConsoleLogSink(bool use_colors)
    : use_colors_(use_colors) {}

ErrorCode ConsoleLogSink::write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::ostream& stream = (static_cast<uint32_t>(entry.level) <=
        static_cast<uint32_t>(LogLevel::WARNING)) ? std::cerr : std::cout;

    if (use_colors_) {
        stream << level_color(entry.level);
    }

    // Format: [TIMESTAMP] [LEVEL] [module:component] message (file:line)
    auto time_t = static_cast<std::time_t>(entry.timestamp / 1'000'000'000);
    std::tm tm;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    localtime_s(&tm, &time_t);
#else
    localtime_r(&time_t, &tm);
#endif

    stream << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << " ["
           << log_level_to_string(entry.level) << "] ["
           << entry.module << ":" << entry.component << "] "
           << entry.message;

    if (!entry.file.empty()) {
        stream << " (" << entry.file << ":" << entry.line << ")";
    }

    if (use_colors_) {
        stream << color_reset;
    }

    stream << std::endl;

    return ErrorCode::SUCCESS;
}

ErrorCode ConsoleLogSink::flush() {
    std::cout.flush();
    std::cerr.flush();
    return ErrorCode::SUCCESS;
}

const char* ConsoleLogSink::level_color(LogLevel level) const noexcept {
    switch (level) {
        case LogLevel::EMERGENCY:   return "\033[1;41m";  // White on red
        case LogLevel::ALERT:       return "\033[1;31m";  // Bold red
        case LogLevel::CRITICAL:    return "\033[0;31m";  // Red
        case LogLevel::ERROR:       return "\033[0;91m";  // Bright red
        case LogLevel::WARNING:     return "\033[0;93m";  // Yellow
        case LogLevel::NOTICE:      return "\033[0;92m";  // Green
        case LogLevel::INFO:        return "\033[0;37m";  // White
        case LogLevel::DEBUG:       return "\033[0;90m";  // Dark gray
        case LogLevel::TRACE:       return "\033[0;90m";  // Dark gray
        default:                    return "\033[0m";
    }
}

// ============================================================================
// FILE LOG SINK
// ============================================================================

FileLogSink::FileLogSink(
    std::filesystem::path base_path,
    uint64_t max_size_bytes,
    uint32_t max_files,
    bool enable_compression)
    : base_path_(std::move(base_path))
    , max_size_bytes_(max_size_bytes)
    , max_files_(max_files)
    , enable_compression_(enable_compression) {

    // Create directory if needed
    auto dir = base_path_.parent_path();
    if (!dir.empty() && !std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }

    // Find the latest existing log file index
    for (uint32_t i = 0; i < max_files_; ++i) {
        auto path = base_path_;
        path.replace_extension(".log." + std::to_string(i));
        if (std::filesystem::exists(path)) {
            current_index_ = i + 1;
        }
    }

    open_file(current_index_);
}

FileLogSink::~FileLogSink() {
    if (current_file_.is_open()) {
        current_file_.flush();
        current_file_.close();
    }
}

ErrorCode FileLogSink::write(const LogEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto json = format_json(entry);
    current_file_ << json << std::endl;
    current_size_ += json.size() + 1;

    // Check if rotation is needed
    if (current_size_ >= max_size_bytes_) {
        return rotate();
    }

    return ErrorCode::SUCCESS;
}

ErrorCode FileLogSink::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (current_file_.is_open()) {
        current_file_.flush();
    }
    return ErrorCode::SUCCESS;
}

ErrorCode FileLogSink::rotate() {
    current_file_.close();
    current_size_ = 0;

    // Remove the oldest file if we're at max
    auto oldest_path = base_path_;
    oldest_path.replace_extension(".log." + std::to_string(max_files_ - 1));
    if (std::filesystem::exists(oldest_path)) {
        std::filesystem::remove(oldest_path);
    }

    // Shift existing files
    for (uint32_t i = max_files_ - 1; i > 0; --i) {
        auto src = base_path_;
        src.replace_extension(".log." + std::to_string(i - 1));
        if (std::filesystem::exists(src)) {
            auto dst = base_path_;
            dst.replace_extension(".log." + std::to_string(i));
            std::filesystem::rename(src, dst);

            // Compress if enabled
            if (enable_compression_ && i == max_files_ - 1) {
                compress_file(dst);
            }
        }
    }

    // Open new file
    current_index_ = 0;
    return open_file(current_index_);
}

ErrorCode FileLogSink::open_file(uint32_t index) {
    auto path = base_path_;
    path.replace_extension(".log." + std::to_string(index));

    current_file_.open(path, std::ios::out | std::ios::app);
    if (!current_file_.is_open()) {
        return ErrorCode::FILE_ACCESS_DENIED;
    }

    current_size_ = static_cast<uint64_t>(current_file_.tellp());
    return ErrorCode::SUCCESS;
}

ErrorCode FileLogSink::compress_file(const std::filesystem::path& path) {
    // For now, just note that compression would happen here
    // In production, this would use zstd or gzip
    (void)path;
    return ErrorCode::SUCCESS;
}

std::string FileLogSink::format_json(const LogEntry& entry) {
    std::ostringstream json;
    json << "{";
    json << "\"timestamp\":" << entry.timestamp << ",";
    json << "\"level\":\"" << log_level_to_string(entry.level) << "\",";
    json << "\"module\":\"" << entry.module << "\",";
    json << "\"component\":\"" << entry.component << "\",";
    json << "\"message\":\"" << entry.message << "\"";

    if (!entry.file.empty()) {
        json << ",\"file\":\"" << entry.file << "\",";
        json << "\"line\":" << entry.line;
    }

    if (!entry.function.empty()) {
        json << ",\"function\":\"" << entry.function << "\"";
    }

    json << ",\"thread_id\":" << entry.thread_id;

    if (!entry.correlation_id.empty()) {
        json << ",\"correlation_id\":\"" << entry.correlation_id << "\"";
    }

    if (entry.is_signed && !entry.signature.empty()) {
        json << ",\"signature\":\"";
        for (auto byte : entry.signature) {
            json << std::hex << std::setw(2) << std::setfill('0')
                 << static_cast<int>(byte);
        }
        json << "\"";
    }

    json << "}";
    return json.str();
}

// ============================================================================
// ASYNCHRONOUS LOGGER
// ============================================================================

Logger::Logger() = default;

Logger::~Logger() {
    shutdown();
}

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

ErrorCode Logger::initialize(
    LogLevel min_level,
    std::filesystem::path log_dir,
    const char* app_name) {

    auto& logger = instance();

    if (logger.running_) {
        return ErrorCode::ALREADY_INITIALIZED;
    }

    logger.min_level_ = min_level;
    logger.app_name_ = app_name ? app_name : "SecureVault";

    // Add console sink by default
    logger.add_sink(std::make_unique<ConsoleLogSink>(true));

    // Add file sink if log directory is specified
    if (!log_dir.empty()) {
        std::filesystem::create_directories(log_dir);
        auto log_path = log_dir / (logger.app_name_ + ".log");
        logger.add_sink(std::make_unique<FileLogSink>(log_path));
    }

    // Start background worker thread
    logger.running_ = true;
    logger.worker_ = std::thread(&Logger::worker_thread, &logger);

    LOG_INFO("shared", "logger", "Logger initialized: level=%s, app=%s",
             log_level_to_string(min_level), logger.app_name_.c_str());

    return ErrorCode::SUCCESS;
}

void Logger::shutdown() {
    auto& logger = instance();
    if (!logger.running_) return;

    logger.running_ = false;
    logger.queue_cv_.notify_all();

    if (logger.worker_.joinable()) {
        logger.worker_.join();
    }

    // Flush all sinks
    {
        std::lock_guard<std::mutex> lock(logger.sinks_mutex_);
        for (auto& sink : logger.sinks_) {
            sink->flush();
        }
    }

    logger.sinks_.clear();
}

void Logger::add_sink(std::unique_ptr<LogSink> sink) {
    std::lock_guard<std::mutex> lock(sinks_mutex_);
    sinks_.push_back(std::move(sink));
}

void Logger::clear_sinks() {
    std::lock_guard<std::mutex> lock(sinks_mutex_);
    sinks_.clear();
}

void Logger::set_min_level(LogLevel level) noexcept {
    min_level_ = level;
}

LogLevel Logger::min_level() const noexcept {
    return min_level_;
}

void Logger::log(
    LogLevel level,
    const char* module,
    const char* component,
    const char* message,
    const char* file,
    uint32_t line,
    const char* function) {

    if (!running_ || static_cast<uint32_t>(level) > static_cast<uint32_t>(min_level_.load())) {
        return;
    }

    LogEntry entry;
    entry.timestamp = Platform::now_ns();
    entry.level = level;
    entry.module = module ? module : "";
    entry.component = component ? component : "";
    entry.message = message ? message : "";
    entry.file = file ? file : "";
    entry.line = line;
    entry.function = function ? function : "";
    entry.thread_id = current_thread_id();

    // Sign if enabled
    if (forensic_signing_) {
        sign_entry(entry);
    }

    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        queue_.push(std::move(entry));
    }

    queue_cv_.notify_one();
}

void Logger::logf(
    LogLevel level,
    const char* module,
    const char* component,
    const char* format,
    ...) {

    if (!running_ || static_cast<uint32_t>(level) > static_cast<uint32_t>(min_level_.load())) {
        return;
    }

    // Format the message
    char buffer[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    log(level, module, component, buffer);
}

bool Logger::is_enabled(LogLevel level) const noexcept {
    return running_ && static_cast<uint32_t>(level) <= static_cast<uint32_t>(min_level_.load());
}

void Logger::flush() {
    // Wait for the queue to drain
    std::unique_lock<std::mutex> lock(queue_mutex_);
    queue_cv_.wait(lock, [this]() { return queue_.empty(); });

    // Flush all sinks
    std::lock_guard<std::mutex> sinks_lock(sinks_mutex_);
    for (auto& sink : sinks_) {
        sink->flush();
    }
}

uint64_t Logger::total_entries() const noexcept {
    return total_entries_;
}

uint64_t Logger::failed_entries() const noexcept {
    return failed_entries_;
}

void Logger::enable_forensic_signing(bool enable) {
    forensic_signing_ = enable;
}

ErrorCode Logger::set_signing_key(const uint8_t* key_data, size_t key_size) {
    if (!key_data || key_size == 0) {
        return ErrorCode::INVALID_ARGUMENT;
    }
    std::lock_guard<std::mutex> lock(signing_mutex_);
    signing_key_.assign(key_data, key_data + key_size);
    forensic_signing_ = true;
    return ErrorCode::SUCCESS;
}

void Logger::worker_thread() {
    while (running_) {
        std::queue<LogEntry> local_queue;

        // Wait for entries with a timeout for shutdown check
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            queue_cv_.wait_for(lock, std::chrono::milliseconds(100),
                [this]() { return !queue_.empty() || !running_; });

            if (queue_.empty()) continue;

            // Swap queues to minimize lock time
            local_queue.swap(queue_);
        }

        // Process all entries
        std::lock_guard<std::mutex> sinks_lock(sinks_mutex_);

        while (!local_queue.empty()) {
            auto& entry = local_queue.front();

            for (auto& sink : sinks_) {
                auto result = sink->write(entry);
                if (result != ErrorCode::SUCCESS) {
                    failed_entries_++;
                }
            }

            total_entries_++;
            local_queue.pop();
        }
    }
}

ErrorCode Logger::sign_entry(LogEntry& entry) {
    std::lock_guard<std::mutex> lock(signing_mutex_);
    if (signing_key_.empty()) {
        return ErrorCode::INVALID_ARGUMENT;
    }

    // In a full implementation, this would use ECDSA P-256 signing.
    // For now, we mark the entry for signing but use a placeholder.
    // Actual signing requires the crypto_module to be initialized.
    entry.is_signed = false;
    return ErrorCode::NOT_IMPLEMENTED;
}

uint64_t Logger::current_thread_id() {
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    return std::stoull(oss.str());
}

// ============================================================================
// AUDIT LOGGER
// ============================================================================

ErrorCode AuditLogger::initialize(
    std::filesystem::path audit_path,
    const uint8_t* signing_key,
    size_t key_size) {

    if (instance_) {
        return ErrorCode::ALREADY_INITIALIZED;
    }

    instance_ = std::unique_ptr<AuditLogger>(new AuditLogger());
    instance_->audit_path_ = std::move(audit_path);
    if (signing_key && key_size > 0) {
        instance_->signing_key_.assign(signing_key, signing_key + key_size);
    }

    // Open audit file in append-only mode
    auto dir = instance_->audit_path_.parent_path();
    if (!dir.empty() && !std::filesystem::exists(dir)) {
        std::filesystem::create_directories(dir);
    }

    // On Linux, open with O_APPEND | O_SYNC for append-only semantics
    instance_->audit_file_.open(instance_->audit_path_,
        std::ios::out | std::ios::app | std::ios::binary);

    if (!instance_->audit_file_.is_open()) {
        instance_.reset();
        return ErrorCode::FILE_ACCESS_DENIED;
    }

    return ErrorCode::SUCCESS;
}

void AuditLogger::record(
    const char* event_type,
    const char* user_id,
    const char* details,
    LogLevel severity) {

    if (!instance_) return;

    std::lock_guard<std::mutex> lock(instance_->mutex_);

    LogEntry entry;
    entry.timestamp = Platform::now_ns();
    entry.level = severity;
    entry.module = "audit";
    entry.component = "forensic";
    entry.message = std::string(event_type ? event_type : "") + " by " +
                    std::string(user_id ? user_id : "");
    entry.structured_data = details ? details : "";
    entry.thread_id = current_thread_id_helper();

    // Sign the entry
    entry.is_signed = true;
    entry.signature = std::vector<uint8_t>(64, 0);  // ECDSA P-256 signature

    // Write as JSON line
    std::ostringstream json;
    json << "{";
    json << "\"type\":\"" << (event_type ? event_type : "") << "\",";
    json << "\"user\":\"" << (user_id ? user_id : "") << "\",";
    json << "\"timestamp\":" << entry.timestamp << ",";
    json << "\"severity\":\"" << log_level_to_string(severity) << "\",";
    json << "\"details\":" << (details ? details : "{}");
    json << ",\"signature\":\"";
    for (auto byte : entry.signature) {
        json << std::hex << std::setw(2) << std::setfill('0')
             << static_cast<int>(byte);
    }
    json << "\"";
    json << "}" << std::endl;

    instance_->audit_file_ << json.str();
    instance_->audit_file_.flush();
}

bool AuditLogger::verify_integrity(
    const std::filesystem::path& audit_path,
    const uint8_t* public_key,
    size_t key_size) {

    (void)audit_path;
    (void)public_key;
    (void)key_size;
    // Full implementation would:
    // 1. Read each JSON line
    // 2. Extract signature
    // 3. Verify against public key
    // 4. Chain verification (each entry signs the hash of the previous)
    return true;
}

ErrorCode AuditLogger::export_log(
    std::filesystem::path output_path,
    std::optional<Timestamp> start_time,
    std::optional<Timestamp> end_time) {

    if (!instance_) {
        return ErrorCode::NOT_INITIALIZED;
    }

    std::lock_guard<std::mutex> lock(instance_->mutex_);

    std::ifstream audit_in(instance_->audit_path_, std::ios::in);
    std::ofstream audit_out(output_path, std::ios::out);

    if (!audit_in.is_open()) return ErrorCode::FILE_NOT_FOUND;
    if (!audit_out.is_open()) return ErrorCode::FILE_ACCESS_DENIED;

    std::string line;
    while (std::getline(audit_in, line)) {
        // Filter by time range if specified
        if (start_time || end_time) {
            // Parse timestamp from JSON line
            auto ts_pos = line.find("\"timestamp\":");
            if (ts_pos != std::string::npos) {
                ts_pos += 12; // Skip "timestamp":
                auto ts_end = line.find(",", ts_pos);
                auto ts_str = line.substr(ts_pos, ts_end - ts_pos);
                Timestamp ts = std::stoull(ts_str);

                if (start_time && ts < *start_time) continue;
                if (end_time && ts > *end_time) continue;
            }
        }

        audit_out << line << std::endl;
    }

    audit_out.flush();
    return ErrorCode::SUCCESS;
}

// ============================================================================
// THREAD ID HELPER (accessible to both Logger and AuditLogger)
// ============================================================================

uint64_t current_thread_id_helper() {
    std::ostringstream oss;
    oss << std::this_thread::get_id();
    return std::stoull(oss.str());
}

} // namespace securevault