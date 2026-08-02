// ============================================================================
// SecureVault - Platform Abstraction Layer
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
// ============================================================================

#ifndef SECUREVAULT_PLATFORM_H
#define SECUREVAULT_PLATFORM_H

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <optional>
#include <memory>
#include <vector>
#include <filesystem>
#include <limits>
#include <new>

#include "common_types.h"
#include "error_codes.h"

// ============================================================================
// PLATFORM DETECTION MACROS
// ============================================================================

#ifndef SECUREVAULT_PLATFORM_WINDOWS
    #if defined(_WIN32) || defined(_WIN64)
        #define SECUREVAULT_PLATFORM_WINDOWS 1
    #endif
#endif

#ifndef SECUREVAULT_PLATFORM_LINUX
    #if defined(__linux__) || defined(__linux)
        #define SECUREVAULT_PLATFORM_LINUX 1
    #endif
#endif

#ifndef SECUREVAULT_PLATFORM_MACOS
    #if defined(__APPLE__) || defined(__MACH__)
        #define SECUREVAULT_PLATFORM_MACOS 1
    #endif
#endif

#if defined(SECUREVAULT_PLATFORM_LINUX) || defined(SECUREVAULT_PLATFORM_MACOS)
    #define SECUREVAULT_PLATFORM_POSIX 1
#endif

namespace securevault {

// ============================================================================
// CPU FEATURE DETECTION
// ============================================================================

struct CpuFeatures {
    bool aes_ni = false;
    bool avx = false;
    bool avx2 = false;
    bool avx512 = false;
    bool sha_ni = false;
    bool rdrand = false;
    bool rdseed = false;
    bool clmul = false;
    bool ssse3 = false;
    bool bmi2 = false;
    bool adx = false;
    bool pclmulqdq = false;
    bool sm3_sm4 = false;
    bool constant_time_enforced = true;
    std::string vendor;
    std::string model_name;
    uint32_t logical_cores = 0;
    uint32_t physical_cores = 0;
    uint32_t page_size = 4096;
    uint32_t cache_line_size = 64;
    uint32_t l1_data_cache_kb = 32;
    uint32_t l2_cache_kb = 256;
    uint32_t l3_cache_kb = 8192;
};

// ============================================================================
// OS AND PROCESS INFO
// ============================================================================

struct OsInfo {
    std::string name;
    std::string version;
    std::string build;
    std::string architecture;
    bool is_64bit = true;
    bool is_container = false;
    bool is_virtual_machine = false;
    std::string kernel_name;
    std::string kernel_version;
};

struct ProcessInfo {
    uint64_t pid = 0;
    uint64_t ppid = 0;
    std::string name;
    std::string executable_path;
    std::string command_line;
    std::string working_directory;
    std::string user_id;
    bool is_elevated = false;
    bool is_service = false;
    uint32_t page_size = 4096;
    bool is_debugged = false;
    bool has_console = true;
};

// ============================================================================
// PLATFORM CLASS
// ============================================================================

class Platform {
public:
    Platform() = delete;

    static ErrorCode initialize();
    static void shutdown();

    static CpuFeatures detect_cpu_features();
    static const CpuFeatures& cpu_features();

    static ErrorCode lock_memory(void* addr, size_t size);
    static ErrorCode unlock_memory(void* addr, size_t size);
    static ErrorCode protect_memory(void* addr, size_t size, bool read, bool write, bool execute);
    static void* allocate_pages(size_t size);
    static void free_pages(void* addr, size_t size);
    static size_t page_size();

    static Timestamp now_ns();
    static Timestamp monotonic_ns();
    static void sleep_ns(uint64_t nanoseconds);

    static ProcessInfo current_process();
    static bool is_debugged();
    static ErrorCode raise_priority(bool realtime = false);
    static ErrorCode lower_priority();

    static OsInfo os_info();
    static std::filesystem::path temp_directory();
    static std::filesystem::path home_directory();
    static std::filesystem::path app_data_directory();

    static ErrorCode secure_random(MutableByteSpan buffer);
    static uint64_t secure_random_u64();

    static ErrorCode set_thread_affinity(const std::vector<uint32_t>& core_indices);
    static ErrorCode clear_thread_affinity();

    static ErrorCode system_error_to_error_code(int32_t system_error_code);
    static std::string last_system_error_message();

    static ErrorCode disable_core_dumps();
    static uint64_t available_physical_memory();
    static uint64_t total_physical_memory();
    static bool is_on_battery_power();
    static uint32_t cpu_core_count();

private:
    static CpuFeatures cached_cpu_features_;
    static bool initialized_;
};

// ============================================================================
// SECURE ALLOCATOR
// ============================================================================

template <typename T>
class SecureAllocator {
public:
    using value_type = T;

    SecureAllocator() noexcept = default;

    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(size_t n) {
        if (n > std::numeric_limits<size_t>::max() / sizeof(T)) {
            throw std::bad_array_new_length();
        }
        size_t bytes = n * sizeof(T);
        void* ptr = Platform::allocate_pages(bytes);
        if (!ptr) throw std::bad_alloc();
        Platform::lock_memory(ptr, bytes);
        memset(ptr, 0, bytes);
        return static_cast<T*>(ptr);
    }

    void deallocate(T* ptr, size_t n) noexcept {
        if (!ptr) return;
        size_t bytes = n * sizeof(T);
        memset(static_cast<void*>(ptr), 0, bytes);
        Platform::unlock_memory(ptr, bytes);
        Platform::free_pages(ptr, bytes);
    }

    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

using SecureByteArray = std::vector<uint8_t, SecureAllocator<uint8_t>>;
using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

// ============================================================================
// ENDIAN CONVERSION
// ============================================================================

inline uint16_t host_to_be16(uint16_t value) noexcept {
    #if defined(SECUREVAULT_PLATFORM_WINDOWS)
        return _byteswap_ushort(value);
    #else
        return __builtin_bswap16(value);
    #endif
}

inline uint32_t host_to_be32(uint32_t value) noexcept {
    #if defined(SECUREVAULT_PLATFORM_WINDOWS)
        return _byteswap_ulong(value);
    #else
        return __builtin_bswap32(value);
    #endif
}

inline uint64_t host_to_be64(uint64_t value) noexcept {
    #if defined(SECUREVAULT_PLATFORM_WINDOWS)
        return _byteswap_uint64(value);
    #else
        return __builtin_bswap64(value);
    #endif
}

inline uint16_t be16_to_host(uint16_t value) noexcept { return host_to_be16(value); }
inline uint32_t be32_to_host(uint32_t value) noexcept { return host_to_be32(value); }
inline uint64_t be64_to_host(uint64_t value) noexcept { return host_to_be64(value); }

} // namespace securevault

#endif // SECUREVAULT_PLATFORM_H