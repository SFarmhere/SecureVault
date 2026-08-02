// ============================================================================
// SecureVault - Platform Abstraction Layer Implementation
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
// ============================================================================

#include "platform.h"
#include "logging.h"

#include <cstring>
#include <limits>
#include <system_error>
#include <thread>
#include <chrono>
#include <vector>

#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <bcrypt.h>
    #include <processthreadsapi.h>
    #include <memoryapi.h>
    #include <sysinfoapi.h>
    #include <intrin.h>
#elif defined(SECUREVAULT_PLATFORM_LINUX)
    #include <unistd.h>
    #include <sys/mman.h>
    #include <sys/sysinfo.h>
    #include <sys/resource.h>
    #include <sys/utsname.h>
    #include <cpuid.h>
    #include <pthread.h>
    #include <sched.h>
#elif defined(SECUREVAULT_PLATFORM_MACOS)
    #include <unistd.h>
    #include <sys/mman.h>
    #include <sys/sysctl.h>
    #include <sys/resource.h>
    #include <sys/utsname.h>
    #include <mach/mach_time.h>
    #include <mach/mach_init.h>
    #include <pthread.h>
#endif

namespace securevault {

// ============================================================================
// STATIC MEMBERS
// ============================================================================

CpuFeatures Platform::cached_cpu_features_;
bool Platform::initialized_ = false;

// ============================================================================
// INITIALIZATION
// ============================================================================

ErrorCode Platform::initialize() {
    if (initialized_) {
        return ErrorCode::SUCCESS;
    }
    cached_cpu_features_ = detect_cpu_features();
    initialized_ = true;

    LOG_INFO("shared", "platform", "Platform initialized: {} {} cores, {} MB RAM",
        cached_cpu_features_.model_name,
        cached_cpu_features_.logical_cores,
        total_physical_memory() / (1024 * 1024));

    return ErrorCode::SUCCESS;
}

void Platform::shutdown() {
    initialized_ = false;
    LOG_INFO("shared", "platform", "Platform shutdown complete");
}

// ============================================================================
// CPU FEATURE DETECTION
// ============================================================================

CpuFeatures Platform::detect_cpu_features() {
    CpuFeatures features;

#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    features.logical_cores = sysInfo.dwNumberOfProcessors;
    features.page_size = sysInfo.dwPageSize;

    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    char vendor[13] = {0};
    std::memcpy(vendor, &cpuInfo[1], 4);
    std::memcpy(vendor + 4, &cpuInfo[3], 4);
    std::memcpy(vendor + 8, &cpuInfo[2], 4);
    features.vendor = vendor;

    __cpuid(cpuInfo, 1);
    features.aes_ni = (cpuInfo[2] & (1 << 25)) != 0;
    features.avx = (cpuInfo[2] & (1 << 28)) != 0;
    features.rdrand = (cpuInfo[2] & (1 << 30)) != 0;
    features.clmul = (cpuInfo[2] & (1 << 1)) != 0;
    features.ssse3 = (cpuInfo[2] & (1 << 9)) != 0;
    features.pclmulqdq = (cpuInfo[2] & (1 << 1)) != 0;

    __cpuid(cpuInfo, 7);
    features.avx2 = (cpuInfo[1] & (1 << 5)) != 0;
    features.bmi2 = (cpuInfo[1] & (1 << 8)) != 0;
    features.adx = (cpuInfo[1] & (1 << 19)) != 0;
    features.sha_ni = (cpuInfo[1] & (1 << 29)) != 0;
    features.avx512 = (cpuInfo[1] & (1 << 16)) != 0;
    features.rdseed = (cpuInfo[1] & (1 << 18)) != 0;

    features.cache_line_size = 64;

    DWORD bufferSize = 0;
    GetLogicalProcessorInformation(nullptr, &bufferSize);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> buffer(
            bufferSize / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));
        if (GetLogicalProcessorInformation(buffer.data(), &bufferSize)) {
            for (const auto& info : buffer) {
                if (info.Relationship == RelationProcessorCore) {
                    features.physical_cores++;
                }
                if (info.Relationship == RelationCache) {
                    if (info.Cache.Level == 1 && info.Cache.Type == CacheData)
                        features.l1_data_cache_kb = info.Cache.Size / 1024;
                    else if (info.Cache.Level == 2)
                        features.l2_cache_kb = info.Cache.Size / 1024;
                    else if (info.Cache.Level == 3)
                        features.l3_cache_kb = info.Cache.Size / 1024;
                }
            }
        }
    }

#elif defined(SECUREVAULT_PLATFORM_LINUX)
    features.logical_cores = static_cast<uint32_t>(sysconf(_SC_NPROCESSORS_ONLN));
    features.page_size = static_cast<uint32_t>(sysconf(_SC_PAGESIZE));
    features.physical_cores = static_cast<uint32_t>(sysconf(_SC_NPROCESSORS_CONF));

    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        char vendor[13] = {0};
        std::memcpy(vendor, &ebx, 4);
        std::memcpy(vendor + 4, &edx, 4);
        std::memcpy(vendor + 8, &ecx, 4);
        features.vendor = vendor;
    }
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        features.aes_ni = (ecx & (1 << 25)) != 0;
        features.avx = (ecx & (1 << 28)) != 0;
        features.rdrand = (ecx & (1 << 30)) != 0;
        features.clmul = (ecx & (1 << 1)) != 0;
        features.ssse3 = (ecx & (1 << 9)) != 0;
        features.pclmulqdq = (ecx & (1 << 1)) != 0;
    }
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        features.avx2 = (ebx & (1 << 5)) != 0;
        features.bmi2 = (ebx & (1 << 8)) != 0;
        features.adx = (ebx & (1 << 19)) != 0;
        features.sha_ni = (ebx & (1 << 29)) != 0;
        features.avx512 = (ebx & (1 << 16)) != 0;
        features.rdseed = (ebx & (1 << 18)) != 0;
    }

#elif defined(SECUREVAULT_PLATFORM_MACOS)
    features.logical_cores = static_cast<uint32_t>(sysconf(_SC_NPROCESSORS_ONLN));
    features.page_size = static_cast<uint32_t>(sysconf(_SC_PAGESIZE));

    int cpu_count = 0;
    size_t size = sizeof(cpu_count);
    if (sysctlbyname("hw.physicalcpu", &cpu_count, &size, nullptr, 0) == 0)
        features.physical_cores = static_cast<uint32_t>(cpu_count);

    int64_t cache_size = 0;
    size = sizeof(cache_size);
    if (sysctlbyname("hw.l1dcachesize", &cache_size, &size, nullptr, 0) == 0)
        features.l1_data_cache_kb = static_cast<uint32_t>(cache_size / 1024);
    if (sysctlbyname("hw.l2cachesize", &cache_size, &size, nullptr, 0) == 0)
        features.l2_cache_kb = static_cast<uint32_t>(cache_size / 1024);
    if (sysctlbyname("hw.l3cachesize", &cache_size, &size, nullptr, 0) == 0)
        features.l3_cache_kb = static_cast<uint32_t>(cache_size / 1024);

    features.cache_line_size = 64;
#endif

    features.constant_time_enforced = true;
    return features;
}

const CpuFeatures& Platform::cpu_features() {
    if (!initialized_) cached_cpu_features_ = detect_cpu_features();
    return cached_cpu_features_;
}

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

ErrorCode Platform::lock_memory(void* addr, size_t size) {
    if (!addr || size == 0) return ErrorCode::INVALID_ARGUMENT;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    return VirtualLock(addr, size) ? ErrorCode::SUCCESS :
        system_error_to_error_code(GetLastError());
#else
    return mlock(addr, size) == 0 ? ErrorCode::SUCCESS :
        system_error_to_error_code(errno);
#endif
}

ErrorCode Platform::unlock_memory(void* addr, size_t size) {
    if (!addr || size == 0) return ErrorCode::INVALID_ARGUMENT;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    return VirtualUnlock(addr, size) ? ErrorCode::SUCCESS :
        system_error_to_error_code(GetLastError());
#else
    return munlock(addr, size) == 0 ? ErrorCode::SUCCESS :
        system_error_to_error_code(errno);
#endif
}

ErrorCode Platform::protect_memory(void* addr, size_t size, bool read, bool write, bool execute) {
    if (!addr || size == 0) return ErrorCode::INVALID_ARGUMENT;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    DWORD prot = PAGE_NOACCESS;
    if (read && write && !execute) prot = PAGE_READWRITE;
    else if (read && !write && !execute) prot = PAGE_READONLY;
    else if (read && write && execute) prot = PAGE_EXECUTE_READWRITE;
    else if (!read && !write && execute) prot = PAGE_EXECUTE;
    else if (read && !write && execute) prot = PAGE_EXECUTE_READ;
    DWORD old;
    return VirtualProtect(addr, size, prot, &old) ? ErrorCode::SUCCESS :
        system_error_to_error_code(GetLastError());
#else
    int prot = 0;
    if (read)  prot |= PROT_READ;
    if (write) prot |= PROT_WRITE;
    if (execute) prot |= PROT_EXEC;
    return mprotect(addr, size, prot) == 0 ? ErrorCode::SUCCESS :
        system_error_to_error_code(errno);
#endif
}

void* Platform::allocate_pages(size_t size) {
    size_t ps = page_size();
    size_t aligned = ((size + ps - 1) / ps) * ps;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    return VirtualAlloc(nullptr, aligned, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    void* ptr = mmap(nullptr, aligned, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (ptr == MAP_FAILED) ? nullptr : ptr;
#endif
}

void Platform::free_pages(void* addr, size_t size) {
    if (!addr) return;
    size_t ps = page_size();
    size_t aligned = ((size + ps - 1) / ps) * ps;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    VirtualFree(addr, 0, MEM_RELEASE);
#else
    munmap(addr, aligned);
#endif
}

size_t Platform::page_size() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    return static_cast<size_t>(sysconf(_SC_PAGESIZE));
#endif
}

// ============================================================================
// HIGH-RESOLUTION TIMING
// ============================================================================

Timestamp Platform::now_ns() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    ULARGE_INTEGER li;
    li.LowPart = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    return static_cast<Timestamp>(li.QuadPart * 100);
#elif defined(SECUREVAULT_PLATFORM_MACOS)
    return static_cast<Timestamp>(mach_continuous_time());
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return static_cast<Timestamp>(ts.tv_sec) * 1'000'000'000 +
           static_cast<Timestamp>(ts.tv_nsec);
#endif
}

Timestamp Platform::monotonic_ns() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return static_cast<Timestamp>(counter.QuadPart * 1'000'000'000 / freq.QuadPart);
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return static_cast<Timestamp>(ts.tv_sec) * 1'000'000'000 +
           static_cast<Timestamp>(ts.tv_nsec);
#endif
}

void Platform::sleep_ns(uint64_t nanoseconds) {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    HANDLE timer = CreateWaitableTimer(nullptr, TRUE, nullptr);
    if (timer) {
        LARGE_INTEGER due;
        due.QuadPart = -static_cast<int64_t>(nanoseconds / 100);
        SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE);
        WaitForSingleObject(timer, INFINITE);
        CloseHandle(timer);
    }
#else
    struct timespec ts;
    ts.tv_sec = static_cast<time_t>(nanoseconds / 1'000'000'000);
    ts.tv_nsec = static_cast<long>(nanoseconds % 1'000'000'000);
    nanosleep(&ts, nullptr);
#endif
}

// ============================================================================
// CRYPTOGRAPHIC RANDOM
// ============================================================================

ErrorCode Platform::secure_random(MutableByteSpan buffer) {
    if (buffer.empty()) return ErrorCode::SUCCESS;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    NTSTATUS status = BCryptGenRandom(nullptr, buffer.data(), 
                                    static_cast<ULONG>(buffer.size()),
                                    BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return (status == 0) ? ErrorCode::SUCCESS : ErrorCode::ENCRYPTION_FAILED;
#elif defined(SECUREVAULT_PLATFORM_LINUX)
    if (getentropy(buffer.data(), buffer.size()) == 0) return ErrorCode::SUCCESS;
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return ErrorCode::ENCRYPTION_FAILED;
    size_t r = fread(buffer.data(), 1, buffer.size(), f);
    fclose(f);
    return r == buffer.size() ? ErrorCode::SUCCESS : ErrorCode::ENCRYPTION_FAILED;
#else
    return getentropy(buffer.data(), buffer.size()) == 0 ?
           ErrorCode::SUCCESS : ErrorCode::ENCRYPTION_FAILED;
#endif
}

uint64_t Platform::secure_random_u64() {
    uint64_t value = 0;
    secure_random(MutableByteSpan(reinterpret_cast<uint8_t*>(&value), sizeof(value)));
    return value;
}

// ============================================================================
// PROCESS INFORMATION
// ============================================================================

ProcessInfo Platform::current_process() {
    ProcessInfo info;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    info.pid = GetCurrentProcessId();
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev;
        DWORD size = sizeof(elev);
        if (GetTokenInformation(token, TokenElevation, &elev, size, &size))
            info.is_elevated = elev.TokenIsElevated != 0;
        CloseHandle(token);
    }
    info.has_console = GetConsoleWindow() != nullptr;
    info.is_debugged = IsDebuggerPresent() != FALSE;
#else
    info.pid = static_cast<uint64_t>(getpid());
    info.is_elevated = (geteuid() == 0);
    info.has_console = isatty(STDOUT_FILENO) != 0;
#endif
    info.page_size = static_cast<uint32_t>(page_size());
    return info;
}

bool Platform::is_debugged() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    return IsDebuggerPresent() != FALSE;
#elif defined(SECUREVAULT_PLATFORM_LINUX)
    FILE* f = fopen("/proc/self/status", "r");
    if (!f) return false;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "TracerPid:", 10) == 0) {
            long pid = std::strtol(line + 10, nullptr, 10);
            fclose(f);
            return pid != 0;
        }
    }
    fclose(f);
    return false;
#else
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc kp;
    size_t len = sizeof(kp);
    if (sysctl(mib, 4, &kp, &len, nullptr, 0) == 0)
        return (kp.kp_proc.p_flag & P_TRACED) != 0;
    return false;
#endif
}

ErrorCode Platform::raise_priority(bool realtime) {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    DWORD prio = realtime ? REALTIME_PRIORITY_CLASS : HIGH_PRIORITY_CLASS;
    return SetPriorityClass(GetCurrentProcess(), prio) ? ErrorCode::SUCCESS :
        system_error_to_error_code(GetLastError());
#else
    int prio = realtime ? -20 : -10;
    return setpriority(PRIO_PROCESS, 0, prio) == 0 ? ErrorCode::SUCCESS :
        system_error_to_error_code(errno);
#endif
}

ErrorCode Platform::lower_priority() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    return SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS) ? ErrorCode::SUCCESS :
        system_error_to_error_code(GetLastError());
#else
    return setpriority(PRIO_PROCESS, 0, 0) == 0 ? ErrorCode::SUCCESS :
        system_error_to_error_code(errno);
#endif
}

// ============================================================================
// OS INFORMATION
// ============================================================================

OsInfo Platform::os_info() {
    OsInfo info;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    info.name = "Windows";
    OSVERSIONINFOW osvi = {sizeof(osvi)};
#pragma warning(push)
#pragma warning(disable: 4996)
    if (GetVersionExW(&osvi)) {
#pragma warning(pop)
        info.version = std::to_string(osvi.dwMajorVersion) + "." +
                       std::to_string(osvi.dwMinorVersion);
        info.build = std::to_string(osvi.dwBuildNumber);
    }
    info.kernel_name = "Windows NT";
    info.architecture = "x86_64";
#else
    struct utsname uts;
    if (uname(&uts) == 0) {
        info.name = uts.sysname;
        info.version = uts.release;
        info.kernel_name = uts.sysname;
        info.kernel_version = uts.version;
        info.architecture = uts.machine;
    }
#endif
    info.is_64bit = true;
    return info;
}

std::filesystem::path Platform::temp_directory() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    char path[MAX_PATH];
    return GetTempPathA(MAX_PATH, path) ? std::filesystem::path(path) :
        std::filesystem::path("C:\\Temp");
#else
    const char* tmp = std::getenv("TMPDIR");
    return (tmp && *tmp) ? std::filesystem::path(tmp) : std::filesystem::path("/tmp");
#endif
}

std::filesystem::path Platform::home_directory() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    const char* home = std::getenv("USERPROFILE");
    return (home && *home) ? std::filesystem::path(home) :
        std::filesystem::path("C:\\Users\\Default");
#else
    const char* home = std::getenv("HOME");
    return (home && *home) ? std::filesystem::path(home) :
        std::filesystem::path("/root");
#endif
}

std::filesystem::path Platform::app_data_directory() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    const char* appData = std::getenv("LOCALAPPDATA");
    return (appData && *appData) ? std::filesystem::path(appData) / "SecureVault" :
        home_directory() / "SecureVault";
#elif defined(SECUREVAULT_PLATFORM_LINUX)
    const char* xdg = std::getenv("XDG_DATA_HOME");
    return (xdg && *xdg) ? std::filesystem::path(xdg) / "securevault" :
        home_directory() / ".local" / "share" / "securevault";
#else
    return home_directory() / "Library" / "Application Support" / "SecureVault";
#endif
}

// ============================================================================
// ERROR HANDLING
// ============================================================================

ErrorCode Platform::system_error_to_error_code(int32_t code) {
    switch (code) {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
        case ERROR_SUCCESS:             return ErrorCode::SUCCESS;
        case ERROR_FILE_NOT_FOUND:      return ErrorCode::FILE_NOT_FOUND;
        case ERROR_ACCESS_DENIED:       return ErrorCode::ACCESS_DENIED;
        case ERROR_OUTOFMEMORY:         return ErrorCode::OUT_OF_MEMORY;
        case ERROR_LOCK_VIOLATION:      return ErrorCode::FILE_LOCKED;
        case ERROR_DISK_FULL:           return ErrorCode::DISK_FULL;
        case ERROR_INVALID_PARAMETER:   return ErrorCode::INVALID_ARGUMENT;
        case ERROR_TIMEOUT:             return ErrorCode::OPERATION_TIMEOUT;
        case ERROR_CANCELLED:           return ErrorCode::OPERATION_CANCELLED;
#else
        case 0:                         return ErrorCode::SUCCESS;
        case EACCES:                    return ErrorCode::ACCESS_DENIED;
        case EAGAIN:                    return ErrorCode::RESOURCE_BUSY;
        case EBADF:                     return ErrorCode::INVALID_HANDLE;
        case EINVAL:                    return ErrorCode::INVALID_ARGUMENT;
        case EIO:                       return ErrorCode::IO_ERROR;
        case ENOENT:                    return ErrorCode::FILE_NOT_FOUND;
        case ENOMEM:                    return ErrorCode::OUT_OF_MEMORY;
        case ENOSPC:                    return ErrorCode::DISK_FULL;
        case EPERM:                     return ErrorCode::PERMISSION_DENIED;
        case ETIMEDOUT:                 return ErrorCode::OPERATION_TIMEOUT;
#endif
        default:                        return ErrorCode::UNKNOWN_ERROR;
    }
}

std::string Platform::last_system_error_message() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    DWORD err = GetLastError();
    LPSTR buf = nullptr;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                   nullptr, err, 0, reinterpret_cast<LPSTR>(&buf), 0, nullptr);
    std::string msg(buf);
    LocalFree(buf);
    return msg;
#else
    return std::string(std::strerror(errno));
#endif
}

// ============================================================================
// UTILITY
// ============================================================================

ErrorCode Platform::disable_core_dumps() {
#if defined(SECUREVAULT_PLATFORM_POSIX)
    struct rlimit rlim = {0, 0};
    return setrlimit(RLIMIT_CORE, &rlim) == 0 ? ErrorCode::SUCCESS :
        system_error_to_error_code(errno);
#else
    return ErrorCode::NOT_IMPLEMENTED;
#endif
}

uint64_t Platform::available_physical_memory() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    MEMORYSTATUSEX mem = {sizeof(mem)};
    return GlobalMemoryStatusEx(&mem) ? mem.ullAvailPhys : 0;
#elif defined(SECUREVAULT_PLATFORM_LINUX)
    struct sysinfo si;
    return (sysinfo(&si) == 0) ? static_cast<uint64_t>(si.freeram) * si.mem_unit : 0;
#else
    int64_t mem = 0;
    size_t size = sizeof(mem);
    return (sysctlbyname("hw.memsize", &mem, &size, nullptr, 0) == 0) ?
        static_cast<uint64_t>(mem) : 0;
#endif
}

uint64_t Platform::total_physical_memory() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    MEMORYSTATUSEX mem = {sizeof(mem)};
    return GlobalMemoryStatusEx(&mem) ? mem.ullTotalPhys : 0;
#elif defined(SECUREVAULT_PLATFORM_LINUX)
    struct sysinfo si;
    return (sysinfo(&si) == 0) ? static_cast<uint64_t>(si.totalram) * si.mem_unit : 0;
#else
    int64_t mem = 0;
    size_t size = sizeof(mem);
    return (sysctlbyname("hw.memsize", &mem, &size, nullptr, 0) == 0) ?
        static_cast<uint64_t>(mem) : 0;
#endif
}

bool Platform::is_on_battery_power() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    SYSTEM_POWER_STATUS ps;
    return GetSystemPowerStatus(&ps) ? (ps.ACLineStatus == 0) : false;
#else
    return false;
#endif
}

uint32_t Platform::cpu_core_count() {
    return cpu_features().logical_cores;
}

ErrorCode Platform::set_thread_affinity(const std::vector<uint32_t>& cores) {
    if (cores.empty()) return ErrorCode::INVALID_ARGUMENT;
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    DWORD_PTR mask = 0;
    for (auto c : cores) mask |= (1ULL << c);
    return SetThreadAffinityMask(GetCurrentThread(), mask) ? ErrorCode::SUCCESS :
        system_error_to_error_code(GetLastError());
#elif defined(SECUREVAULT_PLATFORM_LINUX)
    cpu_set_t set;
    CPU_ZERO(&set);
    for (auto c : cores) CPU_SET(c, &set);
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == 0 ?
        ErrorCode::SUCCESS : system_error_to_error_code(errno);
#else
    return ErrorCode::PLATFORM_NOT_SUPPORTED;
#endif
}

ErrorCode Platform::clear_thread_affinity() {
#if defined(SECUREVAULT_PLATFORM_WINDOWS)
    return SetThreadAffinityMask(GetCurrentThread(), ~(DWORD_PTR)0) ? ErrorCode::SUCCESS :
        system_error_to_error_code(GetLastError());
#elif defined(SECUREVAULT_PLATFORM_LINUX)
    cpu_set_t set;
    CPU_ZERO(&set);
    for (uint32_t i = 0; i < CPU_SETSIZE; i++) CPU_SET(i, &set);
    return pthread_setaffinity_np(pthread_self(), sizeof(set), &set) == 0 ?
        ErrorCode::SUCCESS : system_error_to_error_code(errno);
#else
    return ErrorCode::PLATFORM_NOT_SUPPORTED;
#endif
}

} // namespace securevault
