// ============================================================================
// SecureVault - Test Compilation File
// Version: 2.0.0
// (c) 2026 SecureVault Contributors
// License: GNU GPL v3
//
// PURPOSE:
//   Simple compilation test to verify all shared headers compile correctly.
//   Run: g++ -std=c++17 -I. -c test_compile.cpp -o test_compile.o
// ============================================================================

#include "include/common_types.h"
#include "include/error_codes.h"
#include "include/platform.h"
#include "include/logging.h"
#include "include/config.h"

// Verify enum values
static_assert(static_cast<int>(securevault::SecurityLevel::ORIGINAL) == 0, "SecurityLevel enum mismatch");
static_assert(static_cast<int>(securevault::LogLevel::EMERGENCY) == 0, "LogLevel enum mismatch");

using namespace securevault;

// Fixed-size buffer test
static_assert(sizeof(Aes256Key) == 32, "AES-256 key must be 32 bytes");
static_assert(sizeof(AesGcmIv) == 12, "AES-GCM IV must be 12 bytes");
static_assert(sizeof(Sha256Digest) == 32, "SHA-256 digest must be 32 bytes");

// KDF parameter structs
Argon2Params argon2_params;
Pbkdf2Params pbkdf2_params;
ScryptParams scrypt_params;

// Container metadata
ContainerInfo container_info;
FileMetadata file_meta;

// Result type
Result<int> int_result = Result<int>::ok(42);
Result<void> void_result = Result<void>::ok();

// Error codes
ErrorCode ec = ErrorCode::SUCCESS;
CryptoError ce = CryptoError::CRYPTO_BASE;

// Platform structs
CpuFeatures cpu;
OsInfo os;
ProcessInfo proc;

// Secure allocator
SecureAllocator<uint8_t> alloc;
SecureByteArray secure_bytes;
SecureString secure_str;

// Endian conversion
uint16_t be16 = host_to_be16(0x1234);
uint32_t be32 = host_to_be32(0x12345678);
uint64_t be64 = host_to_be64(0x123456789ABCDEF0ULL);

// Config types
ConfigNode node;
std::any config_value;

// Logger types
LogEntry log_entry;

int main() {
    // Verify security level conversion
    auto level_str = security_level_to_string(SecurityLevel::HYPER);
    (void)level_str;

    // Verify log level conversion
    auto log_str = log_level_to_string(LogLevel::INFO);
    (void)log_str;

    // Verify error code conversion
    auto err_str = error_code_to_string(ErrorCode::SUCCESS);
    (void)err_str;

    // Verify crypto error conversion
    auto cerr_str = crypto_error_to_string(CryptoError::CRYPTO_BASE);
    (void)cerr_str;

    // Verify std::any config value
    config_value = true;
    config_value = int64_t(42);
    config_value = std::string("test");

    // Verify ConfigNode
    node.value = config_value;
    node.description = "Test config value";
    node.required = true;

    // Verify LogEntry
    log_entry.timestamp = 0;
    log_entry.level = LogLevel::INFO;
    log_entry.module = "test";
    log_entry.component = "compile_test";
    log_entry.message = "Compilation test passed";

    // Verify ByteSpan
    uint8_t test_data[] = {1, 2, 3, 4};
    ByteSpan span(test_data, 4);
    MutableByteSpan mspan(test_data, 4);
    (void)span;
    (void)mspan;

    return 0;
}