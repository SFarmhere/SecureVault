// ============================================================================
// SecureVault - Вспомогательные функции для тестов PKCS#11
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Вспомогательные функции, используемые в модульных тестах:
//   создание тестовых ключей, сертификатов, проверка соответствия.
// ============================================================================

#include "test_utils.h"

#include <chrono>
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>

#include "../src/adapters/pkcs11_helpers.h"

namespace securevault {
namespace pkcs11 {
namespace test {

using helpers::BytesToHex;

// ============================================================================
// ГЕНЕРАЦИЯ ТЕСТОВЫХ ДАННЫХ
// ============================================================================

std::string GenerateHexId(size_t bytes) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < bytes * 2; ++i) {
        ss << std::setw(1) << dis(gen);
    }
    return ss.str();
}

KeyInfo MakeTestKeyInfo(const std::string& id, const std::string& label,
                        KeyType type, KeySizeBits bits) {
    KeyInfo info;
    info.set_id(id.c_str());
    info.set_label(label.c_str());
    info.type = type;
    info.size_bits = bits;
    info.created_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    info.set_token(true);
    info.set_modifiable(true);
    return info;
}

TokenInfo MakeTestTokenInfo(TokenType type, const std::string& serial) {
    TokenInfo info;
    info.type = type;
    strncpy(info.serial_number, serial.c_str(), sizeof(info.serial_number) - 1);
    info.set_initialized(true);
    info.set_hardware(true);
    info.set_removable(true);
    info.max_pin_len = 8;
    info.min_pin_len = 4;
    info.pin_retries = 3;
    info.so_pin_retries = 3;
    info.insert_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return info;
}

CertificateInfo MakeTestCertificate(const std::string& id,
                                    const std::string& subject,
                                    int64_t not_before_ms,
                                    int64_t not_after_ms) {
    CertificateInfo info;
    strncpy(info.id, id.c_str(), sizeof(info.id) - 1);
    strncpy(info.subject, subject.c_str(), sizeof(info.subject) - 1);
    strncpy(info.issuer, subject.c_str(), sizeof(info.issuer) - 1);
    strncpy(info.serial_number, "1234567890", sizeof(info.serial_number) - 1);
    info.not_before_ms = not_before_ms;
    info.not_after_ms = not_after_ms;
    info.format = CertificateFormat::X509_DER;
    info.version = 3;
    return info;
}

// ============================================================================
// ПРОВЕРКА СООТВЕТСТВИЯ
// ============================================================================

bool IsKeyInfoEqual(const KeyInfo& a, const KeyInfo& b) {
    return std::strcmp(a.get_id(), b.get_id()) == 0 &&
           std::strcmp(a.get_label(), b.get_label()) == 0 &&
           a.type == b.type &&
           a.size_bits == b.size_bits &&
           a.flags == b.flags;
}

bool IsTokenInfoEqual(const TokenInfo& a, const TokenInfo& b) {
    return a.type == b.type &&
           std::strcmp(a.serial_number, b.serial_number) == 0 &&
           a.flags == b.flags;
}

// ============================================================================
// ГЕНЕРАЦИЯ СЛУЧАЙНЫХ ДАННЫХ
// ============================================================================

std::vector<uint8_t> GenerateRandomBytes(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dis(0, 255);
    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(dis(gen));
    }
    return data;
}

std::string GenerateRandomHex(size_t bytes) {
    return BytesToHex(GenerateRandomBytes(bytes));
}

} // namespace test
} // namespace pkcs11
} // namespace securevault