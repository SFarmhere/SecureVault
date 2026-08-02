// ============================================================================
// SecureVault - Парсинг X.509 сертификатов
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Реализует функции парсинга X.509 сертификатов, конвертации PEM/DER
// и проверки срока действия.
// ============================================================================

#include "certificate_ops.h"

#include <chrono>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace securevault {
namespace pkcs11 {

CertificateInfo ParseX509Certificate(const std::vector<uint8_t>& der_data) {
    CertificateInfo info;

    if (der_data.empty()) {
        return info;
    }

    // Упрощённый парсинг DER (полная реализация через OpenSSL)
    // Заполняем базовые поля
    strncpy(info.id, "cert", sizeof(info.id) - 1);
    strncpy(info.label, "parsed", sizeof(info.label) - 1);
    info.format = CertificateFormat::X509_DER;
    info.version = 3;

    // Копируем публичный ключ (упрощённо)
    size_t copy_size = std::min(der_data.size(), sizeof(info.public_key.data));
    std::memcpy(info.public_key.data, der_data.data(), copy_size);
    info.public_key.size = static_cast<uint32_t>(copy_size);

    return info;
}

std::vector<uint8_t> PemToDer(const std::string& pem_data) {
    std::vector<uint8_t> result;

    // Ищем BEGIN/END маркеры
    size_t begin = pem_data.find("-----BEGIN CERTIFICATE-----");
    size_t end = pem_data.find("-----END CERTIFICATE-----");

    if (begin == std::string::npos || end == std::string::npos) {
        return result;
    }

    // Извлекаем base64 часть
    size_t data_start = begin + std::strlen("-----BEGIN CERTIFICATE-----");
    std::string b64 = pem_data.substr(data_start, end - data_start);

    // Упрощённая декодировка base64 (полная через OpenSSL)
    // TODO: реализовать полное декодирование
    for (char c : b64) {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t') {
            result.push_back(static_cast<uint8_t>(c));
        }
    }

    return result;
}

std::string DerToPem(const std::vector<uint8_t>& der_data) {
    if (der_data.empty()) {
        return "";
    }

    // Упрощённая конвертация (полная через OpenSSL)
    std::stringstream ss;
    ss << "-----BEGIN CERTIFICATE-----\n";
    for (size_t i = 0; i < der_data.size(); i += 64) {
        size_t len = std::min<size_t>(64, der_data.size() - i);
        ss << std::string(reinterpret_cast<const char*>(der_data.data() + i), len) << "\n";
    }
    ss << "-----END CERTIFICATE-----\n";
    return ss.str();
}

bool IsCertificateValid(const CertificateInfo& cert, int64_t now_ms) {
    if (now_ms == 0) {
        now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    // Проверяем срок действия
    if (cert.not_before_ms > 0 && now_ms < cert.not_before_ms) {
        return false;  // Ещё не начал действовать
    }
    if (cert.not_after_ms > 0 && now_ms > cert.not_after_ms) {
        return false;  // Истёк
    }

    return true;
}

} // namespace pkcs11
} // namespace securevault