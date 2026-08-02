// ============================================================================
// SecureVault - Импорт сертификатов на токены
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Реализует функции импорта X.509 сертификатов на аппаратные токены,
// используя низкоуровневый ITokenModule.
// ============================================================================

#include "certificate_ops.h"

#include <fstream>
#include <string>
#include <vector>

namespace securevault {
namespace pkcs11 {

TokenResult ImportCertificate(ITokenModule& module,
                              SessionId session_id,
                              const std::vector<uint8_t>& cert_data,
                              const std::string& label,
                              const std::string& key_id) {
    if (!module.IsInitialized() || cert_data.empty()) {
        return TokenResult::ERR_NOT_INITIALIZED;
    }
    return module.ImportCertificate(session_id, cert_data, label, key_id);
}

TokenResult ImportCertificateFromFile(ITokenModule& module,
                                      SessionId session_id,
                                      const std::string& pem_path,
                                      const std::string& label) {
    if (!module.IsInitialized() || pem_path.empty()) {
        return TokenResult::ERR_NOT_INITIALIZED;
    }

    // Читаем файл
    std::ifstream file(pem_path, std::ios::binary);
    if (!file.is_open()) {
        return TokenResult::ERR_GENERAL;
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
    file.close();

    if (data.empty()) {
        return TokenResult::ERR_GENERAL;
    }

    return module.ImportCertificate(session_id, data, label);
}

} // namespace pkcs11
} // namespace securevault