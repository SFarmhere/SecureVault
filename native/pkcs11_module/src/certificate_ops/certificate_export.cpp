// ============================================================================
// SecureVault - Экспорт сертификатов с токенов
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Реализует функции экспорта X.509 сертификатов с аппаратных токенов,
// используя низкоуровневый ITokenModule.
// ============================================================================

#include "certificate_ops.h"

#include <fstream>
#include <string>
#include <vector>

namespace securevault {
namespace pkcs11 {

std::vector<uint8_t> ExportCertificate(ITokenModule& module,
                                       SessionId session_id,
                                       const std::string& cert_id,
                                       const std::string& format) {
    if (!module.IsInitialized() || cert_id.empty()) {
        return {};
    }
    return module.ExportCertificate(session_id, cert_id, format);
}

bool ExportCertificateToFile(ITokenModule& module,
                             SessionId session_id,
                             const std::string& cert_id,
                             const std::string& output_path,
                             const std::string& format) {
    auto data = ExportCertificate(module, session_id, cert_id, format);
    if (data.empty()) {
        return false;
    }

    std::ofstream file(output_path, std::ios::binary);
    if (!file.is_open()) {
        return false;
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    file.close();
    return true;
}

} // namespace pkcs11
} // namespace securevault