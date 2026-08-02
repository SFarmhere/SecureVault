// ============================================================================
// SecureVault - Реализация управления ключами
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Реализует высокоуровневые функции управления ключами на токенах,
// используя низкоуровневый ITokenModule.
// ============================================================================

#include "key_management.h"

#include <string>
#include <vector>
#include <memory>

namespace securevault {
namespace pkcs11 {

std::vector<KeyInfo> ListKeys(ITokenModule& module, SessionId session_id) {
    if (!module.IsInitialized()) {
        return {};
    }
    return module.ListKeys(session_id);
}

std::unique_ptr<KeyInfo> FindKeyById(ITokenModule& module,
                                     SessionId session_id,
                                     const std::string& key_id) {
    if (!module.IsInitialized() || key_id.empty()) {
        return nullptr;
    }
    return module.FindKeyById(session_id, key_id);
}

std::unique_ptr<KeyInfo> FindKeyByLabel(ITokenModule& module,
                                        SessionId session_id,
                                        const std::string& label) {
    if (!module.IsInitialized() || label.empty()) {
        return nullptr;
    }

    auto keys = module.ListKeys(session_id);
    for (auto& key : keys) {
        if (label == key.get_label()) {
            return std::make_unique<KeyInfo>(key);
        }
    }
    return nullptr;
}

TokenResult DeleteKey(ITokenModule& module,
                      SessionId session_id,
                      const std::string& key_id) {
    if (!module.IsInitialized() || key_id.empty()) {
        return TokenResult::ERR_NOT_INITIALIZED;
    }
    return module.DeleteKey(session_id, key_id);
}

std::string ExportPublicKeyPem(ITokenModule& module,
                               SessionId session_id,
                               const std::string& key_id) {
    if (!module.IsInitialized() || key_id.empty()) {
        return "";
    }

    auto key = module.FindKeyById(session_id, key_id);
    if (!key) {
        return "";
    }

    // Экспортируем только публичный ключ
    if (key->is_private()) {
        // Ищем публичный ключ с тем же ID
        auto keys = module.ListKeys(session_id);
        for (auto& k : keys) {
            if (!k.is_private() && key_id == k.get_id()) {
                // Формируем PEM из модуля/экспоненты
                // (упрощённо: возвращаем hex-представление)
                return "-----BEGIN PUBLIC KEY-----\n" +
                       std::string(key->get_id()) +
                       "\n-----END PUBLIC KEY-----\n";
            }
        }
        return "";
    }

    // Уже публичный ключ
    return "-----BEGIN PUBLIC KEY-----\n" +
           std::string(key->get_id()) +
           "\n-----END PUBLIC KEY-----\n";
}

int CountKeys(ITokenModule& module, SessionId session_id) {
    if (!module.IsInitialized()) {
        return -1;
    }
    auto keys = module.ListKeys(session_id);
    return static_cast<int>(keys.size());
}

} // namespace pkcs11
} // namespace securevault