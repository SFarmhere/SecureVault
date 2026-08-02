// ============================================================================
// SecureVault - Реализация генерации ключей
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Реализует высокоуровневые функции генерации ключевых пар,
// используя низкоуровневый ITokenModule::GenerateRsaKeyPair().
// ============================================================================

#include "key_generation.h"
#include "key_management.h"

#include <string>
#include <vector>

namespace securevault {
namespace pkcs11 {

KeyGenerationResult GenerateRsaKeyPair(ITokenModule& module,
                                       SessionId session_id,
                                       const RsaKeyParams& params) {
    KeyGenerationResult result;

    // Проверяем, что модуль инициализирован
    if (!module.IsInitialized()) {
        result.result = TokenResult::ERR_NOT_INITIALIZED;
        return result;
    }

    // Проверяем размер ключа
    if (params.key_size != 2048 && params.key_size != 4096) {
        result.result = TokenResult::ERR_KEY_SIZE;
        return result;
    }

    // Генерируем ключевую пару через модуль
    std::string key_id = module.GenerateRsaKeyPair(session_id, params);
    if (key_id.empty()) {
        result.result = TokenResult::ERR_KEY_TYPE;
        return result;
    }

    // Заполняем результат
    result.result = TokenResult::SUCCESS;
    result.key_id = key_id;
    result.key_type = KeyType::RSA_PRIVATE;
    result.size_bits = params.key_size;
    result.on_token = params.is_token();

    // Пытаемся получить публичный ключ
    auto key_info = module.FindKeyById(session_id, key_id);
    if (key_info) {
        result.public_key_pem = ExportPublicKeyPem(module, session_id, key_id);
    }

    return result;
}

KeyGenerationResult GenerateRsaKeyPairDefault(ITokenModule& module,
                                              SessionId session_id,
                                              const std::string& label,
                                              KeySizeBits bits) {
    RsaKeyParams params(bits);
    params.set_label(label.c_str());
    return GenerateRsaKeyPair(module, session_id, params);
}

bool IsRsaKeyGenerationSupported(ITokenModule& module,
                                 SessionId session_id,
                                 KeySizeBits bits) {
    (void)session_id;

    if (!module.IsInitialized()) {
        return false;
    }

    // Проверяем поддерживаемые размеры
    return bits == 2048 || bits == 4096;
}

} // namespace pkcs11
} // namespace securevault