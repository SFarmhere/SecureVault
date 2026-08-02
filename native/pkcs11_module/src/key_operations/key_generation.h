// ============================================================================
// SecureVault - Заголовочный файл генерации ключей
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Объявление функций генерации ключевых пар на аппаратных токенах.
//   Реализация находится в key_generation.cpp.
//
// СВЯЗЬ С ДРУГИМИ МОДУЛЯМИ:
//   - ITokenModule::GenerateRsaKeyPair() - низкоуровневая генерация
//   - SessionManager - управление сессиями для операций
//   - Python bindings - высокоуровневый доступ
// ============================================================================

#ifndef SECUREVAULT_PKCS11_KEY_GENERATION_H
#define SECUREVAULT_PKCS11_KEY_GENERATION_H

#include <string>
#include <vector>
#include <memory>

#include "../../include/pkcs11_api.h"
#include "../../include/session_types.h"
#include "../../include/token_types.h"

namespace securevault {
namespace pkcs11 {

// ============================================================================
// РЕЗУЛЬТАТ ГЕНЕРАЦИИ КЛЮЧА
// ============================================================================

/**
 * @brief Результат генерации ключевой пары
 */
struct KeyGenerationResult {
    TokenResult result{TokenResult::ERR_GENERAL}; ///< Результат операции
    std::string key_id;                           ///< ID сгенерированного ключа (hex)
    std::string public_key_pem;                   ///< Публичный ключ в PEM-формате
    KeyType key_type{KeyType::UNKNOWN};           ///< Тип ключа
    KeySizeBits size_bits{0};                     ///< Размер ключа в битах
    bool on_token{false};                         ///< Ключ хранится на токене
};

// ============================================================================
// ФУНКЦИИ ГЕНЕРАЦИИ КЛЮЧЕЙ
// ============================================================================

/**
 * @brief Сгенерировать пару ключей RSA на токене
 * @param module Модуль токена (ITokenModule)
 * @param session_id ID сессии
 * @param params Параметры генерации RSA
 * @return Результат генерации
 *
 * Приватный ключ генерируется и остаётся на токене.
 * Публичный ключ возвращается в PEM-формате.
 */
KeyGenerationResult GenerateRsaKeyPair(ITokenModule& module,
                                       SessionId session_id,
                                       const RsaKeyParams& params);

/**
 * @brief Сгенерировать пару ключей RSA с автоматическим выбором размера
 * @param module Модуль токена
 * @param session_id ID сессии
 * @param label Метка ключа
 * @param bits Размер ключа (2048 или 4096)
 * @return Результат генерации
 *
 * Удобная обёртка над GenerateRsaKeyPair с параметрами по умолчанию.
 */
KeyGenerationResult GenerateRsaKeyPairDefault(ITokenModule& module,
                                              SessionId session_id,
                                              const std::string& label,
                                              KeySizeBits bits = 2048);

/**
 * @brief Проверить, поддерживает ли токен генерацию RSA
 * @param module Модуль токена
 * @param session_id ID сессии
 * @param bits Запрашиваемый размер ключа
 * @return true если поддерживается
 */
bool IsRsaKeyGenerationSupported(ITokenModule& module,
                                 SessionId session_id,
                                 KeySizeBits bits);

} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_KEY_GENERATION_H