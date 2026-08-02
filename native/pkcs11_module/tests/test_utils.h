// ============================================================================
// SecureVault - Заголовочный файл тестовых утилит PKCS#11
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Объявление вспомогательных функций, используемых в модульных тестах.
//   Реализация в test_utils.cpp.
// ============================================================================

#ifndef SECUREVAULT_PKCS11_TEST_UTILS_H
#define SECUREVAULT_PKCS11_TEST_UTILS_H

#include <string>
#include <cstdint>
#include <vector>

#include "../include/token_types.h"

namespace securevault {
namespace pkcs11 {
namespace test {

// ============================================================================
// ГЕНЕРАЦИЯ ТЕСТОВЫХ ДАННЫХ
// ============================================================================

/**
 * @brief Сгенерировать случайный hex-идентификатор
 * @param bytes Количество байт (по умолчанию 8 = 16 hex символов)
 * @return Hex строка
 */
std::string GenerateHexId(size_t bytes = 8);

/**
 * @brief Создать тестовый KeyInfo
 * @param id Идентификатор ключа
 * @param label Метка
 * @param type Тип ключа
 * @param bits Размер в битах
 * @return Заполненный KeyInfo
 */
KeyInfo MakeTestKeyInfo(const std::string& id,
                        const std::string& label,
                        KeyType type = KeyType::RSA_PRIVATE,
                        KeySizeBits bits = 2048);

/**
 * @brief Создать тестовый TokenInfo
 * @param type Тип токена
 * @param serial Серийный номер
 * @return Заполненный TokenInfo
 */
TokenInfo MakeTestTokenInfo(TokenType type = TokenType::RUTOKEN,
                            const std::string& serial = "TEST-SERIAL-0001");

/**
 * @brief Создать тестовый CertificateInfo
 * @param id Идентификатор сертификата
 * @param subject Subject DN
 * @param not_before_ms Начало действия (мс)
 * @param not_after_ms Окончание действия (мс)
 * @return Заполненный CertificateInfo
 */
CertificateInfo MakeTestCertificate(const std::string& id,
                                    const std::string& subject = "CN=Test",
                                    int64_t not_before_ms = 0,
                                    int64_t not_after_ms = 0);

// ============================================================================
// ПРОВЕРКА СООТВЕТСТВИЯ
// ============================================================================

/**
 * @brief Сравнить два KeyInfo по полям
 * @return true если ID, label, type, size_bits, flags совпадают
 */
bool IsKeyInfoEqual(const KeyInfo& a, const KeyInfo& b);

/**
 * @brief Сравнить два TokenInfo по полям
 * @return true если type, serial_number, flags совпадают
 */
bool IsTokenInfoEqual(const TokenInfo& a, const TokenInfo& b);

// ============================================================================
// ГЕНЕРАЦИЯ СЛУЧАЙНЫХ ДАННЫХ
// ============================================================================

/**
 * @brief Сгенерировать случайные байты
 * @param size Количество байт
 * @return Вектор случайных байт
 */
std::vector<uint8_t> GenerateRandomBytes(size_t size);

/**
 * @brief Сгенерировать случайную hex-строку
 * @param bytes Количество байт
 * @return Hex строка (длина = bytes * 2)
 */
std::string GenerateRandomHex(size_t bytes);

} // namespace test
} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_TEST_UTILS_H