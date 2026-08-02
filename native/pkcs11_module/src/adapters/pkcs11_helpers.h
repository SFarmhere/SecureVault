// ============================================================================
// SecureVault - Header-only вспомогательные утилиты для PKCS#11
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Header-only набор утилит для работы с PKCS#11 токенами:
//   - Безопасная конвертация byte <-> hex (с валидацией)
//   - Анти-форензик затирание памяти
//   - Человеко-читаемые имена токенов (Ru/En)
//   - Все функции inline - нулевой оверхед
// ============================================================================

#ifndef SECUREVAULT_PKCS11_HELPERS_H
#define SECUREVAULT_PKCS11_HELPERS_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <cctype>
#include <stdexcept>
#include <algorithm>

#include "../../include/token_types.h"

namespace securevault {
namespace pkcs11 {
namespace helpers {

// ============================================================================
// HEX КОНВЕРТАЦИЯ
// ============================================================================

/**
 * @brief Конвертировать байт в hex символ (constexpr, C++20)
 */
constexpr uint8_t HexCharToByte(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    return 0xFF; // невалидный символ
}

/**
 * @brief Проверить, является ли строка валидной hex-строкой
 * @param str Строка для проверки
 * @param require_even Если true, проверяет что длина четная
 * @return true если строка валидна
 */
inline bool IsValidHexString(const std::string& str, bool require_even = true) {
    if (str.empty()) return false;
    if (require_even && (str.length() % 2 != 0)) return false;

    return std::all_of(str.begin(), str.end(), [](char c) {
        return std::isxdigit(static_cast<unsigned char>(c)) != 0;
    });
}

/**
 * @brief Конвертировать vector<uint8_t> в hex строку (uppercase)
 * @param bytes Бинарные данные
 * @return Hex строка (например, "DEADBEEF")
 */
inline std::string BytesToHex(const std::vector<uint8_t>& bytes) {
    static const char hex_digits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        result.push_back(hex_digits[b >> 4]);
        result.push_back(hex_digits[b & 0x0F]);
    }
    return result;
}

/**
 * @brief Конвертировать hex строку в vector<uint8_t>
 * @param hex Hex-строка (должна быть четной длины)
 * @return Бинарные данные или пустой vector при ошибке
 */
inline std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;

    if (hex.empty() || hex.length() % 2 != 0) {
        return bytes;
    }

    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t high = HexCharToByte(hex[i]);
        uint8_t low = HexCharToByte(hex[i + 1]);

        if (high == 0xFF || low == 0xFF) {
            bytes.clear();
            return bytes;
        }

        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }

    return bytes;
}

/**
 * @brief Безопасная версия HexToBytes с bool-статусом
 * @param hex Hex-строка
 * @param bytes [out] Бинарные данные
 * @return true если успешно, false при ошибке
 */
inline bool HexToBytesSafe(const std::string& hex, std::vector<uint8_t>& bytes) {
    bytes = HexToBytes(hex);
    return !bytes.empty();
}

/**
 * @brief Compile-time конвертация hex в bytes (C++17)
 */
template<size_t N>
constexpr std::array<uint8_t, N / 2> HexToBytesConstexpr(const char (&hex)[N]) {
    std::array<uint8_t, N / 2> result{};
    for (size_t i = 0; i < N - 1; i += 2) {
        uint8_t high = HexCharToByte(hex[i]);
        uint8_t low = HexCharToByte(hex[i + 1]);
        result[i / 2] = static_cast<uint8_t>((high << 4) | low);
    }
    return result;
}

// ============================================================================
// БЕЗОПАСНОЕ ЗАТИРАНИЕ ПАМЯТИ
// ============================================================================

/**
 * @brief Безопасно затереть память (анти-оптимизация компилятора)
 * @param ptr Указатель на память
 * @param size Размер в байтах
 */
inline void SecureZeroMemory(volatile uint8_t* ptr, size_t size) {
    if (ptr == nullptr || size == 0) return;
    for (size_t i = 0; i < size; ++i) {
        ptr[i] = 0;
    }
}

/**
 * @brief Перегрузка для сырых указателей
 */
inline void SecureZeroMemory(void* ptr, size_t size) {
    SecureZeroMemory(static_cast<volatile uint8_t*>(ptr), size);
}

/**
 * @brief Перегрузка для std::vector<uint8_t>
 */
inline void SecureZeroMemory(std::vector<uint8_t>& vec) {
    if (vec.empty()) return;
    SecureZeroMemory(vec.data(), vec.size());
    vec.clear();
}

// ============================================================================
// ЛОКАЛИЗОВАННЫЕ ИМЕНА ТОКЕНОВ
// ============================================================================

/**
 * @brief Получить строковое имя типа токена (русский)
 */
inline std::string TokenTypeToStringRu(TokenType type) {
    switch (type) {
        case TokenType::RUTOKEN:        return "Рутокен";
        case TokenType::ETOKEN:         return "eToken";
        case TokenType::JA_CARTA:       return "JaCarta";
        case TokenType::YUBIKEY:        return "YubiKey";
        case TokenType::SOLOKEY:        return "SoloKey";
        case TokenType::NITROKEY:       return "Nitrokey";
        case TokenType::GENERIC_PKCS11: return "PKCS#11 (универсальный)";
        case TokenType::PCSC_SMARTCARD: return "Смарт-карта (PC/SC)";
        default:                        return "Неизвестный токен";
    }
}

/**
 * @brief Получить строковое имя типа токена (английский)
 */
inline std::string TokenTypeToStringEn(TokenType type) {
    switch (type) {
        case TokenType::RUTOKEN:        return "Rutoken";
        case TokenType::ETOKEN:         return "eToken";
        case TokenType::JA_CARTA:       return "JaCarta";
        case TokenType::YUBIKEY:        return "YubiKey";
        case TokenType::SOLOKEY:        return "SoloKey";
        case TokenType::NITROKEY:       return "Nitrokey";
        case TokenType::GENERIC_PKCS11: return "Generic PKCS#11";
        case TokenType::PCSC_SMARTCARD: return "Smart Card (PC/SC)";
        default:                        return "Unknown token";
    }
}

/**
 * @brief Получить строковое имя типа токена (по умолчанию английский)
 */
inline std::string TokenTypeToString(TokenType type) {
    return TokenTypeToStringEn(type);
}

} // namespace helpers
} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_HELPERS_H