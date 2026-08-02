// ============================================================================
// SecureVault - Реализация детектора типов аппаратных токенов
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Определяет тип токена по пути к PKCS#11 библиотеке, предоставляет
// стандартные пути библиотек для Windows/Linux/macOS.
// ============================================================================

#include "token_detector.h"

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <string>
#include <vector>

#ifdef _WIN32
    #include <windows.h>
#endif

namespace securevault {
namespace pkcs11 {

// ============================================================================
// ВНУТРЕННИЕ КОНСТАНТЫ
// ============================================================================

namespace {

// Расширения динамических библиотек
const std::vector<std::string>& LibraryExtensions() {
    static const std::vector<std::string> extensions = {
        ".dll", ".so", ".dylib"
    };
    return extensions;
}

// Подстроки путей для матчинга (lowercase)
const std::vector<LibraryPathEntry>& KnownPaths() {
    static const std::vector<LibraryPathEntry> paths = {
        // Рутокен (Aktiv Co.)
        {TokenType::RUTOKEN, "rtpkcs11ecp", "all", true},
        {TokenType::RUTOKEN, "rtpkcs11", "all", true},
        {TokenType::RUTOKEN, "rutoken", "all", true},
        {TokenType::RUTOKEN, "aktiv", "all", false},

        // eToken (SafeNet/Aladdin)
        {TokenType::ETOKEN, "asepkcs", "all", true},
        {TokenType::ETOKEN, "aladdin", "all", false},
        {TokenType::ETOKEN, "etoken", "all", false},
        {TokenType::ETOKEN, "safenet", "all", false},

        // JaCarta (Aliot)
        {TokenType::JA_CARTA, "jacarta", "all", true},
        {TokenType::JA_CARTA, "jacpkcs", "all", true},
        {TokenType::JA_CARTA, "aliot", "all", false},

        // YubiKey (Yubico)
        {TokenType::YUBIKEY, "yubico", "all", true},
        {TokenType::YUBIKEY, "yubikey", "all", true},
        {TokenType::YUBIKEY, "libykcs11", "all", true},

        // SoloKey
        {TokenType::SOLOKEY, "solokey", "all", true},
        {TokenType::SOLOKEY, "solo", "all", false},

        // Nitrokey
        {TokenType::NITROKEY, "nitrokey", "all", true},
        {TokenType::NITROKEY, "nitro", "all", false},

        // PKCS#11 общие (OpenSC, PC/SC)
        {TokenType::GENERIC_PKCS11, "opensc-pkcs11", "all", true},
        {TokenType::GENERIC_PKCS11, "libp11", "all", false},
        {TokenType::GENERIC_PKCS11, "pkcs11", "all", false},

        // Smartcard / PC/SC
        {TokenType::PCSC_SMARTCARD, "pcsclite", "linux", true},
        {TokenType::PCSC_SMARTCARD, "winscard", "windows", true},
        {TokenType::PCSC_SMARTCARD, "pcsc", "all", false},
    };
    return paths;
}

// Производители по типу
TokenManufacturer ManufacturerForType(TokenType type) {
    switch (type) {
        case TokenType::RUTOKEN:  return TokenManufacturer::AKTIV;
        case TokenType::ETOKEN:   return TokenManufacturer::SAFENET;
        case TokenType::JA_CARTA: return TokenManufacturer::ALIOT;
        case TokenType::YUBIKEY:  return TokenManufacturer::YUBICO;
        case TokenType::SOLOKEY:  return TokenManufacturer::SOLOKEYS;
        case TokenType::NITROKEY: return TokenManufacturer::NITROKEY;
        default:                  return TokenManufacturer::OTHER;
    }
}

} // namespace

// ============================================================================
// РЕАЛИЗАЦИЯ TokenDetector
// ============================================================================

TokenType TokenDetector::Detect(const std::string& library_path) {
    if (library_path.empty()) {
        return TokenType::UNKNOWN;
    }

    // Проверка по подстрокам (сначала основные, затем fallback)
    TokenType type = DetectBySubstring(library_path);
    if (type != TokenType::UNKNOWN) {
        return type;
    }

    // Эвристика по имени файла
    type = DetectByFilename(library_path);
    if (type != TokenType::UNKNOWN) {
        return type;
    }

    return TokenType::UNKNOWN;
}

DetectionResult TokenDetector::DetectDetailed(const std::string& library_path) {
    DetectionResult result;
    if (library_path.empty()) {
        result.type = TokenType::UNKNOWN;
        result.reason = "empty path";
        return result;
    }

    if (!IsLikelyPkcs11Library(library_path)) {
        result.type = TokenType::UNKNOWN;
        result.reason = "not a PKCS#11 library extension";
        result.library_path = NormalizePath(library_path);
        return result;
    }

    result.library_path = NormalizePath(library_path);

    // Основной путь (в таблице KnownPaths)
    const auto& paths = KnownPaths();

    for (const auto& entry : paths) {
        if (result.library_path.find(entry.pattern) != std::string::npos) {
            result.type = entry.type;
            result.manufacturer = ManufacturerForType(entry.type);
            result.is_primary_path = entry.is_primary;
            result.confidence = entry.is_primary ? 95 : 70;
            result.reason = entry.is_primary
                ? "known primary library path"
                : "known fallback library path";
            return result;
        }
    }

    // Дополнительная эвристика по имени файла (без пути)
    std::filesystem::path fs_path(library_path);
    std::string filename = fs_path.filename().string();
    std::transform(filename.begin(), filename.end(), filename.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (const auto& entry : paths) {
        if (filename.find(entry.pattern) != std::string::npos) {
            result.type = entry.type;
            result.manufacturer = ManufacturerForType(entry.type);
            result.is_primary_path = entry.is_primary;
            result.confidence = entry.is_primary ? 85 : 60;
            result.reason = "matched filename pattern";
            return result;
        }
    }

    // Неизвестная, но валидная PKCS#11 библиотека
    result.type = TokenType::GENERIC_PKCS11;
    result.manufacturer = TokenManufacturer::OTHER;
    result.confidence = 30;
    result.reason = "generic PKCS#11 library (no known vendor match)";
    return result;
}

std::vector<LibraryPathEntry> TokenDetector::GetKnownLibraryPaths() {
    return KnownPaths();
}

std::vector<std::string> TokenDetector::GetStandardPaths(TokenType type) {
    std::vector<std::string> primary;
    std::vector<std::string> fallback;

    const auto& paths = KnownPaths();
    for (const auto& entry : paths) {
        if (entry.type != type) continue;
        (entry.is_primary ? primary : fallback).push_back(entry.pattern);
    }

    // Возвращаем primary, затем fallback (без дубликатов - паттерны уникальны)
    std::vector<std::string> result = primary;
    result.insert(result.end(), fallback.begin(), fallback.end());
    return result;
}

std::string TokenDetector::GetDefaultPath(TokenType type) {
    const auto& paths = KnownPaths();

    for (const auto& entry : paths) {
        if (entry.type == type && entry.is_primary && entry.platform == "all") {
            // Возвращаем известные конкретные стандартные пути
            switch (type) {
                case TokenType::RUTOKEN:
#ifdef _WIN32
                    return "C:\\Windows\\System32\\rtpkcs11ecp.dll";
#elif defined(__APPLE__)
                    return "/Library/Application Support/Aktiv Co/rtpkcs11ecp.dylib";
#else
                    return "/usr/lib/librtpkcs11ecp.so";
#endif
                case TokenType::ETOKEN:
#ifdef _WIN32
                    return "C:\\Windows\\System32\\asepkcs.dll";
#elif defined(__APPLE__)
                    return "/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib";
#else
                    return "/usr/lib/asepkcs.so";
#endif
                case TokenType::JA_CARTA:
#ifdef _WIN32
                    return "C:\\Windows\\System32\\jacpkcs.dll";
#else
                    return "/usr/lib/libjacpkcs.so";
#endif
                case TokenType::YUBIKEY:
#ifdef _WIN32
                    return "C:\\Windows\\System32\\ykcs11.dll";
#elif defined(__APPLE__)
                    return "/usr/local/lib/libykcs11.dylib";
#else
                    return "/usr/local/lib/libykcs11.so";
#endif
                case TokenType::SOLOKEY:
                    return "solokey-pkcs11.dll"; // упрощённо
                case TokenType::NITROKEY:
                    return "nitrokey-pkcs11.dll"; // упрощённо
                case TokenType::GENERIC_PKCS11:
#ifdef _WIN32
                    return "opensc-pkcs11.dll";
#else
                    return "/usr/lib/opensc-pkcs11.so";
#endif
                default:
                    return "";
            }
        }
    }

    return "";
}

bool TokenDetector::IsLikelyPkcs11Library(const std::string& path) {
    if (path.empty()) return false;

    // Игнорируем если это не файл (каталог, некорректный путь)
    std::filesystem::path fs_path(path);
    // Не проверяем существование (пути могут указывать на ещё не установленные библиотеки)

    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    for (const auto& ext : LibraryExtensions()) {
        if (lower.size() >= ext.size() &&
            lower.compare(lower.size() - ext.size(), ext.size(), ext) == 0) {
            return true;
        }
    }

    // Допускаем именованные библиотеки без расширения (редкое, но бывает)
    if (lower.find("pkcs11") != std::string::npos ||
        lower.find("p11") != std::string::npos) {
        return lower.find('/') != std::string::npos ||
               lower.find('\\') != std::string::npos;
    }

    return false;
}

std::string TokenDetector::NormalizePath(const std::string& path) {
    std::string normalized = path;

    // Приводим к lowercase для сравнения
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Нормализуем разделители (Windows -> '/')
#ifdef _WIN32
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
#else
    // На Unix оставляем как есть (но системные пути могут содержать и те и другие)
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
#endif

    return normalized;
}

TokenType TokenDetector::DetectBySubstring(const std::string& normalized) {
    const auto& paths = KnownPaths();

    for (const auto& entry : paths) {
        if (normalized.find(entry.pattern) != std::string::npos) {
            return entry.type;
        }
    }

    return TokenType::UNKNOWN;
}

TokenType TokenDetector::DetectByFilename(const std::string& library_path) {
    std::filesystem::path fs_path(library_path);
    std::string filename = fs_path.filename().string();

    if (filename.empty()) {
        return TokenType::UNKNOWN;
    }

    std::transform(filename.begin(), filename.end(), filename.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Проверка по базовому имени (без расширения)
    for (const auto& entry : KnownPaths()) {
        if (filename.find(entry.pattern) != std::string::npos) {
            return entry.type;
        }
    }

    return TokenType::UNKNOWN;
}

TokenManufacturer TokenDetector::GetManufacturerForType(TokenType type) {
    return ManufacturerForType(type);
}

} // namespace pkcs11
} // namespace securevault