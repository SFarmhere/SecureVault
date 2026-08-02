// ============================================================================
// SecureVault - Модульные тесты для TokenDetector
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Назначение: Проверка корректности определения типа токена по пути
//             к PKCS#11 библиотеке.
//
// Входные данные:
//   - Пути к библиотекам различных производителей (Windows/Linux/macOS)
//   - Пустые и некорректные пути
//
// Выходные данные:
//   - Результаты тестов в стандартный вывод (Google Test)
//   - PASS/FAIL для каждого тест-кейса
//
// Зависимости:
//   - Google Test (из native/shared/libs/gtest/)
//   - token_detector.cpp
// ============================================================================

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "../include/token_types.h"
#include "../src/token_detection/token_detector.h"

using namespace securevault::pkcs11;

// ============================================================================
// ТЕСТ: ДЕТЕКЦИЯ РУТОКЕН
// ============================================================================

/**
 * @test TokenDetector.RutokenPaths
 *
 * Входные данные:
 *   - Стандартные пути библиотек Рутокен для разных ОС
 *
 * Ожидаемый результат:
 *   - Все пути определяются как TokenType::RUTOKEN
 */
TEST(TokenDetectorTest, RutokenPaths) {
    std::vector<std::string> paths = {
        "C:\\Windows\\System32\\rtpkcs11ecp.dll",
        "/usr/lib/librtpkcs11ecp.so",
        "/Library/Application Support/Aktiv Co/rtpkcs11ecp.dylib",
        "/usr/lib/librtpkcs11.so",
        "C:\\Program Files\\Aktiv Co\\Rutoken\\rtpkcs11ecp.dll"
    };

    for (const auto& path : paths) {
        EXPECT_EQ(TokenDetector::Detect(path), TokenType::RUTOKEN)
            << "Path: " << path;
    }
}

// ============================================================================
// ТЕСТ: ДЕТЕКЦИЯ ETOKEN
// ============================================================================

/**
 * @test TokenDetector.ETokenPaths
 *
 * Входные данные:
 *   - Стандартные пути библиотек eToken (SafeNet/Aladdin)
 *
 * Ожидаемый результат:
 *   - Все пути определяются как TokenType::ETOKEN
 */
TEST(TokenDetectorTest, ETokenPaths) {
    std::vector<std::string> paths = {
        "C:\\Windows\\System32\\asepkcs.dll",
        "/usr/lib/asepkcs.so",
        "/Library/Frameworks/eToken.framework/Versions/Current/libeToken.dylib",
        "C:\\Program Files\\SafeNet\\eToken\\asepkcs.dll"
    };

    for (const auto& path : paths) {
        EXPECT_EQ(TokenDetector::Detect(path), TokenType::ETOKEN)
            << "Path: " << path;
    }
}

// ============================================================================
// ТЕСТ: ДЕТЕКЦИЯ YUBIKEY
// ============================================================================

/**
 * @test TokenDetector.YubiKeyPaths
 *
 * Входные данные:
 *   - Стандартные пути библиотек YubiKey
 *
 * Ожидаемый результат:
 *   - Все пути определяются как TokenType::YUBIKEY
 */
TEST(TokenDetectorTest, YubiKeyPaths) {
    std::vector<std::string> paths = {
        "C:\\Windows\\System32\\ykcs11.dll",
        "/usr/local/lib/libykcs11.so",
        "/usr/local/lib/libykcs11.dylib",
        "/usr/lib/libykcs11.so"
    };

    for (const auto& path : paths) {
        EXPECT_EQ(TokenDetector::Detect(path), TokenType::YUBIKEY)
            << "Path: " << path;
    }
}

// ============================================================================
// ТЕСТ: ДЕТЕКЦИЯ JACARTA
// ============================================================================

/**
 * @test TokenDetector.JaCartaPaths
 *
 * Входные данные:
 *   - Стандартные пути библиотек JaCarta (Aliot)
 *
 * Ожидаемый результат:
 *   - Все пути определяются как TokenType::JA_CARTA
 */
TEST(TokenDetectorTest, JaCartaPaths) {
    std::vector<std::string> paths = {
        "C:\\Windows\\System32\\jacpkcs.dll",
        "/usr/lib/libjacpkcs.so",
        "C:\\Program Files\\Aliot\\JaCarta\\jacpkcs.dll"
    };

    for (const auto& path : paths) {
        EXPECT_EQ(TokenDetector::Detect(path), TokenType::JA_CARTA)
            << "Path: " << path;
    }
}

// ============================================================================
// ТЕСТ: ДЕТЕКЦИЯ GENERIC PKCS#11
// ============================================================================

/**
 * @test TokenDetector.GenericPkcs11
 *
 * Входные данные:
 *   - Пути к общим PKCS#11 библиотекам (OpenSC)
 *
 * Ожидаемый результат:
 *   - Пути определяются как TokenType::GENERIC_PKCS11
 */
TEST(TokenDetectorTest, GenericPkcs11) {
    std::vector<std::string> paths = {
        "/usr/lib/opensc-pkcs11.so",
        "C:\\Windows\\System32\\opensc-pkcs11.dll"
    };

    for (const auto& path : paths) {
        EXPECT_EQ(TokenDetector::Detect(path), TokenType::GENERIC_PKCS11)
            << "Path: " << path;
    }
}

// ============================================================================
// ТЕСТ: ПУСТОЙ ПУТЬ
// ============================================================================

/**
 * @test TokenDetector.EmptyPath
 *
 * Входные данные:
 *   - Пустая строка
 *
 * Ожидаемый результат:
 *   - Возвращается TokenType::UNKNOWN
 */
TEST(TokenDetectorTest, EmptyPath) {
    EXPECT_EQ(TokenDetector::Detect(""), TokenType::UNKNOWN);
}

// ============================================================================
// ТЕСТ: НЕКОРРЕКТНЫЙ ПУТЬ
// ============================================================================

/**
 * @test TokenDetector.InvalidPath
 *
 * Входные данные:
 *   - Путь к не-PKCS#11 файлу
 *
 * Ожидаемый результат:
 *   - Возвращается TokenType::UNKNOWN
 */
TEST(TokenDetectorTest, InvalidPath) {
    EXPECT_EQ(TokenDetector::Detect("C:\\Windows\\System32\\notepad.exe"), TokenType::UNKNOWN);
    EXPECT_EQ(TokenDetector::Detect("/usr/bin/ls"), TokenType::UNKNOWN);
}

// ============================================================================
// ТЕСТ: РАСШИРЕННАЯ ДЕТЕКЦИЯ
// ============================================================================

/**
 * @test TokenDetector.DetailedDetection
 *
 * Входные данные:
 *   - Путь к библиотеке Рутокен
 *
 * Ожидаемый результат:
 *   - Тип = RUTOKEN
 *   - Производитель = AKTIV
 *   - Уверенность > 0
 *   - Причина не пустая
 */
TEST(TokenDetectorTest, DetailedDetection) {
    DetectionResult result = TokenDetector::DetectDetailed(
        "C:\\Windows\\System32\\rtpkcs11ecp.dll");

    EXPECT_EQ(result.type, TokenType::RUTOKEN);
    EXPECT_EQ(result.manufacturer, TokenManufacturer::AKTIV);
    EXPECT_GT(result.confidence, 0);
    EXPECT_FALSE(result.reason.empty());
    EXPECT_FALSE(result.library_path.empty());
}

// ============================================================================
// ТЕСТ: ПРОВЕРКА РАСШИРЕНИЯ БИБЛИОТЕКИ
// ============================================================================

/**
 * @test TokenDetector.IsLikelyPkcs11Library
 *
 * Входные данные:
 *   - Различные пути с разными расширениями
 *
 * Ожидаемый результат:
 *   - .dll/.so/.dylib возвращают true
 *   - .exe/.txt возвращают false
 */
TEST(TokenDetectorTest, IsLikelyPkcs11Library) {
    EXPECT_TRUE(TokenDetector::IsLikelyPkcs11Library("C:\\lib\\test.dll"));
    EXPECT_TRUE(TokenDetector::IsLikelyPkcs11Library("/usr/lib/test.so"));
    EXPECT_TRUE(TokenDetector::IsLikelyPkcs11Library("/usr/lib/test.dylib"));

    EXPECT_FALSE(TokenDetector::IsLikelyPkcs11Library("C:\\test.exe"));
    EXPECT_FALSE(TokenDetector::IsLikelyPkcs11Library("/usr/bin/test"));
    EXPECT_FALSE(TokenDetector::IsLikelyPkcs11Library(""));
}

// ============================================================================
// ТЕСТ: НОРМАЛИЗАЦИЯ ПУТИ
// ============================================================================

/**
 * @test TokenDetector.NormalizePath
 *
 * Входные данные:
 *   - Путь с заглавными буквами и обратными слешами
 *
 * Ожидаемый результат:
 *   - Путь приводится к lowercase
 *   - Обратные слеши заменяются на прямые
 */
TEST(TokenDetectorTest, NormalizePath) {
    std::string normalized = TokenDetector::NormalizePath(
        "C:\\Windows\\System32\\RTPKCS11ECP.DLL");

    EXPECT_EQ(normalized, "c:/windows/system32/rtpkcs11ecp.dll");
}

// ============================================================================
// ТЕСТ: СТАНДАРТНЫЕ ПУТИ
// ============================================================================

/**
 * @test TokenDetector.GetStandardPaths
 *
 * Входные данные:
 *   - Тип токена RUTOKEN
 *
 * Ожидаемый результат:
 *   - Возвращается непустой список путей
 *   - Первый путь - primary
 */
TEST(TokenDetectorTest, GetStandardPaths) {
    auto paths = TokenDetector::GetStandardPaths(TokenType::RUTOKEN);
    EXPECT_FALSE(paths.empty());
}

// ============================================================================
// ТЕСТ: ПУТЬ ПО УМОЛЧАНИЮ
// ============================================================================

/**
 * @test TokenDetector.GetDefaultPath
 *
 * Входные данные:
 *   - Тип токена RUTOKEN
 *
 * Ожидаемый результат:
 *   - Возвращается непустой путь
 */
TEST(TokenDetectorTest, GetDefaultPath) {
    std::string path = TokenDetector::GetDefaultPath(TokenType::RUTOKEN);
    EXPECT_FALSE(path.empty());
}

// ============================================================================
// ТЕСТ: ДЕТЕКЦИЯ ПО ИМЕНИ ФАЙЛА
// ============================================================================

/**
 * @test TokenDetector.DetectByFilename
 *
 * Входные данные:
 *   - Путь, где имя файла содержит известный паттерн
 *
 * Ожидаемый результат:
 *   - Тип определяется корректно
 */
TEST(TokenDetectorTest, DetectByFilename) {
    // Имя файла содержит "rutoken" даже без полного пути
    EXPECT_EQ(TokenDetector::Detect("rutoken_pkcs11.dll"), TokenType::RUTOKEN);
    EXPECT_EQ(TokenDetector::Detect("libykcs11.so"), TokenType::YUBIKEY);
}

// ============================================================================
// MAIN ДЛЯ ЗАПУСКА ТЕСТОВ
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}