// ============================================================================
// SecureVault - Детектор типов аппаратных токенов
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Определение типа подключаемого токена по пути к PKCS#11 библиотеке.
//   Предоставляет стандартные пути библиотек для каждой ОС и методы
//   расширенной детекции по имени файла, содержимому и хешу.
//
// СВЯЗЬ С ДРУГИМИ МОДУЛЯМИ:
//   - SessionManager::OpenSession() использует определяемый тип для
//     создания правильного ITokenModule через ModuleFactory.
//   - ModuleFactory::Detect() выполняет базовую детекцию по имени в пути;
//     этот модуль добавляет запасные пути, платформенные стандарты и
//     определение по признакам библиотеки.
// ============================================================================

#ifndef SECUREVAULT_PKCS11_TOKEN_DETECTOR_H
#define SECUREVAULT_PKCS11_TOKEN_DETECTOR_H

#include <string>
#include <vector>
#include <utility>
#include "../../include/token_types.h"

namespace securevault {
namespace pkcs11 {

// ============================================================================
// ЗАПИСЬ О СТАНДАРТНОМ ПУТИ БИБЛИОТЕКИ
// ============================================================================

/**
 * @brief Запись о известном пути к PKCS#11 библиотеке
 */
struct LibraryPathEntry {
    TokenType               type;       ///< Тип токена
    std::string             pattern;    ///< Подстрока в пути (lowercase) для матчинга
    std::string             platform;   ///< Платформа: "windows", "linux", "macos", "all"
    bool                    is_primary; ///< true = основной путь, false = запасной
};

// ============================================================================
// ОПИСАНИЕ РЕЗУЛЬТАТА ДЕТЕКЦИИ
// ============================================================================

/**
 * @brief Результат детекции токена
 */
struct DetectionResult {
    TokenType           type{TokenType::UNKNOWN};             ///< Определённый тип
    TokenManufacturer   manufacturer{TokenManufacturer::UNKNOWN}; ///< Производитель (если известен)
    std::string         library_path;                          ///< Канонизированный путь
    int                 confidence{0};                         ///< Уверенность 0..100
    std::string         reason;                                ///< Причина/метод определения
    bool                is_primary_path{false};                ///< Был ли использован основной путь
};

// ============================================================================
// ДЕТЕКТОР ТОКЕНОВ
// ============================================================================

/**
 * @brief Детектор типов аппаратных токенов по PKCS#11 библиотекам
 *
 * Предоставляет статические методы для определения типа токена.
 * Методы thread-safe (не хранят состояние).
 */
class TokenDetector {
public:
    // ------------------------------------------------------------------------
    // БАЗОВАЯ ДЕТЕКЦИЯ
    // ------------------------------------------------------------------------

    /**
     * @brief Определить тип токена по пути к библиотеке
     * @param library_path Путь к PKCS#11 библиотеке (.dll/.so/.dylib)
     * @return Определённый TokenType или UNKNOWN
     *
     * Алгоритм:
     *   1. Если путь пуст — UNKNOWN.
     *   2. Приводим путь к lowercase и ищем известные подстроки
     *      (см. GetKnownLibraryPaths).
     *   3. Если не найдено — пробуем эвристики (имя файла, сосуд-функции).
     */
    static TokenType Detect(const std::string& library_path);

    /**
     * @brief Расширенная детекция с деталями
     * @param library_path Путь к библиотеке
     * @return DetectionResult с типом, уверенностью и причиной
     */
    static DetectionResult DetectDetailed(const std::string& library_path);

    // ------------------------------------------------------------------------
    // СПИСКИ ПУТЕЙ
    // ------------------------------------------------------------------------

    /**
     * @brief Получить все известные пути PKCS#11 библиотек
     * @return Вектор записей (тип, подстрока, платформа, primary)
     */
    static std::vector<LibraryPathEntry> GetKnownLibraryPaths();

    /**
     * @brief Получить стандартные пути для конкретного типа токена
     * @param type Тип токена
     * @return Вектор путей, упорядоченный: primary сначала
     */
    static std::vector<std::string> GetStandardPaths(TokenType type);

    /**
     * @brief Получить стандартный путь для типа токена на текущей ОС
     * @param type Тип токена
     * @return Первый primary путь для текущей платформы, либо пустую строку
     */
    static std::string GetDefaultPath(TokenType type);

    // ------------------------------------------------------------------------
    // УТИЛИТЫ
    // ------------------------------------------------------------------------

    /**
     * @brief Проверить, является ли путь потенциально PKCS#11 библиотекой
     * @param path Путь к файлу
     * @return true если расширение/имя указывает на библиотеку
     *
     * Расширения: .dll, .so, .dylib, .p11 (выборочно).
     */
    static bool IsLikelyPkcs11Library(const std::string& path);

    /**
     * @brief Нормализовать путь (lowercase, заменить назадние слеши)
     * @param path Исходный путь
     * @return Нормализованный путь
     */
    static std::string NormalizePath(const std::string& path);

private:
    // Вспомогательные эвристики
    static TokenType DetectByFilename(const std::string& normalized);
    static TokenType DetectBySubstring(const std::string& normalized);
    static TokenManufacturer GetManufacturerForType(TokenType type);
};

} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_TOKEN_DETECTOR_H