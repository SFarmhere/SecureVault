// ============================================================================
// SecureVault - PKCS#11 API для работы с аппаратными токенами
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// АРХИТЕКТУРНОЕ РЕШЕНИЕ: C++ ABI
// ============================================================================
// Мы осознанно используем C++ ABI с виртуальными классами и STL-типами,
// поскольку полностью контролируем цепочку сборки:
//   - Один компилятор для C++ модуля и Python extension
//   - Одна версия STL (libstdc++/libc++/MSVC STL)
//   - pybind11 обеспечивает ABI-стабильность на уровне биндингов
//
// НЕ ИСПОЛЬЗОВАТЬ:
//   - extern "C" обертки (не нужны, pybind11 работает напрямую с C++ ABI)
//   - __declspec(dllexport)/__attribute__((visibility("default")))
//   - Прямой экспорт STL символов
//
// ВСЕ ПУБЛИЧНЫЕ ТИПЫ имеют фиксированный размер для ABI-стабильности
// при передаче через границы модулей.
// ============================================================================

#ifndef SECUREVAULT_PKCS11_API_H
#define SECUREVAULT_PKCS11_API_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <algorithm>

// Подключаем типы из специализированных заголовков
#include "session_types.h"
#include "token_types.h"

namespace securevault {
namespace pkcs11 {

// ============================================================================
// Типы SessionId, SlotId, ObjectHandle определены в session_types.h
// Типы KeySizeBits, TokenInfo, KeyInfo, CertificateInfo,
//   KeyType, KeyFlags, TokenFlags, RsaKeyParams, RsaSignParams,
//   RsaEncryptParams определены в token_types.h
//
// В этом файле остаётся:
//   - TokenResult (enum с кодами ошибок)
//   - ITokenModule (абстрактный интерфейс)
//   - Фабричные функции
//   - Вспомогательные утилиты (string_to_buffer, bytes_to_hex и т.д.)
// ============================================================================

// ============================================================================
// РЕЗУЛЬТАТ ОПЕРАЦИИ (32 БИТА, ОТРИЦАТЕЛЬНЫЕ ЗНАЧЕНИЯ = ОШИБКИ)
// ============================================================================

/**
 * @brief Результат операции с токеном
 *
 * Фиксированный 32-битный enum class.
 * Успех = 0, ошибки = отрицательные значения.
 * Можно безопасно передавать через границы ABI и сериализовать.
 */
enum class TokenResult : int32_t {
    // Успех (0)
    SUCCESS = 0,                    ///< Операция выполнена успешно

    // Общие ошибки (-1..-19)
    ERR_GENERAL = -1,              ///< Общая ошибка PKCS#11
    ERR_NOT_INITIALIZED = -2,      ///< Модуль не инициализирован
    ERR_ALREADY_INITIALIZED = -3,  ///< Модуль уже инициализирован
    ERR_INVALID_PARAMETER = -4,    ///< Неверный параметр
    ERR_BUFFER_TOO_SMALL = -5,     ///< Недостаточный размер буфера
    ERR_MEMORY = -6,              ///< Недостаточно памяти
    ERR_TIMEOUT = -7,            ///< Таймаут операции
    ERR_NOT_SUPPORTED = -8,      ///< Операция не поддерживается

    // Ошибки токена (-20..-39)
    ERR_TOKEN_NOT_FOUND = -20,    ///< Токен не найден
    ERR_TOKEN_REMOVED = -21,      ///< Токен извлечен во время операции
    ERR_TOKEN_ERROR = -22,        ///< Ошибка токена

    // Ошибки сессии (-40..-59)
    ERR_SESSION_ERROR = -40,      ///< Общая ошибка сессии
    ERR_SESSION_CLOSED = -41,     ///< Сессия закрыта
    ERR_SESSION_HANDLE_INVALID = -42, ///< Неверный идентификатор сессии

    // Ошибки аутентификации (-60..-79)
    ERR_PIN_INCORRECT = -60,      ///< Неверный PIN-код
    ERR_PIN_LOCKED = -61,         ///< PIN-код заблокирован
    ERR_PIN_EXPIRED = -62,        ///< PIN-код истек
    ERR_PIN_ATTEMPTS = -63,       ///< Превышено число попыток
    ERR_NOT_LOGGED_IN = -64,      ///< Не выполнен вход
    ERR_USER_ANOTHER = -65,       ///< Другой пользователь уже аутентифицирован

    // Ошибки ключей (-80..-99)
    ERR_KEY_NOT_FOUND = -80,      ///< Ключ не найден
    ERR_KEY_INDIGESTIBLE = -81,   ///< Ключ не может быть обработан
    ERR_KEY_SIZE = -82,           ///< Неподдерживаемый размер ключа
    ERR_KEY_TYPE = -83,           ///< Неподдерживаемый тип ключа

    // Криптографические ошибки (-100..-119)
    ERR_SIGN_FAILED = -100,       ///< Ошибка подписи
    ERR_VERIFY_FAILED = -101,     ///< Ошибка проверки подписи
    ERR_ENCRYPT_FAILED = -102,    ///< Ошибка шифрования
    ERR_DECRYPT_FAILED = -103,    ///< Ошибка расшифровки
    ERR_DIGEST_FAILED = -104,     ///< Ошибка хеширования
    ERR_RANDOM_FAILED = -105,     ///< Ошибка генерации случайных чисел

    // Ошибки доступа (-120..-139)
    ERR_ACCESS_DENIED = -120,     ///< Доступ запрещен
    ERR_USER_NOT_AUTHORIZED = -121, ///< Пользователь не авторизован
    ERR_OBJECT_READ_ONLY = -122,  ///< Объект только для чтения

    // Ошибки PC/SC (-140..-159)
    ERR_PCSC_NOT_FOUND = -140,    ///< PC/SC не найден
    ERR_PCSC_READER_NOT_FOUND = -141, ///< Читатель не найден
    ERR_PCSC_CARD_NOT_PRESENT = -142, ///< Карта отсутствует
    ERR_PCSC_COMMUNICATION = -143, ///< Ошибка связи с читателем
    ERR_PCSC_PROTOCOL = -144,     ///< Ошибка протокола
};

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ДЛЯ РАБОТЫ С ФИКСИРОВАННЫМИ БУФЕРАМИ
// ============================================================================

/**
 * @brief Безопасная конвертация std::string в фиксированный буфер
 */
template<size_t N>
inline void string_to_buffer(const std::string& src, char (&dst)[N]) {
    size_t len = std::min(src.size(), N - 1);
    std::copy(src.begin(), src.begin() + len, dst);
    dst[len] = '\0';
}

/**
 * @brief Безопасная конвертация фиксированного буфера в std::string
 */
template<size_t N>
inline std::string buffer_to_string(const char (&src)[N]) {
    return std::string(src, strnlen(src, N));
}

/**
 * @brief Безопасная конвертация vector<uint8_t> в hex строку
 */
inline std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
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
 * @brief Безопасная конвертация hex строки в vector<uint8_t>
 */
inline std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// ============================================================================
// ОСНОВНОЙ ИНТЕРФЕЙС (ВИРТУАЛЬНЫЙ КЛАСС, C++ ABI)
// ============================================================================
// ВНИМАНИЕ: Это C++ ABI, НЕ C ABI.
// Мы осознанно используем виртуальные функции и STL-типы,
// потому что полностью контролируем компилятор и среду сборки.
//
// НЕ ДОБАВЛЯТЬ extern "C"!
// НЕ ЭКСПОРТИРОВАТЬ СИМВОЛЫ ЯВНО!
// pybind11 сам сгенерирует правильную точку входа.
// ============================================================================

/**
 * @brief Интерфейс для работы с PKCS#11 токенами
 *
 * Абстрактный базовый класс, который реализуется для каждого типа токенов.
 * Позволяет единообразно работать с Рутокен, eToken, смарт-картами.
 *
 * ABI-стабильность обеспечивается:
 *   1. Фиксированными размерами всех публичных типов
 *   2. Zero-initialization всех структур
 *   3. Одинаковыми настройками компилятора для всех модулей
 *   4. pybind11 на стороне Python
 */
class ITokenModule {
public:
    virtual ~ITokenModule() = default;

    // ------------------------------------------------------------------------
    // Инициализация и управление
    // ------------------------------------------------------------------------

    /**
     * @brief Инициализировать модуль PKCS#11
     * @param library_path Путь к библиотеке PKCS#11 (.dll/.so/.dylib)
     * @return Результат операции
     */
    virtual TokenResult Initialize(const std::string& library_path) = 0;

    /**
     * @brief Завершить работу с модулем
     */
    virtual void Finalize() = 0;

    /**
     * @brief Проверить, инициализирован ли модуль
     */
    virtual bool IsInitialized() const = 0;

    // ------------------------------------------------------------------------
    // Работа с токенами
    // ------------------------------------------------------------------------

    /**
     * @brief Получить список доступных токенов
     * @return Вектор с информацией о токенах
     */
    virtual std::vector<TokenInfo> GetAvailableTokens() = 0;

    /**
     * @brief Открыть сессию на токене
     * @param slot_id Идентификатор слота (фиксированный 32-битный)
     * @param pin PIN-код пользователя
     * @return Идентификатор сессии или 0 при ошибке
     */
    virtual SessionId OpenSession(SlotId slot_id, const std::string& pin) = 0;

    /**
     * @brief Закрыть сессию
     * @param session_id Идентификатор сессии
     */
    virtual void CloseSession(SessionId session_id) = 0;

    /**
     * @brief Проверить, активна ли сессия
     */
    virtual bool IsSessionValid(SessionId session_id) const = 0;

    /**
     * @brief Изменить PIN-код пользователя
     * @param session_id Идентификатор сессии
     * @param old_pin Старый PIN
     * @param new_pin Новый PIN
     */
    virtual TokenResult ChangePin(SessionId session_id,
                                  const std::string& old_pin,
                                  const std::string& new_pin) = 0;

    // ------------------------------------------------------------------------
    // Управление ключами
    // ------------------------------------------------------------------------

    /**
     * @brief Сгенерировать пару ключей RSA на токене
     * @param session_id Идентификатор сессии
     * @param params Параметры генерации
     * @return ID ключа (hex строка) или пустая строка при ошибке
     */
    virtual std::string GenerateRsaKeyPair(SessionId session_id,
                                           const RsaKeyParams& params) = 0;

    /**
     * @brief Получить список ключей на токене
     * @param session_id Идентификатор сессии
     * @return Вектор с информацией о ключах
     */
    virtual std::vector<KeyInfo> ListKeys(SessionId session_id) = 0;

    /**
     * @brief Найти ключ по ID
     * @param session_id Идентификатор сессии
     * @param key_id Идентификатор ключа (hex строка)
     * @return Информация о ключе или nullptr если не найден
     */
    virtual std::unique_ptr<KeyInfo> FindKeyById(SessionId session_id,
                                                 const std::string& key_id) = 0;

    /**
     * @brief Удалить ключ с токена
     * @param session_id Идентификатор сессии
     * @param key_id Идентификатор ключа (hex строка)
     */
    virtual TokenResult DeleteKey(SessionId session_id,
                                  const std::string& key_id) = 0;

    // ------------------------------------------------------------------------
    // Криптографические операции
    // ------------------------------------------------------------------------

    /**
     * @brief Подписать данные с использованием закрытого ключа RSA
     * @param session_id Идентификатор сессии
     * @param key_id Идентификатор ключа
     * @param data Данные для подписи
     * @param params Параметры подписи
     * @return Подпись в бинарном виде
     */
    virtual std::vector<uint8_t> SignRsa(SessionId session_id,
                                         const std::string& key_id,
                                         const std::vector<uint8_t>& data,
                                         const RsaSignParams& params = {}) = 0;

    /**
     * @brief Проверить подпись RSA
     * @param session_id Идентификатор сессии
     * @param key_id Идентификатор ключа (публичного)
     * @param data Исходные данные
     * @param signature Подпись для проверки
     * @param params Параметры подписи
     * @return true если подпись корректна
     */
    virtual bool VerifyRsa(SessionId session_id,
                           const std::string& key_id,
                           const std::vector<uint8_t>& data,
                           const std::vector<uint8_t>& signature,
                           const RsaSignParams& params = {}) = 0;

    /**
     * @brief Зашифровать данные открытым ключом RSA
     * @param session_id Идентификатор сессии
     * @param key_id Идентификатор ключа (публичного)
     * @param plaintext Открытый текст
     * @param params Параметры шифрования
     * @return Зашифрованные данные
     */
    virtual std::vector<uint8_t> EncryptRsa(SessionId session_id,
                                            const std::string& key_id,
                                            const std::vector<uint8_t>& plaintext,
                                            const RsaEncryptParams& params = {}) = 0;

    /**
     * @brief Расшифровать данные закрытым ключом RSA
     * @param session_id Идентификатор сессии
     * @param key_id Идентификатор ключа (приватного)
     * @param ciphertext Зашифрованные данные
     * @param params Параметры шифрования
     * @return Расшифрованный текст
     */
    virtual std::vector<uint8_t> DecryptRsa(SessionId session_id,
                                            const std::string& key_id,
                                            const std::vector<uint8_t>& ciphertext,
                                            const RsaEncryptParams& params = {}) = 0;

    // ------------------------------------------------------------------------
    // Работа с сертификатами
    // ------------------------------------------------------------------------

    /**
     * @brief Получить список сертификатов на токене
     * @param session_id Идентификатор сессии
     * @return Вектор с информацией о сертификатах
     */
    virtual std::vector<CertificateInfo> ListCertificates(SessionId session_id) = 0;

    /**
     * @brief Импортировать сертификат на токен
     * @param session_id Идентификатор сессии
     * @param cert_data Данные сертификата (DER/PEM)
     * @param label Метка сертификата
     * @param key_id ID связанного ключа (опционально)
     */
    virtual TokenResult ImportCertificate(SessionId session_id,
                                         const std::vector<uint8_t>& cert_data,
                                         const std::string& label,
                                         const std::string& key_id = "") = 0;

    /**
     * @brief Экспортировать сертификат с токена
     * @param session_id Идентификатор сессии
     * @param cert_id Идентификатор сертификата
     * @param format Формат (DER/PEM)
     * @return Данные сертификата
     */
    virtual std::vector<uint8_t> ExportCertificate(SessionId session_id,
                                                   const std::string& cert_id,
                                                   const std::string& format = "DER") = 0;

    // ------------------------------------------------------------------------
    // Утилиты
    // ------------------------------------------------------------------------

    /**
     * @brief Получить строковое описание ошибки
     */
    virtual std::string GetErrorMessage(TokenResult result) const = 0;

    /**
     * @brief Получить версию модуля
     */
    virtual std::string GetVersion() const = 0;
};

// ============================================================================
// ФАБРИКА МОДУЛЕЙ
// ============================================================================

/**
 * @brief Создать экземпляр модуля для работы с токеном
 * @param type Тип токена
 * @return Умный указатель на интерфейс
 */
//std::unique_ptr<ITokenModule> CreateTokenModule(TokenType type);

/**
 * @brief Автоматически определить тип токена по библиотеке
 * @param library_path Путь к библиотеке
 * @return Определенный тип или GENERIC_PKCS11
 */
// TokenType DetectTokenType(const std::string& library_path);

} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_API_H