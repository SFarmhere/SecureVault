// ============================================================================
// SecureVault - Типы данных для PKCS#11 токенов
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Определение типов, связанных с аппаратными токенами, ключами и
//   криптографическими операциями.
//
// ВСЕ ПУБЛИЧНЫЕ ТИПЫ имеют фиксированный размер для ABI-стабильности.
// ============================================================================

#ifndef SECUREVAULT_PKCS11_TOKEN_TYPES_H
#define SECUREVAULT_PKCS11_TOKEN_TYPES_H

#include <cstdint>
#include <cstring>

namespace securevault {
namespace pkcs11 {

// ============================================================================
// ФИКСИРОВАННЫЕ ТИПЫ ДЛЯ ABI-СТАБИЛЬНОСТИ
// ============================================================================

using KeySizeBits = uint32_t;      ///< Размер ключа в битах (всегда 4 байта)
using MemoryBytes = uint64_t;      ///< Размер памяти в байтах (всегда 8 байт)
using TimestampMs = int64_t;       ///< Временная метка в миллисекундах (всегда 8 байт)

// ============================================================================
// ТИПЫ ТОКЕНОВ (С ФИКСИРОВАННЫМ РАЗМЕРОМ)
// ============================================================================

/**
 * @brief Типы поддерживаемых токенов
 */
enum class TokenType : int32_t {
    UNKNOWN = 0,
    RUTOKEN = 1,
    ETOKEN = 2,
    JA_CARTA = 3,
    YUBIKEY = 4,
    SOLOKEY = 5,
    NITROKEY = 6,
    GENERIC_PKCS11 = 7,
    PCSC_SMARTCARD = 8,
};

/**
 * @brief Производители токенов
 */
enum class TokenManufacturer : int32_t {
    UNKNOWN = 0,
    AKTIV = 1,
    SAFENET = 2,
    ALIOT = 3,
    YUBICO = 4,
    SOLOKEYS = 5,
    NITROKEY = 6,
    OTHER = 7
};

/**
 * @brief Транспорт/интерфейс токена
 */
enum class TokenTransport : int32_t {
    UNKNOWN = 0,
    USB_HID = 1,
    USB_CCID = 2,
    NFC = 3,
    BLE = 4,
    PCSC = 5,
    INTERNAL = 6
};

// ============================================================================
// ТИПЫ КЛЮЧЕЙ (С ФИКСИРОВАННЫМ РАЗМЕРОМ)
// ============================================================================

/**
 * @brief Тип ключа
 */
enum class KeyType : int32_t {
    UNKNOWN = 0,
    RSA_PRIVATE = 1,
    RSA_PUBLIC = 2,
    EC_PRIVATE = 3,
    EC_PUBLIC = 4,
    AES = 5,
    GOST_PRIVATE = 6,
    GOST_PUBLIC = 7,
    ED25519_PRIVATE = 8,
    ED25519_PUBLIC = 9,
    SECRET = 10
};

/**
 * @brief Алгоритм подписи
 */
enum class SignAlgorithm : int32_t {
    UNKNOWN = 0,
    RSA_PKCS1_SHA256 = 1,
    RSA_PKCS1_SHA384 = 2,
    RSA_PKCS1_SHA512 = 3,
    RSA_PSS_SHA256 = 4,
    RSA_PSS_SHA384 = 5,
    RSA_PSS_SHA512 = 6,
    ECDSA_SHA256 = 7,
    ECDSA_SHA384 = 8,
    GOST_3410_2012_256 = 9,
    GOST_3410_2012_512 = 10
};

/**
 * @brief Алгоритм шифрования
 */
enum class EncryptAlgorithm : int32_t {
    UNKNOWN = 0,
    RSA_PKCS1 = 1,
    RSA_OAEP_SHA256 = 2,
    RSA_OAEP_SHA384 = 3,
    RSA_OAEP_SHA512 = 4,
    AES_CBC = 5,
    AES_GCM = 6,
    GOST_28147_89 = 7
};

/**
 * @brief Формат сертификата
 */
enum class CertificateFormat : int32_t {
    UNKNOWN = 0,
    X509_DER = 1,
    X509_PEM = 2,
    PKCS7 = 3,
    PKCS12 = 4
};

// ============================================================================
// БИТОВЫЕ ФЛАГИ ДЛЯ KEYINFO
// ============================================================================

namespace KeyFlags {
    constexpr uint32_t PRIVATE = 1 << 0;           ///< Приватный ключ
    constexpr uint32_t EXTRACTABLE = 1 << 1;       ///< Можно экспортировать
    constexpr uint32_t MODIFIABLE = 1 << 2;        ///< Можно изменять
    constexpr uint32_t TOKEN = 1 << 3;             ///< Хранится на токене
    constexpr uint32_t SENSITIVE = 1 << 4;         ///< Чувствительный
    constexpr uint32_t ALWAYS_SENSITIVE = 1 << 5;  ///< Всегда чувствительный
    constexpr uint32_t NEVER_EXTRACTABLE = 1 << 6; ///< Никогда не экспортируемый
    constexpr uint32_t LOCAL = 1 << 7;             ///< Сгенерирован локально
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ БУФЕРЫ
// ============================================================================

/**
 * @brief Фиксированный буфер для бинарных данных
 */
template<size_t N>
struct Buffer {
    uint8_t data[N]{};      ///< Данные
    uint32_t size{};        ///< Реальный размер (0..N)

    void clear() { size = 0; }
    bool empty() const { return size == 0; }
    const uint8_t* begin() const { return data; }
    const uint8_t* end() const { return data + size; }
};

// ============================================================================
// СТРУКТУРЫ ДЛЯ КЛЮЧЕЙ (ABI-СТАБИЛЬНЫЕ)
// ============================================================================

/**
 * @brief Информация о ключе на токене
 *
 * ABI-стабильная структура с фиксированными размерами всех полей.
 * Все строки хранятся в фиксированных буферах.
 */
struct KeyInfo {
    // Идентификация (фиксированные буферы)
    char id[64]{};                     ///< Идентификатор ключа (hex строка)
    char label[128]{};                 ///< Метка/имя ключа

    // Тип и размер
    KeyType type{KeyType::UNKNOWN};     ///< Тип ключа
    KeySizeBits size_bits{};            ///< Размер в битах

    // Атрибуты (битовые флаги вместо 8 bool)
    uint32_t flags{};                   ///< Битовые флаги (см. KeyFlags)

    // PKCS#11 хендл
    uint32_t object_handle{};           ///< PKCS#11 хендл объекта

    // Временные метки
    TimestampMs created_ms{};            ///< Дата создания
    TimestampMs last_used_ms{};          ///< Последнее использование

    // RSA данные (фиксированные буферы)
    Buffer<512> modulus;                 ///< Модуль RSA (макс 4096 бит = 512 байт)
    Buffer<4> public_exponent;           ///< Публичная экспонента (обычно 0x010001)

    // EC данные
    Buffer<256> ec_params;               ///< Параметры эллиптической кривой
    Buffer<256> ec_point;                ///< Точка на кривой (публичный ключ)

    KeyInfo() = default;

    // Геттеры для флагов
    bool is_private() const { return flags & KeyFlags::PRIVATE; }
    bool is_extractable() const { return flags & KeyFlags::EXTRACTABLE; }
    bool is_modifiable() const { return flags & KeyFlags::MODIFIABLE; }
    bool is_token() const { return flags & KeyFlags::TOKEN; }
    bool is_sensitive() const { return flags & KeyFlags::SENSITIVE; }
    bool is_always_sensitive() const { return flags & KeyFlags::ALWAYS_SENSITIVE; }
    bool is_never_extractable() const { return flags & KeyFlags::NEVER_EXTRACTABLE; }
    bool is_local() const { return flags & KeyFlags::LOCAL; }

    // Сеттеры для флагов
    void set_private(bool v) { set_flag(KeyFlags::PRIVATE, v); }
    void set_extractable(bool v) { set_flag(KeyFlags::EXTRACTABLE, v); }
    void set_modifiable(bool v) { set_flag(KeyFlags::MODIFIABLE, v); }
    void set_token(bool v) { set_flag(KeyFlags::TOKEN, v); }
    void set_sensitive(bool v) { set_flag(KeyFlags::SENSITIVE, v); }
    void set_always_sensitive(bool v) { set_flag(KeyFlags::ALWAYS_SENSITIVE, v); }
    void set_never_extractable(bool v) { set_flag(KeyFlags::NEVER_EXTRACTABLE, v); }
    void set_local(bool v) { set_flag(KeyFlags::LOCAL, v); }

    // Вспомогательные методы для строк
    void set_id(const char* s) { strncpy(id, s, sizeof(id) - 1); }
    void set_label(const char* s) { strncpy(label, s, sizeof(label) - 1); }
    const char* get_id() const { return id; }
    const char* get_label() const { return label; }

private:
    void set_flag(uint32_t flag, bool value) {
        if (value) flags |= flag;
        else flags &= ~flag;
    }
};

// ============================================================================
// СТРУКТУРЫ ДЛЯ СЕРТИФИКАТОВ (ABI-СТАБИЛЬНЫЕ)
// ============================================================================

/**
 * @brief Информация о сертификате
 */
struct CertificateInfo {
    char id[64]{};                          ///< Идентификатор (hex)
    char label[128]{};                      ///< Метка
    CertificateFormat format{};              ///< Формат

    char subject[256]{};                     ///< Subject DN
    char issuer[256]{};                      ///< Issuer DN
    char serial_number[64]{};                ///< Серийный номер

    TimestampMs not_before_ms{};             ///< Начало действия
    TimestampMs not_after_ms{};              ///< Окончание действия

    Buffer<1024> public_key;                 ///< Публичный ключ
    char signature_algorithm[32]{};          ///< Алгоритм подписи сертификата

    uint32_t flags{};                        ///< Флаги (CA, self-signed, etc.)
    uint32_t version{};                      ///< Версия X.509

    uint32_t key_handle{};                    ///< Связанный ключ (ObjectHandle)

    CertificateInfo() = default;

    // Флаги для сертификата
    static constexpr uint32_t FLAG_CA = 1 << 0;
    static constexpr uint32_t FLAG_SELF_SIGNED = 1 << 1;

    bool is_ca() const { return flags & FLAG_CA; }
    bool is_self_signed() const { return flags & FLAG_SELF_SIGNED; }
    void set_ca(bool v) { set_flag(FLAG_CA, v); }
    void set_self_signed(bool v) { set_flag(FLAG_SELF_SIGNED, v); }

private:
    void set_flag(uint32_t flag, bool value) {
        if (value) flags |= flag;
        else flags &= ~flag;
    }
};

// ============================================================================
// ПАРАМЕТРЫ КРИПТОГРАФИЧЕСКИХ ОПЕРАЦИЙ (ABI-СТАБИЛЬНЫЕ)
// ============================================================================

/**
 * @brief Параметры генерации ключа RSA
 */
struct RsaKeyParams {
    KeySizeBits key_size{2048};             ///< Размер ключа
    uint32_t public_exponent{65537};        ///< Публичная экспонента
    char label[128]{};                      ///< Метка ключа

    // Атрибуты (битовые флаги вместо 6 bool)
    uint32_t flags{KeyFlags::TOKEN | KeyFlags::PRIVATE | KeyFlags::SENSITIVE};

    RsaKeyParams() = default;
    explicit RsaKeyParams(KeySizeBits size) : key_size(size) {}

    // Геттеры
    bool is_token() const { return flags & KeyFlags::TOKEN; }
    bool is_private() const { return flags & KeyFlags::PRIVATE; }
    bool is_extractable() const { return flags & KeyFlags::EXTRACTABLE; }
    bool is_sensitive() const { return flags & KeyFlags::SENSITIVE; }
    bool is_modifiable() const { return flags & KeyFlags::MODIFIABLE; }

    // Сеттеры
    void set_token(bool v) { set_flag(KeyFlags::TOKEN, v); }
    void set_private(bool v) { set_flag(KeyFlags::PRIVATE, v); }
    void set_extractable(bool v) { set_flag(KeyFlags::EXTRACTABLE, v); }
    void set_sensitive(bool v) { set_flag(KeyFlags::SENSITIVE, v); }
    void set_modifiable(bool v) { set_flag(KeyFlags::MODIFIABLE, v); }

    void set_label(const char* s) { strncpy(label, s, sizeof(label) - 1); }
    const char* get_label() const { return label; }

private:
    void set_flag(uint32_t flag, bool value) {
        if (value) flags |= flag;
        else flags &= ~flag;
    }
};

/**
 * @brief Параметры подписи RSA
 */
struct RsaSignParams {
    enum class Padding : uint8_t {
        PKCS1 = 0,
        PSS = 1,
        NO_PADDING = 2
    };

    Padding padding{Padding::PSS};
    char hash_algorithm[16]{"SHA256"};      ///< SHA256, SHA384, SHA512
    uint32_t salt_length{32};

    RsaSignParams() = default;
    explicit RsaSignParams(Padding pad) : padding(pad) {}

    void set_hash_algorithm(const char* algo) {
        strncpy(hash_algorithm, algo, sizeof(hash_algorithm) - 1);
    }
    const char* get_hash_algorithm() const { return hash_algorithm; }
};

/**
 * @brief Параметры шифрования RSA
 */
struct RsaEncryptParams {
    enum class Padding : uint8_t {
        PKCS1 = 0,
        OAEP = 1,
        NO_PADDING = 2
    };

    Padding padding{Padding::OAEP};
    char hash_algorithm[16]{"SHA256"};      ///< Для OAEP
    char mgf_hash_algorithm[16]{"SHA256"};  ///< MGF1 hash
    Buffer<64> label;                       ///< OAEP label (опционально)

    RsaEncryptParams() = default;
    explicit RsaEncryptParams(Padding pad) : padding(pad) {}

    void set_hash_algorithm(const char* algo) {
        strncpy(hash_algorithm, algo, sizeof(hash_algorithm) - 1);
    }
    void set_mgf_hash_algorithm(const char* algo) {
        strncpy(mgf_hash_algorithm, algo, sizeof(mgf_hash_algorithm) - 1);
    }
};

// ============================================================================
// ИНФОРМАЦИЯ О ТОКЕНЕ (ABI-СТАБИЛЬНАЯ)
// ============================================================================

namespace TokenInfoFlags {
    constexpr uint32_t INITIALIZED = 1 << 0;      ///< Токен инициализирован
    constexpr uint32_t USER_PIN_SET = 1 << 1;     ///< PIN пользователя установлен
    constexpr uint32_t SO_PIN_SET = 1 << 2;       ///< PIN администратора установлен
    constexpr uint32_t REMOVABLE = 1 << 3;        ///< Съемный токен
    constexpr uint32_t HARDWARE = 1 << 4;         ///< Аппаратное устройство
}

/**
 * @brief Полная информация о токене
 */
struct TokenInfo {
    TokenType type{TokenType::UNKNOWN};                ///< Тип токена
    TokenManufacturer manufacturer{TokenManufacturer::UNKNOWN}; ///< Производитель
    TokenTransport transport{TokenTransport::UNKNOWN}; ///< Транспорт

    char manufacturer_name[64]{};     ///< Строковое имя производителя
    char model[64]{};                 ///< Модель
    char serial_number[32]{};         ///< Серийный номер
    char label[64]{};                 ///< Метка токена
    char firmware_version[16]{};      ///< Версия прошивки

    MemoryBytes total_memory{};        ///< Общая память (байт)
    MemoryBytes free_memory{};         ///< Свободная память (байт)

    uint32_t flags{};                  ///< Битовые флаги (см. TokenInfoFlags)

    uint8_t max_pin_len{};            ///< Максимальная длина PIN
    uint8_t min_pin_len{};            ///< Минимальная длина PIN
    uint8_t pin_retries{};            ///< Осталось попыток PIN
    uint8_t so_pin_retries{};         ///< Осталось попыток SO PIN

    uint32_t max_session_count{};      ///< Максимум сессий
    uint32_t session_count{};          ///< Текущее количество сессий

    uint32_t supported_mechanisms[16]{}; ///< Поддерживаемые механизмы (до 16)
    uint32_t mechanism_count{};          ///< Количество поддерживаемых механизмов

    TimestampMs insert_time_ms{};      ///< Время подключения

    TokenInfo() = default;

    // Геттеры для флагов
    bool is_initialized() const { return flags & TokenInfoFlags::INITIALIZED; }
    bool is_user_pin_set() const { return flags & TokenInfoFlags::USER_PIN_SET; }
    bool is_so_pin_set() const { return flags & TokenInfoFlags::SO_PIN_SET; }
    bool is_removable() const { return flags & TokenInfoFlags::REMOVABLE; }
    bool is_hardware() const { return flags & TokenInfoFlags::HARDWARE; }

    // Сеттеры для флагов
    void set_initialized(bool v) { set_flag(TokenInfoFlags::INITIALIZED, v); }
    void set_user_pin_set(bool v) { set_flag(TokenInfoFlags::USER_PIN_SET, v); }
    void set_so_pin_set(bool v) { set_flag(TokenInfoFlags::SO_PIN_SET, v); }
    void set_removable(bool v) { set_flag(TokenInfoFlags::REMOVABLE, v); }
    void set_hardware(bool v) { set_flag(TokenInfoFlags::HARDWARE, v); }

private:
    void set_flag(uint32_t flag, bool value) {
        if (value) flags |= flag;
        else flags &= ~flag;
    }
};

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ============================================================================

/**
 * @brief Получить строковое представление типа токена
 */
inline const char* TokenTypeToString(TokenType type) {
    switch (type) {
        case TokenType::RUTOKEN: return "RUTOKEN";
        case TokenType::ETOKEN: return "ETOKEN";
        case TokenType::JA_CARTA: return "JA_CARTA";
        case TokenType::YUBIKEY: return "YUBIKEY";
        case TokenType::SOLOKEY: return "SOLOKEY";
        case TokenType::NITROKEY: return "NITROKEY";
        case TokenType::GENERIC_PKCS11: return "GENERIC_PKCS11";
        case TokenType::PCSC_SMARTCARD: return "PCSC_SMARTCARD";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Получить строковое представление типа ключа
 */
inline const char* KeyTypeToString(KeyType type) {
    switch (type) {
        case KeyType::RSA_PRIVATE: return "RSA_PRIVATE";
        case KeyType::RSA_PUBLIC: return "RSA_PUBLIC";
        case KeyType::EC_PRIVATE: return "EC_PRIVATE";
        case KeyType::EC_PUBLIC: return "EC_PUBLIC";
        case KeyType::AES: return "AES";
        case KeyType::GOST_PRIVATE: return "GOST_PRIVATE";
        case KeyType::GOST_PUBLIC: return "GOST_PUBLIC";
        case KeyType::ED25519_PRIVATE: return "ED25519_PRIVATE";
        case KeyType::ED25519_PUBLIC: return "ED25519_PUBLIC";
        case KeyType::SECRET: return "SECRET";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// ABI-ПРОВЕРКИ
// ============================================================================

#ifdef SECUREVAULT_ENABLE_ABI_CHECKS
static_assert(sizeof(KeyInfo) == 64+128+4+4+4+4+8+8+512+4+4+4+256+4+256+4, "KeyInfo has unexpected size");
static_assert(sizeof(CertificateInfo) == 64+128+4+256+256+64+8+8+1024+4+32+4+4+4, "CertificateInfo has unexpected size");
static_assert(sizeof(TokenInfo) == 4+4+4+64+64+32+64+16+8+8+4+1+1+1+1+4+4+64+4+8, "TokenInfo has unexpected size");
static_assert(std::is_standard_layout_v<KeyInfo>, "KeyInfo must be standard layout");
static_assert(std::is_trivially_copyable_v<KeyInfo>, "KeyInfo must be trivially copyable");
#endif

} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_TOKEN_TYPES_H