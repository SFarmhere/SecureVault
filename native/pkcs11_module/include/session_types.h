// ============================================================================
// SecureVault - Типы данных для PKCS#11 сессий
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Определение типов, связанных с PKCS#11 сессиями, слотами и состоянием.
//   Эти типы используются во всех модулях для типобезопасности.
//
// ВСЕ ПУБЛИЧНЫЕ ТИПЫ имеют фиксированный размер для ABI-стабильности.
// ============================================================================

#ifndef SECUREVAULT_PKCS11_SESSION_TYPES_H
#define SECUREVAULT_PKCS11_SESSION_TYPES_H

#include <cstdint>
#include <chrono>
#include <cstring>

namespace securevault {
namespace pkcs11 {

// ============================================================================
// ФИКСИРОВАННЫЕ ТИПЫ ДЛЯ ABI-СТАБИЛЬНОСТИ (ВСЕГДА 32/64 БИТА)
// ============================================================================

/**
 * @brief Уникальный идентификатор сессии (всегда 4 байта)
 *
 * Используется во всех API для идентификации открытой сессии.
 * Значение > 0 означает валидную сессию, <= 0 - ошибку.
 */
using SessionId = int32_t;

/**
 * @brief Уникальный идентификатор слота (всегда 4 байта)
 *
 * PKCS#11 использует CK_SLOT_ID (unsigned long), но в публичном API
 * мы фиксируем размер до 32 бит для кроссплатформенной совместимости.
 */
using SlotId = uint32_t;

/**
 * @brief Уникальный идентификатор объекта на токене (всегда 4 байта)
 */
using ObjectHandle = uint32_t;

// ============================================================================
// ТИПЫ ДЛЯ СЕССИЙ (ВСЕ С ФИКСИРОВАННЫМ РАЗМЕРОМ)
// ============================================================================

/**
 * @brief Состояние сессии
 */
enum class SessionState : uint8_t {
    INVALID = 0,        ///< Сессия не существует или невалидна
    INITIALIZED,        ///< Сессия создана, но не аутентифицирована
    LOGGED_IN,          ///< Пользователь аутентифицирован, сессия активна
    LOGGED_OUT,         ///< Сессия существует, но пользователь вышел
    CLOSING,            ///< Сессия в процессе закрытия
    ERROR               ///< Сессия в ошибочном состоянии
};

/**
 * @brief Тип аутентификации пользователя
 */
enum class UserType : uint8_t {
    SO = 0,             ///< Security Officer (администратор)
    USER = 1,           ///< Обычный пользователь
    CONTEXT_SPECIFIC = 2 ///< Контекстно-зависимый (для некоторых токенов)
};

/**
 * @brief Флаги сессии (32 бита)
 */
enum class SessionFlags : uint32_t {
    NONE = 0x0000,
    RW_SESSION = 0x0002,        ///< Чтение/запись (не только чтение)
    SERIAL_SESSION = 0x0004,    ///< Сериализованные операции
};

// Оператор OR для флагов
inline SessionFlags operator|(SessionFlags a, SessionFlags b) {
    return static_cast<SessionFlags>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b)
    );
}

inline SessionFlags operator&(SessionFlags a, SessionFlags b) {
    return static_cast<SessionFlags>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b)
    );
}

/**
 * @brief Расширенная информация о сессии (ABI-стабильная структура)
 *
 * Все поля имеют фиксированный размер, строки - фиксированные буферы.
 * Конструктор по умолчанию инициализирует все поля нулями.
 */
struct SessionInfo {
    SessionId id{};                 ///< Внутренний ID сессии
    SlotId slot_id{};               ///< ID слота (фиксированный 32 бита)
    SessionState state{};           ///< Текущее состояние
    SessionFlags flags{};           ///< Флаги сессии
    UserType user_type{};           ///< Тип аутентифицированного пользователя

    // Временные метки (миллисекунды с эпохи, 64 бита)
    int64_t created_at_ms{};        ///< Время создания
    int64_t last_used_ms{};         ///< Последнее использование

    uint32_t operation_count{};     ///< Количество операций в сессии
    uint32_t error_count{};         ///< Количество ошибок

    // Фиксированные буферы вместо std::string
    char token_label[64]{};         ///< Метка токена
    char reader_name[128]{};        ///< Имя читателя (для смарт-карт)

    SessionInfo() = default;

    // Вспомогательные методы для работы с буферами
    void set_token_label(const char* label) {
        strncpy(token_label, label, sizeof(token_label) - 1);
        token_label[sizeof(token_label) - 1] = '\0';
    }

    void set_reader_name(const char* name) {
        strncpy(reader_name, name, sizeof(reader_name) - 1);
        reader_name[sizeof(reader_name) - 1] = '\0';
    }

    const char* get_token_label() const { return token_label; }
    const char* get_reader_name() const { return reader_name; }
};

// ============================================================================
// ТИПЫ ДЛЯ СЛОТОВ (ВСЕ С ФИКСИРОВАННЫМ РАЗМЕРОМ)
// ============================================================================

/**
 * @brief Состояние слота
 */
enum class SlotState : uint8_t {
    UNKNOWN = 0,        ///< Состояние неизвестно
    EMPTY,              ///< Слот пуст, токен отсутствует
    PRESENT,            ///< Токен присутствует, не инициализирован
    INITIALIZED,        ///< Токен инициализирован
    REMOVED,            ///< Токен был извлечен
    ERROR               ///< Ошибка слота
};

/**
 * @brief Тип события слота (для callback'ов)
 */
enum class SlotEventType : uint8_t {
    TOKEN_INSERTED,     ///< Токен подключен
    TOKEN_REMOVED,      ///< Токен извлечен
    TOKEN_INITIALIZED,  ///< Токен инициализирован
    SESSION_OPENED,     ///< Открыта сессия
    SESSION_CLOSED,     ///< Закрыта сессия
    PIN_CHANGED,        ///< PIN изменен
    PIN_BLOCKED,        ///< PIN заблокирован
    CARD_ERROR          ///< Ошибка смарт-карты
};

/**
 * @brief Флаги для SlotInfo (экономия памяти)
 */
namespace SlotInfoFlags {
    constexpr uint32_t HAS_TOKEN = 1 << 0;          ///< Есть токен
    constexpr uint32_t TOKEN_INITIALIZED = 1 << 1;  ///< Токен инициализирован
    constexpr uint32_t USER_PIN_SET = 1 << 2;       ///< PIN пользователя установлен
    constexpr uint32_t SO_PIN_SET = 1 << 3;         ///< PIN администратора установлен
}

/**
 * @brief Информация о слоте (ABI-стабильная структура)
 */
struct SlotInfo {
    SlotId id{};                        ///< ID слота
    SlotState state{};                  ///< Состояние
    uint32_t flags{};                   ///< Битовые флаги (вместо отдельных bool)

    // Фиксированные буферы для строк
    char manufacturer[64]{};            ///< Производитель
    char model[64]{};                   ///< Модель
    char serial_number[32]{};           ///< Серийный номер токена
    char library_path[256]{};           ///< Путь к PKCS#11 библиотеке

    uint32_t max_session_count{};       ///< Максимум сессий
    uint32_t session_count{};           ///< Текущее количество сессий

    uint8_t pin_retries{};              ///< Осталось попыток PIN
    uint8_t so_pin_retries{};           ///< Осталось попыток SO PIN

    int64_t last_seen_ms{};             ///< Время последнего обнаружения

    SlotInfo() = default;

    // Геттеры для флагов
    bool has_token() const { return flags & SlotInfoFlags::HAS_TOKEN; }
    bool token_initialized() const { return flags & SlotInfoFlags::TOKEN_INITIALIZED; }
    bool user_pin_set() const { return flags & SlotInfoFlags::USER_PIN_SET; }
    bool so_pin_set() const { return flags & SlotInfoFlags::SO_PIN_SET; }

    // Сеттеры для флагов
    void set_has_token(bool v) { set_flag(SlotInfoFlags::HAS_TOKEN, v); }
    void set_token_initialized(bool v) { set_flag(SlotInfoFlags::TOKEN_INITIALIZED, v); }
    void set_user_pin_set(bool v) { set_flag(SlotInfoFlags::USER_PIN_SET, v); }
    void set_so_pin_set(bool v) { set_flag(SlotInfoFlags::SO_PIN_SET, v); }

    // Вспомогательные методы для строк
    void set_manufacturer(const char* s) { strncpy(manufacturer, s, sizeof(manufacturer) - 1); }
    void set_model(const char* s) { strncpy(model, s, sizeof(model) - 1); }
    void set_serial_number(const char* s) { strncpy(serial_number, s, sizeof(serial_number) - 1); }
    void set_library_path(const char* s) { strncpy(library_path, s, sizeof(library_path) - 1); }

private:
    void set_flag(uint32_t flag, bool value) {
        if (value) flags |= flag;
        else flags &= ~flag;
    }
};

// ============================================================================
// ТИПЫ ДЛЯ USB/ХОТПЛАГА (С ФИКСИРОВАННЫМИ БУФЕРАМИ)
// ============================================================================

/**
 * @brief Идентификатор USB устройства (ABI-стабильная структура)
 */
struct USBDeviceId {
    uint16_t vendor_id{};           ///< Vendor ID (например, 0x1050 для Yubico)
    uint16_t product_id{};          ///< Product ID (например, 0x0407 для YubiKey 5)
    char serial_number[64]{};       ///< Серийный номер (фиксированный буфер)

    bool operator<(const USBDeviceId& other) const {
        if (vendor_id != other.vendor_id) return vendor_id < other.vendor_id;
        if (product_id != other.product_id) return product_id < other.product_id;
        return strcmp(serial_number, other.serial_number) < 0;
    }

    bool operator==(const USBDeviceId& other) const {
        return vendor_id == other.vendor_id &&
               product_id == other.product_id &&
               strcmp(serial_number, other.serial_number) == 0;
    }

    void set_serial_number(const char* s) {
        strncpy(serial_number, s, sizeof(serial_number) - 1);
        serial_number[sizeof(serial_number) - 1] = '\0';
    }
};

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (INLINE, HEADER-ONLY)
// ============================================================================

/**
 * @brief Получить строковое представление состояния сессии
 */
inline const char* SessionStateToString(SessionState state) {
    switch (state) {
        case SessionState::INVALID: return "INVALID";
        case SessionState::INITIALIZED: return "INITIALIZED";
        case SessionState::LOGGED_IN: return "LOGGED_IN";
        case SessionState::LOGGED_OUT: return "LOGGED_OUT";
        case SessionState::CLOSING: return "CLOSING";
        case SessionState::ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

/**
 * @brief Получить строковое представление события слота
 */
inline const char* SlotEventTypeToString(SlotEventType event) {
    switch (event) {
        case SlotEventType::TOKEN_INSERTED: return "TOKEN_INSERTED";
        case SlotEventType::TOKEN_REMOVED: return "TOKEN_REMOVED";
        case SlotEventType::TOKEN_INITIALIZED: return "TOKEN_INITIALIZED";
        case SlotEventType::SESSION_OPENED: return "SESSION_OPENED";
        case SlotEventType::SESSION_CLOSED: return "SESSION_CLOSED";
        case SlotEventType::PIN_CHANGED: return "PIN_CHANGED";
        case SlotEventType::PIN_BLOCKED: return "PIN_BLOCKED";
        case SlotEventType::CARD_ERROR: return "CARD_ERROR";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// ABI-ПРОВЕРКИ (ДЛЯ ОТЛАДКИ)
// ============================================================================

#ifdef SECUREVAULT_ENABLE_ABI_CHECKS
static_assert(sizeof(SessionId) == 4, "SessionId must be 4 bytes for ABI stability");
static_assert(sizeof(SlotId) == 4, "SlotId must be 4 bytes for ABI stability");
static_assert(sizeof(ObjectHandle) == 4, "ObjectHandle must be 4 bytes for ABI stability");
static_assert(sizeof(SessionInfo) == 4+4+1+4+1+8+8+4+4+64+128, "SessionInfo has unexpected size");
static_assert(sizeof(SlotInfo) == 4+1+4+64+64+32+256+4+4+1+1+8, "SlotInfo has unexpected size");
static_assert(alignof(SessionInfo) == 8, "SessionInfo alignment should be 8");
static_assert(alignof(SlotInfo) == 8, "SlotInfo alignment should be 8");
#endif

} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_SESSION_TYPES_H