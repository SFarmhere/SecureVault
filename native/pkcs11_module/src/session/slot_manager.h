// ============================================================================
// SecureVault - Заголовочный файл менеджера слотов PKCS#11
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Объявление публичного API SlotManager и вспомогательных структур.
//   Реализация находится в slot_manager.cpp.
//
// СВЯЗЬ С ДРУГИМИ МОДУЛЯМИ:
//   - SessionManager использует SlotManager для отслеживания состояния
//     слотов и инвалидации сессий при извлечении токена.
//   - GUI и Python bindings используют SlotManager для отображения
//     статуса подключенных токенов.
// ============================================================================

#ifndef SECUREVAULT_PKCS11_SLOT_MANAGER_H
#define SECUREVAULT_PKCS11_SLOT_MANAGER_H

#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../../include/session_types.h"  // для SlotId, SlotState, SlotEventType
#include "../../include/token_types.h"    // для TokenType, TokenInfo

namespace securevault {
namespace pkcs11 {

// ============================================================================
// РАСШИРЕННАЯ ИНФОРМАЦИЯ О СЛОТЕ (ABI-СТАБИЛЬНАЯ)
// ============================================================================

/**
 * @brief Расширенная информация о слоте (ABI-стабильная структура)
 */
struct SlotInfoEx {
    SlotId id{0};                          ///< ID слота (PKCS#11)
    SlotState state{SlotState::EMPTY};     ///< Текущее состояние
    TokenInfo token_info{};                ///< Информация о токене
    char library_path[256]{};              ///< Путь к PKCS#11 библиотеке
    TokenType token_type{TokenType::UNKNOWN}; ///< Тип токена
    uint32_t active_sessions{0};            ///< Количество активных сессий
    int64_t last_seen_ms{0};                ///< Время последнего обнаружения
    int64_t last_used_ms{0};                ///< Время последней операции
    uint32_t error_count{0};                 ///< Счетчик ошибок подряд
    bool is_supported{true};                ///< Поддерживается ли токен
    char usb_vid_pid[32]{};                 ///< USB Vendor ID / Product ID
    char usb_serial[64]{};                  ///< USB серийный номер

    SlotInfoEx() = default;

    void set_library_path(const char* path) {
        strncpy(library_path, path, sizeof(library_path) - 1);
    }
    void set_usb_vid_pid(const char* vidpid) {
        strncpy(usb_vid_pid, vidpid, sizeof(usb_vid_pid) - 1);
    }
    void set_usb_serial(const char* serial) {
        strncpy(usb_serial, serial, sizeof(usb_serial) - 1);
    }
};

// ============================================================================
// CALLBACK ДЛЯ СОБЫТИЙ СЛОТОВ
// ============================================================================

/**
 * @brief Callback для уведомления о событиях слотов
 */
using SlotEventCallback = std::function<void(SlotEventType, const SlotInfoEx&)>;

// ============================================================================
// МЕНЕДЖЕР СЛОТОВ (SINGLETON)
// ============================================================================

/**
 * @brief Центральный менеджер слотов PKCS#11
 *
 * Управляет обнаружением токенов, хотплагом, состоянием слотов.
 * Уведомляет подписчиков о событиях подключения/отключения.
 *
 * ПОТОКОБЕЗОПАСНОСТЬ:
 *   - Все публичные методы thread-safe
 *   - Внутренние потоки: hotplug listener, watchdog
 *   - Recursive mutex для защиты внутренних структур
 */
class SlotManager {
public:
    // ------------------------------------------------------------------------
    // SINGLETON
    // ------------------------------------------------------------------------

    /**
     * @brief Получить глобальный экземпляр менеджера
     * @return Ссылка на синглтон SlotManager
     *
     * @note Thread-safe с C++11 (магическая статика)
     */
    static SlotManager& GetInstance();

    // Запрет копирования (RAII ресурсы не должны копироваться)
    SlotManager(const SlotManager&) = delete;
    SlotManager& operator=(const SlotManager&) = delete;

    // ------------------------------------------------------------------------
    // ЖИЗНЕННЫЙ ЦИКЛ
    // ------------------------------------------------------------------------

    /**
     * @brief Инициализировать менеджер слотов
     * @return true если успешно
     *
     * Инициализирует хотплаг, запускает watchdog и выполняет
     * первоначальное сканирование слотов.
     */
    bool Initialize();

    /**
     * @brief Завершить работу менеджера
     *
     * Останавливает потоки, освобождает платформозависимые ресурсы.
     */
    void Shutdown();

    // ------------------------------------------------------------------------
    // УПРАВЛЕНИЕ МОДУЛЯМИ
    // ------------------------------------------------------------------------

    /**
     * @brief Зарегистрировать PKCS#11 библиотеку
     * @param library_path Путь к .dll/.so/.dylib
     * @return true если успешно
     */
    bool RegisterModule(const std::string& library_path);

    /**
     * @brief Удалить регистрацию PKCS#11 библиотеки
     * @param library_path Путь к библиотеке
     */
    void UnregisterModule(const std::string& library_path);

    // ------------------------------------------------------------------------
    // ПОЛУЧЕНИЕ ИНФОРМАЦИИ О СЛОТАХ
    // ------------------------------------------------------------------------

    /**
     * @brief Получить список всех доступных слотов
     * @return Вектор SlotInfoEx
     */
    std::vector<SlotInfoEx> GetAllSlots();

    /**
     * @brief Получить информацию о конкретном слоте
     * @param slot_id ID слота
     * @return SlotInfoEx или nullptr если не найден
     */
    std::unique_ptr<SlotInfoEx> GetSlotInfo(SlotId slot_id);

    /**
     * @brief Получить слот по USB VID/PID
     * @param vid Vendor ID
     * @param pid Product ID
     * @param serial Серийный номер (опционально)
     * @return ID слота или -1
     */
    SlotId FindSlotByUSB(uint16_t vid, uint16_t pid, const std::string& serial = "");

    // ------------------------------------------------------------------------
    // УПРАВЛЕНИЕ СОСТОЯНИЕМ
    // ------------------------------------------------------------------------

    /**
     * @brief Обновить состояние слота (вызывается из SessionManager)
     * @param slot_id ID слота
     * @param state Новое состояние
     * @return true если успешно
     */
    bool UpdateSlotState(SlotId slot_id, SlotState state);

    /**
     * @brief Увеличить счетчик сессий для слота
     * @param slot_id ID слота
     */
    void IncrementSessionCount(SlotId slot_id);

    /**
     * @brief Уменьшить счетчик сессий для слота
     * @param slot_id ID слота
     */
    void DecrementSessionCount(SlotId slot_id);

    /**
     * @brief Зарегистрировать ошибку для слота
     * @param slot_id ID слота
     */
    void ReportError(SlotId slot_id);

    // ------------------------------------------------------------------------
    // ПОДПИСКА НА СОБЫТИЯ
    // ------------------------------------------------------------------------

    /**
     * @brief Подписаться на события слотов
     * @param callback Функция для вызова при событиях
     * @return ID подписки (для отписки)
     */
    int Subscribe(SlotEventCallback callback);

    /**
     * @brief Отписаться от событий
     * @param subscription_id ID подписки
     * @return true если успешно
     */
    bool Unsubscribe(int subscription_id);

    // ------------------------------------------------------------------------
    // СТАТИСТИКА И ДИАГНОСТИКА
    // ------------------------------------------------------------------------

    /**
     * @brief Получить статистику работы менеджера
     * @return JSON-like строка со статистикой
     */
    std::string GetStatistics();

    /**
     * @brief Принудительно пересканировать слоты
     */
    void ForceRescan();

private:
    // Конструктор/деструктор приватные (singleton)
    SlotManager() = default;
    ~SlotManager();
};

} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_SLOT_MANAGER_H