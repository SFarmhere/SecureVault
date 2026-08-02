// ============================================================================
// SecureVault - Заголовочный файл менеджера сессий
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Фасад для управления PKCS#11 сессиями.
//   Единственная публичная точка входа для Python биндингов.
//   Использует PIMPL идиому для ABI-стабильности.
// ============================================================================

#ifndef SECUREVAULT_PKCS11_SESSION_MANAGER_H
#define SECUREVAULT_PKCS11_SESSION_MANAGER_H

#include <memory>
#include <vector>
#include <string>

#include "../../include/pkcs11_api.h"  // для TokenType, TokenInfo, SessionId

#include "../adapters/module_factory.h"

namespace securevault {
namespace pkcs11 {

// Forward declaration of implementation
class SessionManagerImpl;

/**
 * @brief Фасад для управления сессиями PKCS#11
 *
 * Предоставляет простой и безопасный API для работы с аппаратными токенами.
 * Все сложности реализации скрыты за PIMPL идиомой, что обеспечивает:
 * - ABI-стабильность при изменениях реализации
 * - Быструю компиляцию (изменения в .cpp не требуют перекомпиляции клиентов)
 * - Чистый интерфейс для Python биндингов
 *
 * Типичное использование:
 * @code
 * auto& manager = SessionManager::GetInstance();
 * SessionId sid = manager.OpenSession(TokenType::RUTOKEN, "12345678", "/usr/lib/librtpkcs11ecp.so");
 * if (sid > 0) {
 *     // Работа с сессией...
 *     manager.CloseSession(sid);
 * }
 * @endcode
 *
 * @note Все публичные методы thread-safe.
 * @see SessionManagerImpl для деталей реализации.
 */
class SessionManager {
private:
    std::unique_ptr<SessionManagerImpl> impl_;

public:
    /**
     * @brief Конструктор
     * @post impl_ инициализирован
     */
    SessionManager();

    /**
     * @brief Деструктор
     * @post Все сессии закрыты, ресурсы освобождены
     */
    ~SessionManager();

    // Запрет копирования (RAII ресурсы не должны копироваться)
    SessionManager(const SessionManager&) = delete;
    SessionManager& operator=(const SessionManager&) = delete;

    // Разрешение перемещения (эффективно и безопасно)
    SessionManager(SessionManager&&) noexcept;
    SessionManager& operator=(SessionManager&&) noexcept;

    /**
     * @brief Получить глобальный экземпляр менеджера
     * @return Ссылка на синглтон SessionManager
     *
     * @note Thread-safe с C++11 (магическая статика)
     */
    static SessionManager& GetInstance();

    /**
     * @brief Инициализировать менеджер сессий
     * @return true если инициализация успешна, false в противном случае
     *
     * Вызывает инициализацию всех внутренних компонентов:
     * - Запускает worker thread
     * - Инициализирует пул сессий
     * - Готовит систему к работе
     *
     * @note Должен быть вызван перед любыми другими операциями
     */
    bool Initialize();

    /**
     * @brief Открыть новую сессию на указанном токене
     * @param type Тип токена (RUTOKEN, ETOKEN, PCSC_SMARTCARD и т.д.)
     * @param pin PIN-код пользователя (4-8 символов)
     * @param library_path Путь к PKCS#11 библиотеке (может быть пустым для PC/SC)
     * @return SessionId > 0 при успехе, 0 при ошибке
     *
     * Процесс открытия сессии:
     * 1. Получение или создание модуля для данного типа токена
     * 2. Инициализация модуля (если требуется)
     * 3. Получение списка доступных токенов
     * 4. Выбор первого доступного слота
     * 5. Попытка взять сессию из пула
     * 6. Если пул пуст - создание новой сессии через модуль
     *
     * @note Результат >0 гарантирует валидную сессию
     */
    SessionId OpenSession(TokenType type,
                          const std::string& pin,
                          const std::string& library_path = "");

    /**
     * @brief Закрыть сессию
     * @param session_id ID сессии, полученный от OpenSession
     *
     * Уменьшает счетчик ссылок на сессию.
     * При достижении нуля:
     * - Если в пуле есть место - сессия переводится в IDLE состояние
     * - Если пул переполнен - сессия закрывается реально через модуль
     *
     * @note Безопасно вызывать с невалидным session_id (ничего не произойдет)
     */
    void CloseSession(SessionId session_id);

    /**
     * @brief Получить список всех доступных токенов
     * @return Вектор с информацией о подключенных токенах
     *
     * Опрашивает все инициализированные модули и собирает информацию
     * о доступных токенах. Используется для:
     * - Отображения в GUI
     * - Выбора токена пользователем
     * - Мониторинга состояния
     */
    std::vector<TokenInfo> GetAvailableTokens();

    /**
     * @brief Получить статистику работы менеджера
     * @return JSON-строка со статистикой
     *
     * Поля статистики:
     * - total_sessions: общее количество сессий
     * - active_modules: количество загруженных модулей
     * - request_queue: размер очереди запросов
     *
     * Используется для мониторинга и отладки.
     */
    std::string GetStatistics();

    /**
     * @brief Периодическая очистка истекших сессий
     *
     * Должен вызываться регулярно (например, по таймеру раз в минуту).
     * Удаляет сессии, которые:
     * - Превысили максимальное время жизни (1 час)
     * - Были неактивны больше 5 минут
     * - Находятся в состоянии EXPIRED
     */
    void PeriodicCleanup();

    /**
     * @brief Инвалидировать все сессии на указанном слоте
     * @param slot_id ID слота (например, при извлечении токена)
     *
     * Вызывается SlotManager при обнаружении извлечения токена.
     * Помечает все сессии на этом слоте как EXPIRED.
     * Следующая операция с такой сессией вернет ERR_SESSION_ERROR.
     */
    void InvalidateSlotSessions(SlotId slot_id);
};

} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_SESSION_MANAGER_H