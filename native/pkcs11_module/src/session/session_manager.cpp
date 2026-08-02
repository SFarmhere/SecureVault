// ============================================================================
// SecureVault - Менеджер сессий PKCS#11
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Централизованное управление всеми сессиями с токенами.
//   Обеспечивает многопоточный доступ, пул сессий, таймауты и восстановление.
// ============================================================================

#include "../../include/pkcs11_api.h"
#include "../adapters/pkcs11_helpers.h"
#include "../../include/session_types.h"
#include "../../include/token_types.h"
#include "session_manager.h"

#include <mutex>
#include <map>
#include <queue>
#include <thread>
#include <chrono>
#include <atomic>
#include <condition_variable>
#include <memory>
#include <future>
#include <sstream>
#include <functional>
#include <string>
#include <vector>
#include <cstdint>

namespace securevault {
namespace pkcs11 {

// ============================================================================
// ВНУТРЕННИЕ СТРУКТУРЫ ДАННЫХ
// ============================================================================

/**
 * @brief Внутреннее состояние сессии в пуле (отличается от SessionState из session_types.h)
 */
enum class PoolSessionState : uint8_t {
    INVALID = 0,    ///< Невалидная сессия
    ACTIVE,         ///< Сессия активна, можно использовать
    IDLE,           ///< Сессия в пуле, готова к повторному использованию
    BUSY,           ///< Сессия занята операцией
    EXPIRED,        ///< Сессия истекла, требует перелогина
    ERROR           ///< Сессия в ошибочном состоянии
};

/**
 * @brief Внутренний контекст сессии
 */
struct SessionContext {
    // Реальные данные от токена
    SessionId session_id{0};           ///< Внешний ID сессии
    SlotId slot_id{0};                 ///< ID слота
    TokenType token_type{TokenType::UNKNOWN}; ///< Тип токена

    // Управление
    PoolSessionState state{PoolSessionState::INVALID};
    std::thread::id owner_thread;      ///< ID потока-владельца (для BUSY)
    int ref_count{0};                  ///< Счетчик ссылок
    int error_count{0};                ///< Счетчик ошибок подряд

    // Временные метки
    int64_t created_ms{0};             ///< Время создания
    int64_t last_used_ms{0};           ///< Время последнего использования
    int64_t expires_ms{0};             ///< Время истечения
};

/**
 * @brief Запрос на операцию с сессией
 */
struct SessionRequest {
    SessionId session_id{0};                               ///< ID сессии
    std::function<TokenResult()> operation;               ///< Операция
    std::promise<TokenResult> promise;                    ///< Для получения результата
};

// ============================================================================
// РЕАЛЬНАЯ РЕАЛИЗАЦИЯ (СКРЫТАЯ ЗА PIMPL)
// ============================================================================

class SessionManagerImpl {
private:
    // ------------------------------------------------------------------------
    // ПОЛЯ КЛАССА
    // ------------------------------------------------------------------------

    mutable std::recursive_mutex mutex_;

    // Карта модулей: тип токена -> модуль
    std::map<TokenType, std::unique_ptr<ITokenModule>> modules_;

    // Активные сессии: session_id -> контекст
    std::map<SessionId, SessionContext> sessions_;

    // Пул свободных сессий (по slot_id)
    std::map<SlotId, std::queue<SessionId>> idle_pool_;

    // Очередь запросов на операции
    std::queue<SessionRequest> request_queue_;
    std::condition_variable_any queue_cv_;
    std::thread worker_thread_;
    std::atomic<bool> running_{true};

    // Генерация ID
    std::atomic<SessionId> next_session_id_{1000};

    // Настройки
    static constexpr auto SESSION_TIMEOUT = std::chrono::minutes(5);
    static constexpr auto SESSION_MAX_LIFETIME = std::chrono::hours(1);
    static constexpr int MAX_ERROR_COUNT = 3;
    static constexpr int MAX_IDLE_SESSIONS_PER_SLOT = 5;

    // ------------------------------------------------------------------------
    // ПРИВАТНЫЕ МЕТОДЫ
    // ------------------------------------------------------------------------

    /**
     * @brief Получить или создать модуль для токена
     */
    ITokenModule* GetOrCreateModule(TokenType type) {
        auto it = modules_.find(type);
        if (it != modules_.end()) {
            return it->second.get();
        }

        auto module = CreateTokenModule(type);
        if (!module) {
            return nullptr;
        }

        ITokenModule* ptr = module.get();
        modules_[type] = std::move(module);
        return ptr;
    }

    /**
     * @brief Воркер для асинхронных операций
     */
    void WorkerThread() {
        while (running_) {
            SessionRequest request;
            {
                std::unique_lock<std::recursive_mutex> lock(mutex_);
                queue_cv_.wait_for(lock, std::chrono::seconds(1), [this] {
                    return !request_queue_.empty() || !running_;
                });

                if (!running_) break;
                if (request_queue_.empty()) continue;

                request = std::move(request_queue_.front());
                request_queue_.pop();
            }

            auto it = sessions_.find(request.session_id);
            if (it != sessions_.end()) {
                it->second.state = PoolSessionState::BUSY;
                it->second.owner_thread = std::this_thread::get_id();

                TokenResult result = request.operation();

                if (result == TokenResult::SUCCESS) {
                    it->second.error_count = 0;
                    it->second.last_used_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count();
                    it->second.state = PoolSessionState::IDLE;
                } else {
                    it->second.error_count++;
                    if (it->second.error_count >= MAX_ERROR_COUNT) {
                        it->second.state = PoolSessionState::ERROR;
                    } else {
                        it->second.state = PoolSessionState::IDLE;
                    }
                }

                request.promise.set_value(result);
            } else {
                request.promise.set_value(TokenResult::ERR_SESSION_ERROR);
            }
        }
    }

    /**
     * @brief Очистить истекшие сессии
     */
    void CleanupExpiredSessions() {
        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        for (auto it = sessions_.begin(); it != sessions_.end();) {
            bool expired = false;

            if (it->second.state == PoolSessionState::EXPIRED) {
                expired = true;
            } else if (now_ms > it->second.expires_ms) {
                expired = true;
            } else if (it->second.state == PoolSessionState::IDLE &&
                       now_ms > it->second.last_used_ms +
                       std::chrono::duration_cast<std::chrono::milliseconds>(SESSION_TIMEOUT).count()) {
                expired = true;
            }

            if (expired) {
                // Удаляем из пула
                auto& pool = idle_pool_[it->second.slot_id];
                std::queue<SessionId> new_pool;
                while (!pool.empty()) {
                    if (pool.front() != it->first) {
                        new_pool.push(pool.front());
                    }
                    pool.pop();
                }
                idle_pool_[it->second.slot_id] = new_pool;

                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

    /**
     * @brief Получить свободную сессию из пула
     */
    SessionId GetIdleSession(SlotId slot_id) {
        auto& pool = idle_pool_[slot_id];

        while (!pool.empty()) {
            SessionId session_id = pool.front();
            pool.pop();

            auto it = sessions_.find(session_id);
            if (it != sessions_.end() && it->second.state == PoolSessionState::IDLE) {
                it->second.state = PoolSessionState::ACTIVE;
                it->second.last_used_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count();
                return session_id;
            }
        }

        return 0;  // 0 = невалидная сессия
    }

public:
    // ------------------------------------------------------------------------
    // КОНСТРУКТОР/ДЕСТРУКТОР
    // ------------------------------------------------------------------------

    SessionManagerImpl() {
        worker_thread_ = std::thread(&SessionManagerImpl::WorkerThread, this);
    }

    ~SessionManagerImpl() {
        running_ = false;
        queue_cv_.notify_all();
        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }

        // Закрываем все сессии (реальные модули сами закроют свои сессии)
        sessions_.clear();
        idle_pool_.clear();
        modules_.clear();
    }

    // ------------------------------------------------------------------------
    // ПУБЛИЧНЫЕ МЕТОДЫ
    // ------------------------------------------------------------------------

    /**
     * @brief Открыть новую сессию
     */
    SessionId OpenSession(TokenType type, const std::string& pin, const std::string& library_path) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        // Получаем модуль для токена
        ITokenModule* module = GetOrCreateModule(type);
        if (!module) {
            return 0;
        }

        // Инициализируем модуль если нужно
        if (!module->IsInitialized()) {
            TokenResult result = module->Initialize(library_path);
            if (result != TokenResult::SUCCESS) {
                return 0;
            }
        }

        // Получаем список доступных токенов
        auto tokens = module->GetAvailableTokens();
        if (tokens.empty()) {
            return 0;
        }

        // Берем первый доступный слот (упрощенно)
        SlotId slot_id = 0;  // TODO: получить реальный slot_id из tokens[0]

        // Пробуем взять сессию из пула
        SessionId session_id = GetIdleSession(slot_id);
        if (session_id != 0) {
            auto& ctx = sessions_[session_id];
            ctx.ref_count++;
            return session_id;
        }

        // Создаем новую сессию через модуль
        SessionId new_session_id = module->OpenSession(slot_id, pin);
        if (new_session_id <= 0) {
            return 0;
        }

        // Создаем контекст
        SessionContext ctx;
        ctx.session_id = new_session_id;
        ctx.slot_id = slot_id;
        ctx.token_type = type;
        ctx.state = PoolSessionState::ACTIVE;
        ctx.ref_count = 1;
        ctx.error_count = 0;
        ctx.created_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        ctx.last_used_ms = ctx.created_ms;
        ctx.expires_ms = ctx.created_ms +
            std::chrono::duration_cast<std::chrono::milliseconds>(SESSION_MAX_LIFETIME).count();

        SessionId internal_id = next_session_id_++;
        sessions_[internal_id] = ctx;

        return internal_id;
    }

    /**
     * @brief Закрыть сессию
     */
    void CloseSession(SessionId session_id) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return;
        }

        it->second.ref_count--;

        if (it->second.ref_count <= 0) {
            // Помещаем в пул свободных сессий
            if (idle_pool_[it->second.slot_id].size() < MAX_IDLE_SESSIONS_PER_SLOT) {
                it->second.state = PoolSessionState::IDLE;
                it->second.ref_count = 0;
                idle_pool_[it->second.slot_id].push(session_id);
            } else {
                // Слишком много свободных сессий - закрываем реальную сессию
                auto module_it = modules_.find(it->second.token_type);
                if (module_it != modules_.end()) {
                    module_it->second->CloseSession(it->second.session_id);
                }
                sessions_.erase(it);
            }
        }
    }

    /**
     * @brief Выполнить операцию с сессией
     */
    template<typename Func>
    TokenResult ExecuteOperation(SessionId session_id, Func operation) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            return TokenResult::ERR_SESSION_ERROR;
        }

        // Проверяем состояние сессии
        if (it->second.state == PoolSessionState::EXPIRED ||
            it->second.state == PoolSessionState::ERROR) {
            return TokenResult::ERR_SESSION_ERROR;
        }

        // Создаем запрос
        std::promise<TokenResult> promise;
        auto future = promise.get_future();

        SessionRequest request;
        request.session_id = session_id;
        request.operation = operation;
        request.promise = std::move(promise);

        request_queue_.push(std::move(request));
        queue_cv_.notify_one();

        // Ждем результат (с таймаутом)
        if (future.wait_for(std::chrono::seconds(30)) == std::future_status::timeout) {
            return TokenResult::ERR_TIMEOUT;
        }

        return future.get();
    }

    /**
     * @brief Получить список доступных токенов
     */
    std::vector<TokenInfo> GetAvailableTokens() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        std::vector<TokenInfo> result;

        for (const auto& module_pair : modules_) {
            if (module_pair.second && module_pair.second->IsInitialized()) {
                auto tokens = module_pair.second->GetAvailableTokens();
                result.insert(result.end(), tokens.begin(), tokens.end());
            }
        }

        return result;
    }

    /**
     * @brief Инвалидировать все сессии на слоте
     */
    void InvalidateSlotSessions(SlotId slot_id) {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        for (auto& pair : sessions_) {
            if (pair.second.slot_id == slot_id) {
                pair.second.state = PoolSessionState::EXPIRED;
            }
        }

        idle_pool_.erase(slot_id);
    }

    /**
     * @brief Получить статистику
     */
    std::string GetStatistics() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);

        std::stringstream ss;
        ss << "{\n";
        ss << "  \"total_sessions\": " << sessions_.size() << ",\n";
        ss << "  \"active_modules\": " << modules_.size() << ",\n";
        ss << "  \"request_queue\": " << request_queue_.size() << "\n";
        ss << "}";

        return ss.str();
    }

    /**
     * @brief Периодическая очистка
     */
    void PeriodicCleanup() {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        CleanupExpiredSessions();
    }
};

// ============================================================================
// РЕАЛИЗАЦИЯ ФАСАДА SESSIONMANAGER (PIMPL)
// ============================================================================

SessionManager::SessionManager() : impl_(std::make_unique<SessionManagerImpl>()) {}

SessionManager::~SessionManager() = default;

SessionManager::SessionManager(SessionManager&&) noexcept = default;
SessionManager& SessionManager::operator=(SessionManager&&) noexcept = default;

SessionManager& SessionManager::GetInstance() {
    static SessionManager instance;
    return instance;
}

SessionId SessionManager::OpenSession(TokenType type, const std::string& pin,
                                      const std::string& library_path) {
    return impl_->OpenSession(type, pin, library_path);
}

void SessionManager::CloseSession(SessionId session_id) {
    impl_->CloseSession(session_id);
}

std::vector<TokenInfo> SessionManager::GetAvailableTokens() {
    return impl_->GetAvailableTokens();
}

std::string SessionManager::GetStatistics() {
    return impl_->GetStatistics();
}

void SessionManager::PeriodicCleanup() {
    impl_->PeriodicCleanup();
}

void SessionManager::InvalidateSlotSessions(SlotId slot_id) {
    impl_->InvalidateSlotSessions(slot_id);
}

} // namespace pkcs11
} // namespace securevault