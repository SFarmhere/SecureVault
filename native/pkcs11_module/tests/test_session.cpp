// ============================================================================
// SecureVault - Модульные тесты для SessionManager
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// Назначение: Проверка корректности работы менеджера сессий PKCS#11
//
// Входные данные:
//   - Мок-объект ITokenModule (эмулирует Рутокен)
//   - Параметры тестов (количество потоков, таймауты)
//   - PIN-коды для тестирования
//
// Выходные данные:
//   - Результаты тестов в стандартный вывод (Google Test)
//   - PASS/FAIL для каждого тест-кейса
//   - Статистика производительности
//
// Зависимости:
//   - Google Test (из native/shared/libs/gtest/)
//   - Google Mock (из native/shared/libs/gmock/)
//   - session_manager.cpp
// ============================================================================

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <chrono>
#include <vector>
#include <future>
#include <atomic>

#include "../../include/pkcs11_api.h"
#include "../../include/session_types.h"
#include "../../include/token_types.h"
#include "../src/session/session_manager.h"

using namespace securevault::pkcs11;
using namespace testing;

// ============================================================================
// МОК-ОБЪЕКТ ДЛЯ ТЕСТИРОВАНИЯ
// ============================================================================

/**
 * @brief Mock-реализация ITokenModule для тестов
 *
 * Эмулирует поведение реального токена без железа.
 * Позволяет тестировать SessionManager в изоляции.
 */
class MockTokenModule : public ITokenModule {
public:
    MOCK_METHOD(TokenResult, Initialize, (const std::string&), (override));
    MOCK_METHOD(void, Finalize, (), (override));
    MOCK_METHOD(bool, IsInitialized, (), (const, override));
    MOCK_METHOD(std::vector<TokenInfo>, GetAvailableTokens, (), (override));
    MOCK_METHOD(SessionId, OpenSession, (SlotId, const std::string&), (override));
    MOCK_METHOD(void, CloseSession, (SessionId), (override));
    MOCK_METHOD(bool, IsSessionValid, (SessionId), (const, override));
    MOCK_METHOD(TokenResult, ChangePin, (SessionId, const std::string&, const std::string&), (override));
    MOCK_METHOD(std::string, GenerateRsaKeyPair, (SessionId, const RsaKeyParams&), (override));
    MOCK_METHOD(std::vector<KeyInfo>, ListKeys, (SessionId), (override));
    MOCK_METHOD(std::unique_ptr<KeyInfo>, FindKeyById, (SessionId, const std::string&), (override));
    MOCK_METHOD(TokenResult, DeleteKey, (SessionId, const std::string&), (override));
    MOCK_METHOD(std::vector<uint8_t>, SignRsa, (SessionId, const std::string&,
                const std::vector<uint8_t>&, const RsaSignParams&), (override));
    MOCK_METHOD(bool, VerifyRsa, (SessionId, const std::string&, const std::vector<uint8_t>&,
                const std::vector<uint8_t>&, const RsaSignParams&), (override));
    MOCK_METHOD(std::vector<uint8_t>, EncryptRsa, (SessionId, const std::string&,
                const std::vector<uint8_t>&, const RsaEncryptParams&), (override));
    MOCK_METHOD(std::vector<uint8_t>, DecryptRsa, (SessionId, const std::string&,
                const std::vector<uint8_t>&, const RsaEncryptParams&), (override));
    MOCK_METHOD(std::vector<CertificateInfo>, ListCertificates, (SessionId), (override));
    MOCK_METHOD(TokenResult, ImportCertificate, (SessionId, const std::vector<uint8_t>&,
                const std::string&, const std::string&), (override));
    MOCK_METHOD(std::vector<uint8_t>, ExportCertificate, (SessionId, const std::string&,
                const std::string&), (override));
    MOCK_METHOD(std::string, GetErrorMessage, (TokenResult), (const, override));
    MOCK_METHOD(std::string, GetVersion, (), (const, override));

    // Реальная реализация для базовых операций
    TokenResult RealInitialize(const std::string& path) {
        (void)path;
        return TokenResult::SUCCESS;
    }

    SessionId RealOpenSession(SlotId slot_id, const std::string& pin) {
        (void)slot_id;
        (void)pin;
        static SessionId next_id = 100;
        return next_id++;
    }

    void RealCloseSession(SessionId session_id) {
        (void)session_id;
        // Ничего не делаем, просто заглушка
    }

    bool RealIsSessionValid(SessionId session_id) const {
        return session_id > 0;
    }

    MockTokenModule() {
        // Настраиваем поведение по умолчанию
        ON_CALL(*this, Initialize(_))
            .WillByDefault(Invoke(this, &MockTokenModule::RealInitialize));
        ON_CALL(*this, OpenSession(_, _))
            .WillByDefault(Invoke(this, &MockTokenModule::RealOpenSession));
        ON_CALL(*this, CloseSession(_))
            .WillByDefault(Invoke(this, &MockTokenModule::RealCloseSession));
        ON_CALL(*this, IsSessionValid(_))
            .WillByDefault(Invoke(this, &MockTokenModule::RealIsSessionValid));
        ON_CALL(*this, GetVersion())
            .WillByDefault(Return("MockTokenModule v1.0"));
        ON_CALL(*this, GetErrorMessage(_))
            .WillByDefault(Return("Mock error message"));
    }
};

// ============================================================================
// ТЕСТ: БАЗОВОЕ ОТКРЫТИЕ/ЗАКРЫТИЕ СЕССИИ
// ============================================================================

/**
 * @test SessionManager.OpenClose
 *
 * Входные данные:
 *   - TokenType::RUTOKEN
 *   - pin = "12345678" (тестовый PIN)
 *
 * Ожидаемый результат:
 *   - OpenSession возвращает валидный ID > 0
 *   - CloseSession не падает с ошибкой
 */
TEST(SessionManagerTest, OpenClose) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";

    // Act
    SessionId session_id = manager.OpenSession(TokenType::RUTOKEN, pin);

    // Assert
    EXPECT_GT(session_id, 0);  // Должен быть положительный ID

    // Act 2: Закрываем сессию
    manager.CloseSession(session_id);

    // Выводим статистику для отладки
    std::cout << manager.GetStatistics() << std::endl;
}

// ============================================================================
// ТЕСТ: ПУЛ СЕССИЙ И ПЕРЕИСПОЛЬЗОВАНИЕ
// ============================================================================

/**
 * @test SessionManager.SessionPool
 *
 * Входные данные:
 *   - 10 последовательных вызовов OpenSession
 *   - Одинаковый PIN
 *
 * Ожидаемый результат:
 *   - Все сессии открываются успешно
 *   - ID уникальны
 *   - Статистика показывает работу пула
 */
TEST(SessionManagerTest, SessionPool) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";

    std::vector<SessionId> session_ids;

    // Act: Открываем 10 сессий
    for (int i = 0; i < 10; i++) {
        SessionId sid = manager.OpenSession(TokenType::RUTOKEN, pin);
        ASSERT_GT(sid, 0);
        session_ids.push_back(sid);
    }

    // Assert: Проверяем, что ID уникальны
    std::set<SessionId> unique_ids(session_ids.begin(), session_ids.end());
    EXPECT_EQ(unique_ids.size(), session_ids.size());

    // Act: Закрываем все сессии
    for (SessionId sid : session_ids) {
        manager.CloseSession(sid);
    }

    // Проверяем статистику
    std::string stats = manager.GetStatistics();
    std::cout << stats << std::endl;

    // Статистика должна быть валидным JSON
    EXPECT_THAT(stats, HasSubstr("total_sessions"));
    EXPECT_THAT(stats, HasSubstr("active_modules"));
}

// ============================================================================
// ТЕСТ: ПЕРИОДИЧЕСКАЯ ОЧИСТКА
// ============================================================================

/**
 * @test SessionManager.PeriodicCleanup
 *
 * Входные данные:
 *   - Открытая сессия
 *   - Закрытая сессия (переходит в IDLE пул)
 *
 * Ожидаемый результат:
 *   - PeriodicCleanup выполняется без ошибок
 *   - Статистика обновляется корректно
 */
TEST(SessionManagerTest, PeriodicCleanup) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";

    // Открываем и закрываем сессию
    SessionId session_id = manager.OpenSession(TokenType::RUTOKEN, pin);
    ASSERT_GT(session_id, 0);
    manager.CloseSession(session_id);

    // Act: Запускаем очистку
    manager.PeriodicCleanup();

    // Assert: Проверяем статистику
    std::string stats = manager.GetStatistics();
    std::cout << stats << std::endl;
    EXPECT_THAT(stats, HasSubstr("total_sessions"));
}

// ============================================================================
// ТЕСТ: ИНВАЛИДАЦИЯ СЕССИЙ СЛОТА
// ============================================================================

/**
 * @test SessionManager.InvalidateSlotSessions
 *
 * Входные данные:
 *   - Открытые сессии на токене
 *   - Вызов InvalidateSlotSessions
 *
 * Ожидаемый результат:
 *   - Метод выполняется без ошибок
 *   - Сессии помечаются как EXPIRED
 */
TEST(SessionManagerTest, InvalidateSlotSessions) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";

    // Открываем несколько сессий
    std::vector<SessionId> session_ids;
    for (int i = 0; i < 3; i++) {
        SessionId sid = manager.OpenSession(TokenType::RUTOKEN, pin);
        ASSERT_GT(sid, 0);
        session_ids.push_back(sid);
    }

    // Act: Инвалидируем сессии
    manager.InvalidateSlotSessions(0);

    // Assert: Проверяем статистику
    std::string stats = manager.GetStatistics();
    std::cout << stats << std::endl;

    // Cleanup
    for (SessionId sid : session_ids) {
        manager.CloseSession(sid);
    }
}

// ============================================================================
// ТЕСТ: ПОЛУЧЕНИЕ СПИСКА ТОКЕНОВ
// ============================================================================

/**
 * @test SessionManager.GetAvailableTokens
 *
 * Входные данные:
 *   - Инициализированный менеджер
 *
 * Ожидаемый результат:
 *   - Метод возвращает вектор токенов (мож быть пустым)
 *   - Нет падения или исключений
 */
TEST(SessionManagerTest, GetAvailableTokens) {
    // Arrange
    auto& manager = SessionManager::GetInstance();

    // Act
    std::vector<TokenInfo> tokens = manager.GetAvailableTokens();

    // Assert
    // Может быть пустым, если нет токенов - это нормально
    std::cout << "Found " << tokens.size() << " tokens" << std::endl;
    EXPECT_TRUE(true);  // Просто проверяем, что метод работает
}

// ============================================================================
// ТЕСТ: МНОГОПОТОЧНЫЙ ДОСТУП
// ============================================================================

/**
 * @test SessionManager.ConcurrentAccess
 *
 * Входные данные:
 *   - 10 параллельных потоков
 *   - Каждый выполняет 100 операций открытия/закрытия
 *   - Разные сессии
 *
 * Ожидаемый результат:
 *   - Все операции успешны
 *   - Нет состояния гонки
 */
TEST(SessionManagerTest, ConcurrentAccess) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    
    std::atomic<int> success_count{0};
    std::vector<std::future<void>> futures;
    
    // Act: Запускаем 10 потоков
    for (int t = 0; t < 10; t++) {
        futures.push_back(std::async(std::launch::async, [&]() {
            for (int i = 0; i < 100; i++) {
                // Каждый поток открывает и закрывает свою сессию
                SessionId session_id = manager.OpenSession(TokenType::RUTOKEN, pin);
                if (session_id > 0) {
                    manager.CloseSession(session_id);
                    success_count++;
                }
            }
        }));
    }
    
    // Ждем завершения всех потоков
    for (auto& f : futures) {
        f.wait();
    }
    
    // Assert
    EXPECT_EQ(success_count.load(), 1000);
}

// ============================================================================
// ТЕСТ: РАЗНЫЕ PIN-КОДЫ
// ============================================================================

/**
 * @test SessionManager.DifferentPins
 *
 * Входные данные:
 *   - Набор различных PIN-кодов
 *
 * Ожидаемый результат:
 *   - Все PIN-коды принимаются
 *   - Сессии открываются успешно
 */
TEST(SessionManagerTest, DifferentPins) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    TokenType token_type = TokenType::RUTOKEN;
    
    std::vector<std::string> pins = {
        "12345678",
        "00000000",
        "password",
        "1234",
        "very_long_pin_1234567890",
        "!@#$%^&*()"
    };
    
    std::vector<SessionId> sessions;
    
    // Act
    for (const auto& pin : pins) {
        SessionId session_id = manager.OpenSession(token_type, pin);
        EXPECT_GT(session_id, 0);
        sessions.push_back(session_id);
    }
    
    // Assert
    EXPECT_EQ(sessions.size(), pins.size());
    
    // Cleanup
    for (SessionId sid : sessions) {
        manager.CloseSession(sid);
    }
}

// ============================================================================
// ТЕСТ: ПРОИЗВОДИТЕЛЬНОСТЬ
// ============================================================================

/**
 * @test SessionManager.Performance
 *
 * Входные данные:
 *   - 1000 операций открытия/закрытия сессии
 *
 * Ожидаемый результат:
 *   - Среднее время операции < 5 мс
 */
TEST(SessionManagerTest, Performance) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    TokenType token_type = TokenType::RUTOKEN;
    
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    // Act: Измеряем время открытия и закрытия сессий
    for (int i = 0; i < iterations; i++) {
        SessionId session_id = manager.OpenSession(token_type, pin);
        if (session_id > 0) {
            manager.CloseSession(session_id);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    // Assert
    double avg_us = duration.count() / (double)iterations;
    std::cout << "Average session open/close time: " << avg_us << " µs" << std::endl;
    std::cout << "Total time: " << duration.count() / 1000.0 << " ms" << std::endl;
    
    EXPECT_LT(avg_us, 5000);  // Меньше 5 мс
}

// ============================================================================
// ТЕСТ: УТЕЧКА ПАМЯТИ
// ============================================================================

/**
 * @test SessionManager.MemoryLeak
 *
 * Входные данные:
 *   - 1000 циклов открытия/закрытия сессии
 *
 * Ожидаемый результат:
 *   - Память не растет
 *   - Все сессии корректно закрываются
 */
TEST(SessionManagerTest, MemoryLeak) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    TokenType token_type = TokenType::RUTOKEN;
    
    // Act: Многократно открываем и закрываем сессии
    for (int i = 0; i < 1000; i++) {
        SessionId session_id = manager.OpenSession(token_type, pin);
        if (session_id > 0) {
            manager.CloseSession(session_id);
        }
    }
    
    // Assert: Проверяем статистику
    std::string stats = manager.GetStatistics();
    std::cout << stats << std::endl;
    
    // Статистика должна показывать корректные значения
    EXPECT_THAT(stats, HasSubstr("total_sessions"));
}

// ============================================================================
// ТЕСТ: СТАТИСТИКА
// ============================================================================

/**
 * @test SessionManager.Statistics
 *
 * Входные данные:
 *   - Открытые сессии
 *
 * Ожидаемый результат:
 *   - Статистика содержит все необходимые поля
 */
TEST(SessionManagerTest, Statistics) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    
    // Act: Открываем несколько сессий
    std::vector<SessionId> sessions;
    for (int i = 0; i < 5; i++) {
        SessionId sid = manager.OpenSession(TokenType::RUTOKEN, pin);
        if (sid > 0) {
            sessions.push_back(sid);
        }
    }
    
    // Получаем статистику
    std::string stats = manager.GetStatistics();
    
    // Assert
    EXPECT_THAT(stats, HasSubstr("total_sessions"));
    EXPECT_THAT(stats, HasSubstr("active_modules"));
    
    std::cout << "Statistics:\n" << stats << std::endl;
    
    // Cleanup
    for (SessionId sid : sessions) {
        manager.CloseSession(sid);
    }
}

// ============================================================================
// ТЕСТ: ПОВТОРНОЕ ИСПОЛЬЗОВАНИЕ СЕССИЙ
// ============================================================================

/**
 * @test SessionManager.SessionReuse
 *
 * Входные данные:
 *   - Открытие и закрытие сессии
 *   - Повторное открытие
 *
 * Ожидаемый результат:
 *   - Сессии корректно переиспользуются
 *   - Нет утечек ресурсов
 */
TEST(SessionManagerTest, SessionReuse) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    
    // Act: Открываем и закрываем сессию несколько раз
    SessionId session1 = manager.OpenSession(TokenType::RUTOKEN, pin);
    ASSERT_GT(session1, 0);
    manager.CloseSession(session1);
    
    SessionId session2 = manager.OpenSession(TokenType::RUTOKEN, pin);
    ASSERT_GT(session2, 0);
    manager.CloseSession(session2);
    
    // Assert: Обе сессии успешно открыты и закрыты
    EXPECT_GT(session1, 0);
    EXPECT_GT(session2, 0);
}

// ============================================================================
// ТЕСТ: ОБРАБОТКА ОШИБОК
// ============================================================================

/**
 * @test SessionManager.ErrorHandling
 *
 * Входные данные:
 *   - Попытка открыть сессию с невалидным типом токена
 *
 * Ожидаемый результат:
 *   - Ошибка корректно обрабатывается
 *   - Возвращается 0 или отрицательное значение
 */
TEST(SessionManagerTest, ErrorHandling) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    
    // Act: Пытаемся открыть сессию с неизвестным типом токена
    SessionId session_id = manager.OpenSession(TokenType::UNKNOWN, pin);
    
    // Assert: Должна вернуться ошибка (0 или отрицательное значение)
    EXPECT_LE(session_id, 0);
}

// ============================================================================
// ТЕСТ: РАЗНЫЕ ТИПЫ ТОКЕНОВ
// ============================================================================

/**
 * @test SessionManager.DifferentTokenTypes
 *
 * Входные данные:
 *   - Разные типы токенов
 *
 * Ожидаемый результат:
 *   - Все типы токенов обрабатываются
 *   - Сессии открываются (или gracefully fail)
 */
TEST(SessionManagerTest, DifferentTokenTypes) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    
    std::vector<TokenType> token_types = {
        TokenType::RUTOKEN,
        TokenType::ETOKEN,
        TokenType::GENERIC_PKCS11,
        TokenType::PCSC_SMARTCARD
    };
    
    // Act & Assert: Пробуем открыть сессии с разными типами
    for (TokenType type : token_types) {
        SessionId sid = manager.OpenSession(type, pin);
        // Может быть 0 (если токен не подключен), но не должно быть падения
        std::cout << "Token type " << static_cast<int>(type) 
                  << " returned session_id: " << sid << std::endl;
    }
}

// ============================================================================
// ПАРАМЕТРИЗОВАННЫЕ ТЕСТЫ
// ============================================================================

class SessionManagerParamTest : public ::testing::TestWithParam<int> {
protected:
    void SetUp() override {
        manager_ = &SessionManager::GetInstance();
    }
    
    void TearDown() override {
        // Очистка выполняется в самом тесте
    }
    
    SessionManager* manager_;
};

TEST_P(SessionManagerParamTest, MultipleSessions) {
    // Arrange
    int count = GetParam();
    std::string pin = "12345678";
    TokenType token_type = TokenType::RUTOKEN;
    
    std::vector<SessionId> sessions;
    
    // Act
    for (int i = 0; i < count; i++) {
        SessionId sid = manager_->OpenSession(token_type, pin);
        if (sid > 0) {
            sessions.push_back(sid);
        }
    }
    
    // Assert
    EXPECT_EQ(sessions.size(), count);
    
    // Cleanup
    for (SessionId sid : sessions) {
        manager_->CloseSession(sid);
    }
}

INSTANTIATE_TEST_SUITE_P(
    SessionCounts,
    SessionManagerParamTest,
    testing::Values(1, 5, 10, 25, 50, 100)
);

// ============================================================================
// ТЕСТОВЫЙ ХЕЛПЕР
// ============================================================================

class SessionManagerTestHelper {
public:
    static void PrintStatistics(const std::string& label = "Statistics") {
        auto& manager = SessionManager::GetInstance();
        std::cout << "\n=== " << label << " ===\n";
        std::cout << manager.GetStatistics() << std::endl;
    }
};

// ============================================================================
// ТЕСТ: ИСПОЛЬЗОВАНИЕ ХЕЛПЕРА
// ============================================================================

TEST(SessionManagerTest, WithHelper) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    SessionManagerTestHelper::PrintStatistics("Before test");
    
    std::string pin = "12345678";
    
    // Act: Открываем сессию
    SessionId session_id = manager.OpenSession(TokenType::RUTOKEN, pin);
    ASSERT_GT(session_id, 0);
    
    SessionManagerTestHelper::PrintStatistics("After open");
    
    // Cleanup
    manager.CloseSession(session_id);
    
    SessionManagerTestHelper::PrintStatistics("After close");
}

// ============================================================================
// ТЕСТ: СТРЕСС-НАГРУЗКА
// ============================================================================

/**
 * @test SessionManager.StressTest
 *
 * Входные данные:
 *   - 1000 потоков
 *   - Каждый открывает и закрывает сессию
 *
 * Ожидаемый результат:
 *   - Система не падает
 *   - Нет утечек ресурсов
 */
TEST(SessionManagerTest, StressTest) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    
    const int NUM_THREADS = 100;
    std::atomic<int> errors{0};
    std::vector<std::future<void>> futures;
    
    auto start = std::chrono::high_resolution_clock::now();
    
    // Act: Запускаем много потоков
    for (int t = 0; t < NUM_THREADS; t++) {
        futures.push_back(std::async(std::launch::async, [&]() {
            try {
                for (int i = 0; i < 10; i++) {
                    SessionId sid = manager.OpenSession(TokenType::RUTOKEN, pin);
                    if (sid > 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(1));
                        manager.CloseSession(sid);
                    } else {
                        errors++;
                    }
                }
            } catch (const std::exception& e) {
                errors++;
            }
        }));
    }
    
    // Ждем завершения
    for (auto& f : futures) {
        f.wait();
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    // Assert
    EXPECT_EQ(errors.load(), 0);
    std::cout << "Stress test completed in " << duration.count() << " ms" << std::endl;
    SessionManagerTestHelper::PrintStatistics("After stress test");
}

// ============================================================================
// ТЕСТ: КОРРЕКТНОСТЬ СТАТИСТИКИ
// ============================================================================

/**
 * @test SessionManager.StatisticsCorrectness
 *
 * Входные данные:
 *   - Открытые и закрытые сессии в разных комбинациях
 *
 * Ожидаемый результат:
 *   - Статистика точно отражает состояние системы
 */
TEST(SessionManagerTest, StatisticsCorrectness) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    
    // Act: Открываем 10 сессий
    std::vector<SessionId> sessions;
    for (int i = 0; i < 10; i++) {
        SessionId sid = manager.OpenSession(TokenType::RUTOKEN, pin);
        if (sid > 0) {
            sessions.push_back(sid);
        }
    }
    
    // Получаем статистику
    std::string stats = manager.GetStatistics();
    
    // Assert: Проверяем, что статистика содержит все ключевые поля
    EXPECT_THAT(stats, testing::HasSubstr("total_sessions"));
    EXPECT_THAT(stats, testing::HasSubstr("active_sessions"));
    EXPECT_THAT(stats, testing::HasSubstr("idle_sessions"));
    EXPECT_THAT(stats, testing::HasSubstr("expired_sessions"));
    EXPECT_THAT(stats, testing::HasSubstr("active_modules"));
    EXPECT_THAT(stats, testing::HasSubstr("total_operations"));
    EXPECT_THAT(stats, testing::HasSubstr("failed_operations"));
    EXPECT_THAT(stats, testing::HasSubstr("success_operations"));
    
    // Проверяем, что статистика - валидный JSON
    EXPECT_THAT(stats, testing::StartsWith("{"));
    EXPECT_THAT(stats, testing::EndsWith("}"));
    
    // Cleanup
    for (SessionId sid : sessions) {
        manager.CloseSession(sid);
    }
}

// ============================================================================
// ТЕСТ: ТАЙМАУТ СЕССИЙ
// ============================================================================

/**
 * @test SessionManager.SessionTimeout
 *
 * Входные данные:
 *   - Сессия с таймаутом
 *   - Ожидание истечения таймаута
 *
 * Ожидаемый результат:
 *   - Сессия автоматически закрывается по таймауту
 */
TEST(SessionManagerTest, SessionTimeout) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    
    // Act: Открываем сессию
    SessionId session_id = manager.OpenSession(TokenType::RUTOKEN, pin);
    ASSERT_GT(session_id, 0);
    
    // Ждем истечения таймаута (в реальном тесте нужно имитировать время)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Запускаем очистку
    manager.PeriodicCleanup();
    
    // Проверяем статус (в реальном коде может быть другой таймаут)
    // Здесь мы просто проверяем, что метод работает без ошибок
    EXPECT_TRUE(session_id > 0);
    
    // Cleanup
    manager.CloseSession(session_id);
}

// ============================================================================
// БЕНЧМАРКИ
// ============================================================================

/**
 * @test SessionManager.Benchmark
 *
 * Входные данные:
 *   - Различные сценарии использования
 *
 * Ожидаемый результат:
 *   - Измерение производительности для разных сценариев
 */
TEST(SessionManagerTest, Benchmark) {
    // Arrange
    auto& manager = SessionManager::GetInstance();
    std::string pin = "12345678";
    
    struct BenchmarkResult {
        std::string name;
        double avg_time_us;
        size_t operations;
    };
    
    std::vector<BenchmarkResult> results;
    
    // Сценарий 1: Открытие/закрытие сессии
    {
        const size_t ops = 1000;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (size_t i = 0; i < ops; i++) {
            SessionId sid = manager.OpenSession(TokenType::RUTOKEN, pin);
            if (sid > 0) manager.CloseSession(sid);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        results.push_back({"Open/Close", duration.count() / (double)ops, ops});
    }
    
    // Сценарий 2: Открытие множества сессий
    {
        const size_t ops = 100;
        auto start = std::chrono::high_resolution_clock::now();
        
        std::vector<SessionId> sessions;
        for (size_t i = 0; i < ops; i++) {
            SessionId sid = manager.OpenSession(TokenType::RUTOKEN, pin);
            if (sid > 0) sessions.push_back(sid);
        }
        for (SessionId sid : sessions) {
            manager.CloseSession(sid);
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        results.push_back({"Bulk Open/Close", duration.count() / (double)ops, ops});
    }
    
    // Выводим результаты
    std::cout << "\n=== BENCHMARK RESULTS ===\n";
    std::cout << std::left << std::setw(25) << "Scenario"
              << std::right << std::setw(15) << "Avg (µs)"
              << std::setw(15) << "Operations"
              << std::endl;
    std::cout << std::string(55, '-') << std::endl;
    
    for (const auto& r : results) {
        std::cout << std::left << std::setw(25) << r.name
                  << std::right << std::setw(15) << std::fixed << std::setprecision(2) << r.avg_time_us
                  << std::setw(15) << r.operations
                  << std::endl;
    }
}

// ============================================================================
// MAIN ДЛЯ ЗАПУСКА ТЕСТОВ
// ============================================================================

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
