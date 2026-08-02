// ============================================================================
// SecureVault - Заголовочный файл управления ключами
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Объявление функций управления ключами на аппаратных токенах:
//   список, поиск, удаление, экспорт публичных ключей.
//   Реализация находится в key_management.cpp.
//
// СВЯЗЬ С ДРУГИМИ МОДУЛЯМИ:
//   - ITokenModule::ListKeys(), FindKeyById(), DeleteKey()
//   - SessionManager - управление сессиями
//   - Python bindings - высокоуровневый доступ
// ============================================================================

#ifndef SECUREVAULT_PKCS11_KEY_MANAGEMENT_H
#define SECUREVAULT_PKCS11_KEY_MANAGEMENT_H

#include <string>
#include <vector>
#include <memory>

#include "../../include/pkcs11_api.h"
#include "../../include/session_types.h"
#include "../../include/token_types.h"

namespace securevault {
namespace pkcs11 {

// ============================================================================
// ФУНКЦИИ УПРАВЛЕНИЯ КЛЮЧАМИ
// ============================================================================

/**
 * @brief Получить список всех ключей на токене
 * @param module Модуль токена (ITokenModule)
 * @param session_id ID сессии
 * @return Вектор с информацией о ключах
 *
 * Возвращает как приватные, так и публичные ключи.
 * Пустой вектор при ошибке или отсутствии ключей.
 */
std::vector<KeyInfo> ListKeys(ITokenModule& module, SessionId session_id);

/**
 * @brief Найти ключ по ID
 * @param module Модуль токена
 * @param session_id ID сессии
 * @param key_id Идентификатор ключа (hex строка)
 * @return Информация о ключе или nullptr если не найден
 */
std::unique_ptr<KeyInfo> FindKeyById(ITokenModule& module,
                                     SessionId session_id,
                                     const std::string& key_id);

/**
 * @brief Найти ключ по метке (label)
 * @param module Модуль токена
 * @param session_id ID сессии
 * @param label Метка ключа
 * @return Информация о ключе или nullptr если не найден
 */
std::unique_ptr<KeyInfo> FindKeyByLabel(ITokenModule& module,
                                        SessionId session_id,
                                        const std::string& label);

/**
 * @brief Удалить ключ с токена
 * @param module Модуль токена
 * @param session_id ID сессии
 * @param key_id Идентификатор ключа
 * @return Результат операции
 */
TokenResult DeleteKey(ITokenModule& module,
                      SessionId session_id,
                      const std::string& key_id);

/**
 * @brief Экспортировать публичный ключ в PEM-формате
 * @param module Модуль токена
 * @param session_id ID сессии
 * @param key_id Идентификатор ключа
 * @return Публичный ключ в PEM или пустая строка при ошибке
 *
 * Экспортируется только публичная часть. Приватный ключ
 * никогда не покидает токен.
 */
std::string ExportPublicKeyPem(ITokenModule& module,
                               SessionId session_id,
                               const std::string& key_id);

/**
 * @brief Получить количество ключей на токене
 * @param module Модуль токена
 * @param session_id ID сессии
 * @return Количество ключей или -1 при ошибке
 */
int CountKeys(ITokenModule& module, SessionId session_id);

} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_KEY_MANAGEMENT_H