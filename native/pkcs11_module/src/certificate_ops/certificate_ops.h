// ============================================================================
// SecureVault - Заголовочный файл операций с сертификатами
// Версия: 2.0.0
// (c) 2026 SecureVault Contributors
// Лицензия: GNU GPL v3
//
// НАЗНАЧЕНИЕ:
//   Объявление функций импорта, экспорта и парсинга X.509 сертификатов
//   на аппаратных токенах. Реализация в certificate_import.cpp,
//   certificate_export.cpp, x509_parse.cpp.
//
// СВЯЗЬ С ДРУГИМИ МОДУЛЯМИ:
//   - ITokenModule::ImportCertificate(), ExportCertificate(), ListCertificates()
//   - SessionManager - управление сессиями
//   - Python bindings - высокоуровневый доступ
// ============================================================================

#ifndef SECUREVAULT_PKCS11_CERTIFICATE_OPS_H
#define SECUREVAULT_PKCS11_CERTIFICATE_OPS_H

#include <string>
#include <vector>
#include <memory>

#include "../../include/pkcs11_api.h"
#include "../../include/session_types.h"
#include "../../include/token_types.h"

namespace securevault {
namespace pkcs11 {

// ============================================================================
// ИМПОРТ СЕРТИФИКАТОВ
// ============================================================================

/**
 * @brief Импортировать X.509 сертификат на токен
 * @param module Модуль токена (ITokenModule)
 * @param session_id ID сессии
 * @param cert_data Данные сертификата (DER или PEM)
 * @param label Метка сертификата
 * @param key_id ID связанного ключа (опционально)
 * @return Результат операции
 */
TokenResult ImportCertificate(ITokenModule& module,
                              SessionId session_id,
                              const std::vector<uint8_t>& cert_data,
                              const std::string& label,
                              const std::string& key_id = "");

/**
 * @brief Импортировать сертификат из PEM-файла
 * @param module Модуль токена
 * @param session_id ID сессии
 * @param pem_path Путь к PEM-файлу
 * @param label Метка сертификата
 * @return Результат операции
 */
TokenResult ImportCertificateFromFile(ITokenModule& module,
                                      SessionId session_id,
                                      const std::string& pem_path,
                                      const std::string& label);

// ============================================================================
// ЭКСПОРТ СЕРТИФИКАТОВ
// ============================================================================

/**
 * @brief Экспортировать сертификат с токена
 * @param module Модуль токена
 * @param session_id ID сессии
 * @param cert_id Идентификатор сертификата
 * @param format Формат: "DER" или "PEM"
 * @return Данные сертификата или пустой вектор при ошибке
 */
std::vector<uint8_t> ExportCertificate(ITokenModule& module,
                                       SessionId session_id,
                                       const std::string& cert_id,
                                       const std::string& format = "DER");

/**
 * @brief Экспортировать сертификат в файл
 * @param module Модуль токена
 * @param session_id ID сессии
 * @param cert_id Идентификатор сертификата
 * @param output_path Путь к выходному файлу
 * @param format Формат: "DER" или "PEM"
 * @return true если успешно
 */
bool ExportCertificateToFile(ITokenModule& module,
                             SessionId session_id,
                             const std::string& cert_id,
                             const std::string& output_path,
                             const std::string& format = "PEM");

// ============================================================================
// ПАРСИНГ X.509
// ============================================================================

/**
 * @brief Разобрать X.509 сертификат из DER-данных
 * @param der_data Данные сертификата в DER-формате
 * @return Информация о сертификате
 *
 * Заполняет поля CertificateInfo: subject, issuer, serial_number,
 * not_before_ms, not_after_ms, signature_algorithm, version.
 */
CertificateInfo ParseX509Certificate(const std::vector<uint8_t>& der_data);

/**
 * @brief Конвертировать PEM в DER
 * @param pem_data Данные сертификата в PEM-формате
 * @return Данные в DER-формате или пустой вектор при ошибке
 */
std::vector<uint8_t> PemToDer(const std::string& pem_data);

/**
 * @brief Конвертировать DER в PEM
 * @param der_data Данные сертификата в DER-формате
 * @return Данные в PEM-формате или пустая строка при ошибке
 */
std::string DerToPem(const std::vector<uint8_t>& der_data);

/**
 * @brief Проверить срок действия сертификата
 * @param cert Информация о сертификате
 * @param now_ms Текущее время в миллисекундах (0 = использовать системное)
 * @return true если сертификат действителен
 */
bool IsCertificateValid(const CertificateInfo& cert, int64_t now_ms = 0);

} // namespace pkcs11
} // namespace securevault

#endif // SECUREVAULT_PKCS11_CERTIFICATE_OPS_H