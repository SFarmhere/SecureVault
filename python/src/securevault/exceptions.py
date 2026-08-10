"""
SecureVault - Исключения проекта

Централизованное определение всех исключений, используемых в SecureVault.
Все исключения наследуются от базового SecureVaultError, что позволяет
обрабатывать их единообразно на верхнем уровне приложения.

Иерархия исключений:
- SecureVaultError (базовое)
  ├── KeyManagerError - ошибки менеджера ключей
  │   ├── KeyNotFoundError
  │   ├── KeyAlreadyExistsError
  │   ├── KeyExpiredError
  │   └── KeyDestroyedError
  ├── EncryptionError - ошибки шифрования
  │   ├── DecryptionError
  │   ├── IntegrityError
  │   └── InvalidEncryptedFileError
  ├── ContainerError - ошибки контейнеров
  │   ├── ContainerNotFoundError
  │   ├── ContainerAlreadyExistsError
  │   └── ContainerFullError
  ├── PolicyError - ошибки политик безопасности
  │   ├── PolicyNotFoundError
  │   ├── PolicyViolationError
  │   ├── AccessDeniedError
  │   └── OperationNotAllowedError
  ├── SessionError - ошибки сессий
  ├── AuditError - ошибки аудита
  ├── StorageError - ошибки хранения
  └── NativeError - ошибки нативных модулей
"""


class SecureVaultError(Exception):
    """
    Базовое исключение для всех ошибок SecureVault.

    Все специфичные исключения проекта наследуются от этого класса.
    Позволяет обрабатывать все ошибки единообразно:

    try:
        ...
    except SecureVaultError as e:
        # Обработка любой ошибки SecureVault
        ...
    """


# ============================================================================
# ОШИБКИ МЕНЕДЖЕРА КЛЮЧЕЙ
# ============================================================================


class KeyManagerError(SecureVaultError):
    """Ошибка менеджера ключей."""


class KeyNotFoundError(KeyManagerError):
    """Ключ не найден."""


class KeyAlreadyExistsError(KeyManagerError):
    """Ключ уже существует."""


class KeyExpiredError(KeyManagerError):
    """Ключ истек."""


class KeyDestroyedError(KeyManagerError):
    """Ключ был уничтожен."""


class TokenError(KeyManagerError):
    """Ошибка работы с токеном."""


class InsufficientSharesError(KeyManagerError):
    """Недостаточно shares для восстановления."""


# ============================================================================
# ОШИБКИ ШИФРОВАНИЯ
# ============================================================================


class EncryptionError(SecureVaultError):
    """Ошибка шифрования/дешифрования."""


class DecryptionError(EncryptionError):
    """Ошибка дешифрования."""


class IntegrityError(EncryptionError):
    """Ошибка проверки целостности."""


class UnsupportedProtectionLevelError(EncryptionError):
    """Неподдерживаемый уровень защиты."""


class InvalidEncryptedFileError(DecryptionError):
    """Невалидный формат зашифрованного файла."""


# ============================================================================
# ОШИБКИ КОНТЕЙНЕРОВ
# ============================================================================


class ContainerError(SecureVaultError):
    """Ошибка работы с контейнерами."""


class ContainerNotFoundError(ContainerError):
    """Контейнер не найден."""


class ContainerAlreadyExistsError(ContainerError):
    """Контейнер уже существует."""


class ContainerFullError(ContainerError):
    """Контейнер заполнен."""


class ContainerNotMountedError(ContainerError):
    """Контейнер не смонтирован."""


class ContainerSealedError(ContainerError):
    """Контейнер запечатан (только для чтения)."""


class FileNotFoundInContainerError(ContainerError):
    """Файл не найден в контейнере."""


class FileAlreadyExistsInContainerError(ContainerError):
    """Файл уже существует в контейнере."""


# ============================================================================
# ОШИБКИ ПОЛИТИК БЕЗОПАСНОСТИ
# ============================================================================


class PolicyError(SecureVaultError):
    """Базовое исключение для ошибок политик безопасности."""


class PolicyNotFoundError(PolicyError):
    """Политика не найдена."""


class PolicyAlreadyExistsError(PolicyError):
    """Политика уже существует."""


class PolicyViolationError(PolicyError):
    """Нарушение политики безопасности."""


class AccessDeniedError(PolicyError):
    """Доступ запрещен."""


class OperationNotAllowedError(PolicyError):
    """Операция не разрешена политикой."""


class PolicyExpiredError(PolicyError):
    """Политика истекла."""


class InvalidPolicyError(PolicyError):
    """Невалидная политика."""


# ============================================================================
# ОШИБКИ СЕССИЙ
# ============================================================================


class SessionError(SecureVaultError):
    """Ошибка управления сессиями."""


class SessionNotFoundError(SessionError):
    """Сессия не найдена."""


class SessionExpiredError(SessionError):
    """Сессия истекла."""


class SessionLockedError(SessionError):
    """Сессия заблокирована."""


# ============================================================================
# ОШИБКИ АУДИТА
# ============================================================================


class AuditError(SecureVaultError):
    """Ошибка аудита."""


class AuditLogError(AuditError):
    """Ошибка записи в журнал аудита."""


class AuditSignatureError(AuditError):
    """Ошибка подписи журнала аудита."""


# ============================================================================
# ОШИБКИ ХРАНЕНИЯ
# ============================================================================


class StorageError(SecureVaultError):
    """Ошибка хранения данных."""


class StorageBackendError(StorageError):
    """Ошибка бэкенда хранения."""


class CloudSyncError(StorageError):
    """Ошибка облачной синхронизации."""


# ============================================================================
# ОШИБКИ ВАЛИДАЦИИ
# ============================================================================


class ValidationError(SecureVaultError):
    """Ошибка валидации входных данных."""


# ============================================================================
# ОШИБКИ НАТИВНЫХ МОДУЛЕЙ
# ============================================================================


class NativeError(SecureVaultError):
    """Ошибка нативного модуля."""


class LibraryNotFoundError(NativeError):
    """Нативная библиотека не найдена."""


class LibraryLoadError(NativeError):
    """Ошибка загрузки библиотеки."""


class FunctionNotFoundError(NativeError):
    """Функция не найдена в библиотеке."""


class NativeModuleError(NativeError):
    """Ошибка выполнения нативного кода."""


# ============================================================================
# ОШИБКИ ЛИЦЕНЗИРОВАНИЯ
# ============================================================================


class LicensingError(SecureVaultError):
    """Ошибка лицензирования."""


class LicenseInvalidError(LicensingError):
    """Невалидная лицензия."""


class LicenseExpiredError(LicensingError):
    """Лицензия истекла."""


# ============================================================================
# ОШИБКИ ПЛАГИНОВ
# ============================================================================


class PluginError(SecureVaultError):
    """Ошибка системы плагинов."""


class PluginLoadError(PluginError):
    """Ошибка загрузки плагина."""


class PluginIsolationError(PluginError):
    """Нарушение изоляции плагина."""


# ============================================================================
# ЭКСПОРТ
# ============================================================================
__all__ = [
    # Базовое
    "SecureVaultError",
    # Ключи
    "KeyManagerError",
    "KeyNotFoundError",
    "KeyAlreadyExistsError",
    "KeyExpiredError",
    "KeyDestroyedError",
    "TokenError",
    "InsufficientSharesError",
    # Шифрование
    "EncryptionError",
    "DecryptionError",
    "IntegrityError",
    "UnsupportedProtectionLevelError",
    "InvalidEncryptedFileError",
    # Контейнеры
    "ContainerError",
    "ContainerNotFoundError",
    "ContainerAlreadyExistsError",
    "ContainerFullError",
    "ContainerNotMountedError",
    "ContainerSealedError",
    "FileNotFoundInContainerError",
    "FileAlreadyExistsInContainerError",
    # Политики
    "PolicyError",
    "PolicyNotFoundError",
    "PolicyAlreadyExistsError",
    "PolicyViolationError",
    "AccessDeniedError",
    "OperationNotAllowedError",
    "PolicyExpiredError",
    "InvalidPolicyError",
    # Сессии
    "SessionError",
    "SessionNotFoundError",
    "SessionExpiredError",
    "SessionLockedError",
    # Аудит
    "AuditError",
    "AuditLogError",
    "AuditSignatureError",
    # Хранение
    "StorageError",
    "StorageBackendError",
    "CloudSyncError",
    # Валидация
    "ValidationError",
    # Нативные
    "NativeError",
    "LibraryNotFoundError",
    "LibraryLoadError",
    "FunctionNotFoundError",
    "NativeModuleError",
    # Лицензирование
    "LicensingError",
    "LicenseInvalidError",
    "LicenseExpiredError",
    # Плагины
    "PluginError",
    "PluginLoadError",
    "PluginIsolationError",
]
