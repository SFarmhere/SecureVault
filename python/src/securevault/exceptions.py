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
    pass


# ============================================================================
# ОШИБКИ МЕНЕДЖЕРА КЛЮЧЕЙ
# ============================================================================

class KeyManagerError(SecureVaultError):
    """Ошибка менеджера ключей."""
    pass


class KeyNotFoundError(KeyManagerError):
    """Ключ не найден."""
    pass


class KeyAlreadyExistsError(KeyManagerError):
    """Ключ уже существует."""
    pass


class KeyExpiredError(KeyManagerError):
    """Ключ истек."""
    pass


class KeyDestroyedError(KeyManagerError):
    """Ключ был уничтожен."""
    pass


class TokenError(KeyManagerError):
    """Ошибка работы с токеном."""
    pass


class InsufficientSharesError(KeyManagerError):
    """Недостаточно shares для восстановления."""
    pass


# ============================================================================
# ОШИБКИ ШИФРОВАНИЯ
# ============================================================================

class EncryptionError(SecureVaultError):
    """Ошибка шифрования/дешифрования."""
    pass


class DecryptionError(EncryptionError):
    """Ошибка дешифрования."""
    pass


class IntegrityError(EncryptionError):
    """Ошибка проверки целостности."""
    pass


class UnsupportedProtectionLevelError(EncryptionError):
    """Неподдерживаемый уровень защиты."""
    pass


class InvalidEncryptedFileError(DecryptionError):
    """Невалидный формат зашифрованного файла."""
    pass


# ============================================================================
# ОШИБКИ КОНТЕЙНЕРОВ
# ============================================================================

class ContainerError(SecureVaultError):
    """Ошибка работы с контейнерами."""
    pass


class ContainerNotFoundError(ContainerError):
    """Контейнер не найден."""
    pass


class ContainerAlreadyExistsError(ContainerError):
    """Контейнер уже существует."""
    pass


class ContainerFullError(ContainerError):
    """Контейнер заполнен."""
    pass


class ContainerNotMountedError(ContainerError):
    """Контейнер не смонтирован."""
    pass


class ContainerSealedError(ContainerError):
    """Контейнер запечатан (только для чтения)."""
    pass


class FileNotFoundInContainerError(ContainerError):
    """Файл не найден в контейнере."""
    pass


class FileAlreadyExistsInContainerError(ContainerError):
    """Файл уже существует в контейнере."""
    pass


# ============================================================================
# ОШИБКИ ПОЛИТИК БЕЗОПАСНОСТИ
# ============================================================================

class PolicyError(SecureVaultError):
    """Базовое исключение для ошибок политик безопасности."""
    pass


class PolicyNotFoundError(PolicyError):
    """Политика не найдена."""
    pass


class PolicyAlreadyExistsError(PolicyError):
    """Политика уже существует."""
    pass


class PolicyViolationError(PolicyError):
    """Нарушение политики безопасности."""
    pass


class AccessDeniedError(PolicyError):
    """Доступ запрещен."""
    pass


class OperationNotAllowedError(PolicyError):
    """Операция не разрешена политикой."""
    pass


class PolicyExpiredError(PolicyError):
    """Политика истекла."""
    pass


class InvalidPolicyError(PolicyError):
    """Невалидная политика."""
    pass


# ============================================================================
# ОШИБКИ СЕССИЙ
# ============================================================================

class SessionError(SecureVaultError):
    """Ошибка управления сессиями."""
    pass


class SessionNotFoundError(SessionError):
    """Сессия не найдена."""
    pass


class SessionExpiredError(SessionError):
    """Сессия истекла."""
    pass


class SessionLockedError(SessionError):
    """Сессия заблокирована."""
    pass


# ============================================================================
# ОШИБКИ АУДИТА
# ============================================================================

class AuditError(SecureVaultError):
    """Ошибка аудита."""
    pass


class AuditLogError(AuditError):
    """Ошибка записи в журнал аудита."""
    pass


class AuditSignatureError(AuditError):
    """Ошибка подписи журнала аудита."""
    pass


# ============================================================================
# ОШИБКИ ХРАНЕНИЯ
# ============================================================================

class StorageError(SecureVaultError):
    """Ошибка хранения данных."""
    pass


class StorageBackendError(StorageError):
    """Ошибка бэкенда хранения."""
    pass


class CloudSyncError(StorageError):
    """Ошибка облачной синхронизации."""
    pass


# ============================================================================
# ОШИБКИ НАТИВНЫХ МОДУЛЕЙ
# ============================================================================

class NativeError(SecureVaultError):
    """Ошибка нативного модуля."""
    pass


class LibraryNotFoundError(NativeError):
    """Нативная библиотека не найдена."""
    pass


class LibraryLoadError(NativeError):
    """Ошибка загрузки библиотеки."""
    pass


class FunctionNotFoundError(NativeError):
    """Функция не найдена в библиотеке."""
    pass


class NativeModuleError(NativeError):
    """Ошибка выполнения нативного кода."""
    pass


# ============================================================================
# ОШИБКИ ЛИЦЕНЗИРОВАНИЯ
# ============================================================================

class LicensingError(SecureVaultError):
    """Ошибка лицензирования."""
    pass


class LicenseInvalidError(LicensingError):
    """Невалидная лицензия."""
    pass


class LicenseExpiredError(LicensingError):
    """Лицензия истекла."""
    pass


# ============================================================================
# ОШИБКИ ПЛАГИНОВ
# ============================================================================

class PluginError(SecureVaultError):
    """Ошибка системы плагинов."""
    pass


class PluginLoadError(PluginError):
    """Ошибка загрузки плагина."""
    pass


class PluginIsolationError(PluginError):
    """Нарушение изоляции плагина."""
    pass


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