"""
SecureVault - Константы проекта

Централизованное определение всех констант, используемых в SecureVault.
Содержит величины для криптографии, контейнеров, защиты и политик безопасности.

Категории констант:
- Криптографические параметры (размеры ключей, nonce, tags)
- Параметры контейнеров (размеры, лимиты)
- Параметры шифрования (алгоритмы, chunk sizes)
- Политики безопасности (роли, действия, уровни строгости)
- Уровни защиты данных
- Пути и директории
- Лимиты и пороговые значения
"""

# ============================================================================
# КРИПТОГРАФИЧЕСКИЕ ПАРАМЕТРЫ
# ============================================================================

# Размеры ключей (в байтах)
AES_KEY_SIZE = 32                      # AES-256 (256 бит)
AES_128_KEY_SIZE = 16                  # AES-128
AES_192_KEY_SIZE = 24                  # AES-192
RSA_2048_KEY_SIZE = 256                # RSA-2048 (в байтах)
RSA_4096_KEY_SIZE = 512                # RSA-4096 (в байтах)
MASTER_KEY_SIZE = 32                   # Мастер-ключ (256 бит)
FILE_KEY_SIZE = 32                     # Ключ файла (256 бит)
SESSION_KEY_SIZE = 32                  # Сессионный ключ (256 бит)
PASSWORD_KEY_SIZE = 32                 # Ключ из пароля (256 бит)
SIGNING_KEY_SIZE = 32                  # Ключ подписи (256 бит)

# Параметры AES-GCM
AES_GCM_NONCE_SIZE = 12                # Размер nonce (96 бит)
AES_GCM_TAG_SIZE = 16                  # Размер тега аутентификации (128 бит)

# Параметры ChaCha20-Poly1305
CHACHA20_KEY_SIZE = 32                 # 256 бит
CHACHA20_NONCE_SIZE = 12               # 96 бит
CHACHA20_TAG_SIZE = 16                 # 128 бит

# Параметры Argon2id
ARGON2_TIME_COST = 3                   # Количество итераций
ARGON2_MEMORY_COST = 65536             # 64 MB памяти
ARGON2_PARALLELISM = 4                 # Параллельные потоки
ARGON2_HASH_LENGTH = 32                # Длина выходного хеша
ARGON2_SALT_LENGTH = 16                # Длина соли

# Параметры Shamir Secret Sharing
SHAMIR_TOTAL_SHARES = 5                # Общее количество shares
SHAMIR_THRESHOLD = 3                   # Минимальное количество для восстановления

# Параметры HMAC
HMAC_SHA256_KEY_SIZE = 32              # 256 бит
HMAC_SHA256_DIGEST_SIZE = 32           # 256 бит

# Параметры ECDSA
ECDSA_P256_KEY_SIZE = 32               # 256 бит
ECDSA_P384_KEY_SIZE = 48               # 384 бит

# Пост-квантовая криптография
KYBER512_KEY_SIZE = 32                 # 256 бит
KYBER1024_KEY_SIZE = 64                # 512 бит


# ============================================================================
# ПАРАМЕТРЫ ШИФРОВАНИЯ
# ============================================================================

# Размеры чанков
DEFAULT_CHUNK_SIZE = 65536             # 64 KB
MAX_CHUNK_SIZE = 1048576               # 1 MB
STREAM_CHUNK_SIZE = 65536              # 64 KB для потокового шифрования

# Блоки и дедупликация
DEFAULT_BLOCK_SIZE = 1048576           # 1 MB - размер блока для дедупликации
CDC_MIN_CHUNK_SIZE = 4096              # 4 KB - минимальный CDC чанк
CDC_AVG_CHUNK_SIZE = 16384             # 16 KB - средний CDC чанк
CDC_MAX_CHUNK_SIZE = 65536             # 64 KB - максимальный CDC чанк
CDC_WINDOW_SIZE = 48                   # Размер скользящего окна

# Сжатие
COMPRESSION_LEVEL_DEFAULT = 6          # Стандартный уровень (zlib)
COMPRESSION_LEVEL_FAST = 1             # Быстрый уровень
COMPRESSION_LEVEL_MAX = 9              # Максимальный уровень


# ============================================================================
# УРОВНИ ЗАЩИТЫ ДАННЫХ
# ============================================================================

class ProtectionLevel:
    """Уровни защиты данных."""
    ORIGINAL = "original"              # Без шифрования
    INDIVIDUAL = "individual"          # Каждый файл отдельно
    CONTAINER = "container"            # Контейнер с файлами
    HYPER = "hyper"                    # Двойное шифрование

PROTECTION_LEVELS = [
    ProtectionLevel.ORIGINAL,
    ProtectionLevel.INDIVIDUAL,
    ProtectionLevel.CONTAINER,
    ProtectionLevel.HYPER,
]

# Минимальные требования к каждому уровню
PROTECTION_LEVEL_REQUIREMENTS = {
    ProtectionLevel.ORIGINAL: {
        "encryption": False,
        "key_required": False,
        "container": False,
        "integrity_check": False,
    },
    ProtectionLevel.INDIVIDUAL: {
        "encryption": True,
        "key_required": True,
        "container": False,
        "integrity_check": True,
        "min_key_size": 16,            # AES-128
        "recommended_algorithm": "aes-256-gcm",
    },
    ProtectionLevel.CONTAINER: {
        "encryption": True,
        "key_required": True,
        "container": True,
        "integrity_check": True,
        "min_key_size": 32,            # AES-256
        "recommended_algorithm": "aes-256-gcm",
    },
    ProtectionLevel.HYPER: {
        "encryption": True,
        "key_required": True,
        "container": True,
        "integrity_check": True,
        "double_encryption": True,
        "min_key_size": 32,            # AES-256
        "recommended_algorithm": "aes-256-gcm",
    },
}


# ============================================================================
# ПАРАМЕТРЫ КОНТЕЙНЕРОВ
# ============================================================================

# Размеры контейнеров (по умолчанию)
DEFAULT_CONTAINER_SIZE = 10737418240   # 10 GB
MIN_CONTAINER_SIZE = 1048576           # 1 MB
MAX_CONTAINER_SIZE = 1099511627776     # 1 TB

# Параметры контейнеров
CONTAINERS_DIR = "containers"
CONTAINER_FORMAT_V1 = 1                # Обычный формат
CONTAINER_FORMAT_V2 = 2                # Скрытый формат (plausible deniability)
CONTAINER_HEADER_MAGIC = b"SVC1"       # Магическая последовательность

# Лимиты
MAX_FILES_PER_CONTAINER = 100000       # Максимум файлов в контейнере
MAX_FILE_SIZE_IN_CONTAINER = 107374182400  # 100 GB
MAX_FILENAME_LENGTH = 256              # Максимальная длина имени файла
MAX_CONTAINER_PASSWORD_LENGTH = 128    # Максимальная длина пароля


# ============================================================================
# ПАРАМЕТРЫ ПОЛИТИК БЕЗОПАСНОСТИ
# ============================================================================

# Роли пользователей
class UserRole:
    """Роли пользователей в SecureVault."""
    ADMIN = "admin"                    # Администратор
    OPERATOR = "operator"              # Оператор
    USER = "user"                      # Обычный пользователь
    GUEST = "guest"                    # Гость
    AUDITOR = "auditor"                # Аудитор

USER_ROLES = [
    UserRole.ADMIN,
    UserRole.OPERATOR,
    UserRole.USER,
    UserRole.GUEST,
    UserRole.AUDITOR,
]

# Действия (операции)
class PolicyAction:
    """Типы действий, контролируемых политиками."""
    ENCRYPT = "encrypt"                # Шифрование
    DECRYPT = "decrypt"                # Дешифрование
    CREATE_CONTAINER = "create_container"    # Создание контейнера
    MOUNT_CONTAINER = "mount_container"      # Монтирование контейнера
    UNMOUNT_CONTAINER = "unmount_container"  # Размонтирование контейнера
    ADD_FILE = "add_file"              # Добавление файла
    EXTRACT_FILE = "extract_file"      # Извлечение файла
    DELETE_FILE = "delete_file"        # Удаление файла
    DELETE_CONTAINER = "delete_container"    # Удаление контейнера
    ROTATE_KEY = "rotate_key"          # Ротация ключей
    BACKUP_KEY = "backup_key"          # Резервное копирование
    RESTORE_KEY = "restore_key"        # Восстановление ключей
    AUDIT_VIEW = "audit_view"          # Просмотр аудита
    POLICY_MANAGE = "policy_manage"    # Управление политиками
    USER_MANAGE = "user_manage"        # Управление пользователями
    INTEGRITY_CHECK = "integrity_check"  # Проверка целостности
    EXPORT_DATA = "export_data"        # Экспорт данных
    IMPORT_DATA = "import_data"        # Импорт данных

POLICY_ACTIONS = [
    PolicyAction.ENCRYPT,
    PolicyAction.DECRYPT,
    PolicyAction.CREATE_CONTAINER,
    PolicyAction.MOUNT_CONTAINER,
    PolicyAction.UNMOUNT_CONTAINER,
    PolicyAction.ADD_FILE,
    PolicyAction.EXTRACT_FILE,
    PolicyAction.DELETE_FILE,
    PolicyAction.DELETE_CONTAINER,
    PolicyAction.ROTATE_KEY,
    PolicyAction.BACKUP_KEY,
    PolicyAction.RESTORE_KEY,
    PolicyAction.AUDIT_VIEW,
    PolicyAction.POLICY_MANAGE,
    PolicyAction.USER_MANAGE,
    PolicyAction.INTEGRITY_CHECK,
    PolicyAction.EXPORT_DATA,
    PolicyAction.IMPORT_DATA,
]

# Уровни строгости политик
class PolicySeverity:
    """Уровни строгости политик."""
    LOW = "low"                        # Низкий - предупреждения
    MEDIUM = "medium"                  # Средний - ограничения
    HIGH = "high"                      # Высокий - запреты
    CRITICAL = "critical"              # Критический - полный контроль

POLICY_SEVERITY_LEVELS = [
    PolicySeverity.LOW,
    PolicySeverity.MEDIUM,
    PolicySeverity.HIGH,
    PolicySeverity.CRITICAL,
]

# Статусы политик
class PolicyStatus:
    """Статусы политик."""
    ACTIVE = "active"                  # Активна
    INACTIVE = "inactive"              # Не активна
    PENDING = "pending"                # Ожидает активации
    EXPIRED = "expired"                # Истекла
    DRAFT = "draft"                    # Черновик

POLICY_STATUSES = [
    PolicyStatus.ACTIVE,
    PolicyStatus.INACTIVE,
    PolicyStatus.PENDING,
    PolicyStatus.EXPIRED,
    PolicyStatus.DRAFT,
]

# Типы политик
class PolicyType:
    """Типы политик безопасности."""
    ACCESS = "access"                  # Контроль доступа
    OPERATION = "operation"            # Контроль операций
    KEY_MANAGEMENT = "key_management"  # Управление ключами
    DATA_HANDLING = "data_handling"    # Обработка данных
    COMPLIANCE = "compliance"          # Соответствие требованиям

POLICY_TYPES = [
    PolicyType.ACCESS,
    PolicyType.OPERATION,
    PolicyType.KEY_MANAGEMENT,
    PolicyType.DATA_HANDLING,
    PolicyType.COMPLIANCE,
]

# Политики по умолчанию
DEFAULT_POLICIES = {
    "default-user": {
        "name": "Standard User",
        "type": PolicyType.ACCESS,
        "severity": PolicySeverity.MEDIUM,
        "allowed_actions": [
            PolicyAction.ENCRYPT,
            PolicyAction.DECRYPT,
            PolicyAction.CREATE_CONTAINER,
            PolicyAction.MOUNT_CONTAINER,
            PolicyAction.UNMOUNT_CONTAINER,
            PolicyAction.ADD_FILE,
            PolicyAction.EXTRACT_FILE,
            PolicyAction.DELETE_FILE,
            PolicyAction.INTEGRITY_CHECK,
        ],
        "max_protection_level": ProtectionLevel.HYPER,
        "password_min_length": 12,
        "require_mfa": False,
        "session_timeout": 3600,       # 1 час
    },
    "default-admin": {
        "name": "Administrator",
        "type": PolicyType.ACCESS,
        "severity": PolicySeverity.CRITICAL,
        "allowed_actions": list(POLICY_ACTIONS),
        "max_protection_level": ProtectionLevel.HYPER,
        "password_min_length": 14,
        "require_mfa": True,
        "session_timeout": 1800,       # 30 минут
    },
    "default-auditor": {
        "name": "Auditor",
        "type": PolicyType.COMPLIANCE,
        "severity": PolicySeverity.HIGH,
        "allowed_actions": [
            PolicyAction.AUDIT_VIEW,
            PolicyAction.INTEGRITY_CHECK,
        ],
        "max_protection_level": ProtectionLevel.CONTAINER,
        "password_min_length": 12,
        "require_mfa": True,
        "session_timeout": 900,        # 15 минут
    },
}


# ============================================================================
# ПАРАМЕТРЫ СЕССИЙ
# ============================================================================

DEFAULT_SESSION_TIMEOUT = 3600         # 1 час
MAX_SESSION_TIMEOUT = 86400            # 24 часа
MIN_SESSION_TIMEOUT = 60               # 1 минута
DEFAULT_IDLE_TIMEOUT = 600             # 10 минут
MAX_FAILED_LOGIN_ATTEMPTS = 5          # Максимум неудачных попыток
LOCKOUT_DURATION = 300                 # Блокировка на 5 минут
SESSION_TOKEN_LENGTH = 32              # Длина токена сессии


# ============================================================================
# ПАРАМЕТРЫ АУДИТА
# ============================================================================

AUDIT_LOG_DIR = "audit"
AUDIT_LOG_FORMAT = "json"
AUDIT_RETENTION_DAYS = 365             # Хранение 1 год
AUDIT_BATCH_SIZE = 100                 # Размер пачки записей
AUDIT_SIGNATURE_KEY_ID = "audit-signing-key"
MAX_AUDIT_LOG_SIZE = 104857600         # 100 MB


# ============================================================================
# ПАРАМЕТРЫ АНТИ-ОТЛАДКИ И БЕЗОПАСНОСТИ
# ============================================================================

# Интеграция
INTEGRITY_CHECK_INTERVAL = 3600        # Каждый час
MAX_MEMORY_DUMP_SIZE = 1048576         # 1 MB

# Защита памяти
MEMORY_GUARD_SIZE = 4096               # Размер guard page
STACK_GUARD_SIZE = 4096


# ============================================================================
# ПУТИ И ДИРЕКТОРИИ
# ============================================================================

SECUREVAULT_DIR_NAME = ".securevault"
KEYS_DIR = "keys"
BACKUPS_DIR = "backups"
CONTAINERS_DIR = "containers"
CONFIG_DIR = "config"
AUDIT_DIR = "audit"
TEMP_DIR = "tmp"
PLUGINS_DIR = "plugins"
LICENSES_DIR = "licenses"

# Файлы
MASTER_KEY_FILE = "master.key"
KEY_METADATA_FILE = "key_metadata.json"
CONTAINER_METADATA_FILE = "container_metadata.json"
POLICY_CONFIG_FILE = "policies.json"
AUDIT_DATABASE_FILE = "audit.db"
LOG_FILE = "securevault.log"
CONFIG_FILE = "config.json"


# ============================================================================
# ЛИМИТЫ И ПОРОГОВЫЕ ЗНАЧЕНИЯ
# ============================================================================

# Общие лимиты
MAX_FILE_PATH_LENGTH = 4096
MAX_OPEN_FILES = 256
MAX_PASSWORD_LENGTH = 256
MIN_PASSWORD_LENGTH = 8

# Пороговые значения для предупреждений
WARN_KEY_USAGE_COUNT = 1000            # Предупреждение при 1000 использованиях
WARN_KEY_AGE_DAYS = 90                 # Предупреждение при возрасте ключа > 90 дней
FORCE_KEY_ROTATION_DAYS = 365          # Принудительная ротация через год

# Дедупликация
DEDUP_RATIO_GOOD = 0.3                 # Хороший коэффициент (30% экономия)
DEDUP_RATIO_EXCELLENT = 0.5            # Отличный (50% экономия)


# ============================================================================
# КОДЫ ОШИБОК
# ============================================================================

class ErrorCode:
    """Коды ошибок для API."""
    # Общие
    OK = 0
    UNKNOWN_ERROR = 1000
    
    # Ключи
    KEY_NOT_FOUND = 2001
    KEY_EXPIRED = 2002
    KEY_DESTROYED = 2003
    KEY_ALREADY_EXISTS = 2004
    KEY_ROTATION_NEEDED = 2005
    
    # Шифрование
    ENCRYPTION_FAILED = 3001
    DECRYPTION_FAILED = 3002
    INTEGRITY_CHECK_FAILED = 3003
    INVALID_ENCRYPTED_FILE = 3004
    
    # Политики
    POLICY_NOT_FOUND = 4001
    POLICY_VIOLATION = 4002
    ACCESS_DENIED = 4003
    OPERATION_NOT_ALLOWED = 4004
    
    # Сессии
    SESSION_EXPIRED = 5001
    SESSION_INVALID = 5002
    SESSION_LOCKED = 5003
    TOO_MANY_ATTEMPTS = 5004
    
    # Аудит
    AUDIT_WRITE_FAILED = 6001
    AUDIT_SIGNATURE_FAILED = 6002
    
    # Контейнеры
    CONTAINER_NOT_FOUND = 7001
    CONTAINER_FULL = 7002
    CONTAINER_NOT_MOUNTED = 7003
    
    # Хранилище
    STORAGE_FULL = 8001
    STORAGE_WRITE_FAILED = 8002
    STORAGE_READ_FAILED = 8003
    
    # Нативные модули
    NATIVE_LIBRARY_NOT_FOUND = 9001
    NATIVE_INITIALIZATION_FAILED = 9002


# ============================================================================
# ЭКСПОРТ
# ============================================================================

__all__ = [
    # Криптография
    "AES_KEY_SIZE",
    "AES_128_KEY_SIZE",
    "AES_192_KEY_SIZE",
    "RSA_2048_KEY_SIZE",
    "RSA_4096_KEY_SIZE",
    "MASTER_KEY_SIZE",
    "FILE_KEY_SIZE",
    "SESSION_KEY_SIZE",
    "PASSWORD_KEY_SIZE",
    "SIGNING_KEY_SIZE",
    "AES_GCM_NONCE_SIZE",
    "AES_GCM_TAG_SIZE",
    "CHACHA20_KEY_SIZE",
    "CHACHA20_NONCE_SIZE",
    "CHACHA20_TAG_SIZE",
    "ARGON2_TIME_COST",
    "ARGON2_MEMORY_COST",
    "ARGON2_PARALLELISM",
    "ARGON2_HASH_LENGTH",
    "ARGON2_SALT_LENGTH",
    "SHAMIR_TOTAL_SHARES",
    "SHAMIR_THRESHOLD",
    "HMAC_SHA256_KEY_SIZE",
    "HMAC_SHA256_DIGEST_SIZE",
    "ECDSA_P256_KEY_SIZE",
    "ECDSA_P384_KEY_SIZE",
    "KYBER512_KEY_SIZE",
    "KYBER1024_KEY_SIZE",
    
    # Шифрование
    "DEFAULT_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "STREAM_CHUNK_SIZE",
    "DEFAULT_BLOCK_SIZE",
    "CDC_MIN_CHUNK_SIZE",
    "CDC_AVG_CHUNK_SIZE",
    "CDC_MAX_CHUNK_SIZE",
    "CDC_WINDOW_SIZE",
    "COMPRESSION_LEVEL_DEFAULT",
    "COMPRESSION_LEVEL_FAST",
    "COMPRESSION_LEVEL_MAX",
    
    # Уровни защиты
    "ProtectionLevel",
    "PROTECTION_LEVELS",
    "PROTECTION_LEVEL_REQUIREMENTS",
    
    # Контейнеры
    "DEFAULT_CONTAINER_SIZE",
    "MIN_CONTAINER_SIZE",
    "MAX_CONTAINER_SIZE",
    "CONTAINERS_DIR",
    "CONTAINER_FORMAT_V1",
    "CONTAINER_FORMAT_V2",
    "CONTAINER_HEADER_MAGIC",
    "MAX_FILES_PER_CONTAINER",
    "MAX_FILE_SIZE_IN_CONTAINER",
    "MAX_FILENAME_LENGTH",
    "MAX_CONTAINER_PASSWORD_LENGTH",
    
    # Политики
    "UserRole",
    "USER_ROLES",
    "PolicyAction",
    "POLICY_ACTIONS",
    "PolicySeverity",
    "POLICY_SEVERITY_LEVELS",
    "PolicyStatus",
    "POLICY_STATUSES",
    "PolicyType",
    "POLICY_TYPES",
    "DEFAULT_POLICIES",
    
    # Сессии
    "DEFAULT_SESSION_TIMEOUT",
    "MAX_SESSION_TIMEOUT",
    "MIN_SESSION_TIMEOUT",
    "DEFAULT_IDLE_TIMEOUT",
    "MAX_FAILED_LOGIN_ATTEMPTS",
    "LOCKOUT_DURATION",
    "SESSION_TOKEN_LENGTH",
    
    # Аудит
    "AUDIT_LOG_DIR",
    "AUDIT_LOG_FORMAT",
    "AUDIT_RETENTION_DAYS",
    "AUDIT_BATCH_SIZE",
    "AUDIT_SIGNATURE_KEY_ID",
    "MAX_AUDIT_LOG_SIZE",
    
    # Пути
    "SECUREVAULT_DIR_NAME",
    "KEYS_DIR",
    "BACKUPS_DIR",
    "CONTAINERS_DIR",
    "CONFIG_DIR",
    "AUDIT_DIR",
    "TEMP_DIR",
    "PLUGINS_DIR",
    "LICENSES_DIR",
    "MASTER_KEY_FILE",
    "KEY_METADATA_FILE",
    "CONTAINER_METADATA_FILE",
    "POLICY_CONFIG_FILE",
    "AUDIT_DATABASE_FILE",
    "LOG_FILE",
    "CONFIG_FILE",
    
    # Лимиты
    "MAX_FILE_PATH_LENGTH",
    "MAX_OPEN_FILES",
    "MAX_PASSWORD_LENGTH",
    "MIN_PASSWORD_LENGTH",
    "WARN_KEY_USAGE_COUNT",
    "WARN_KEY_AGE_DAYS",
    "FORCE_KEY_ROTATION_DAYS",
    "DEDUP_RATIO_GOOD",
    "DEDUP_RATIO_EXCELLENT",
    
    # Коды ошибок
    "ErrorCode",
]