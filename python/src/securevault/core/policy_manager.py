"""
SecureVault - Менеджер политик безопасности

Управление политиками безопасности и контроля доступа:
- Создание, обновление, удаление политик
- Валидация операций шифрования/дешифрования
- Проверка прав доступа пользователей и ролей
- Применение политик к операциям
- Аудит действий пользователей
- Интеграция с session_manager и audit_manager

Политики определяют:
1. Какие операции разрешены (шифрование, дешифрование, контейнеры и т.д.)
2. Какие роли имеют доступ к операциям
3. Максимальный уровень защиты для роли
4. Требования к паролям и MFA
5. Временные ограничения (срок действия политики)

Зависимости:
- core/key_manager.py: Управление ключами
- core/session_manager.py: Управление сессиями
- core/audit_manager.py: Аудит действий
- security/access_control.py: Контроль доступа
- exceptions: Исключения проекта
- constants: Константы
- native/crypto.py: Криптографические операции

Использование:
    from securevault.core.policy_manager import PolicyManager

    pm = PolicyManager()

    # Создание политики
    policy = pm.create_policy(
        name="Secure Operations",
        description="Политика для администраторов",
        allowed_actions=["encrypt", "decrypt", "create_container"],
        roles=["admin", "operator"],
        max_protection_level="hyper",
        severity="critical",
    )

    # Проверка доступа
    pm.check_access("user1", "encrypt", roles=["admin"])

    # Валидация операции
    pm.validate_operation(
        action="encrypt",
        roles=["admin"],
        protection_level="hyper",
        key_available=True,
    )

    # Применение политики
    pm.enforce_policy("user1", "encrypt")

    # Аудит действия
    pm.audit_action("user1", "encrypt", "success", {"file": "document.pdf"})
"""

import json
import hashlib
import logging
from typing import Optional, List, Dict, Any, Set
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

# Внутренние импорты
from securevault.core import key_manager
from securevault import exceptions
from securevault import constants

logger = logging.getLogger(__name__)


# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================


class PolicyStatus(Enum):
    """Статусы политик."""

    ACTIVE = "active"  # Активна, применяется
    INACTIVE = "inactive"  # Не активна, не применяется
    PENDING = "pending"  # Ожидает активации
    EXPIRED = "expired"  # Срок действия истек
    DRAFT = "draft"  # Черновик (не применяется)


class PolicyType(Enum):
    """Типы политик безопасности."""

    ACCESS = "access"  # Контроль доступа
    OPERATION = "operation"  # Контроль операций
    KEY_MANAGEMENT = "key_management"  # Управление ключами
    DATA_HANDLING = "data_handling"  # Обработка данных
    COMPLIANCE = "compliance"  # Соответствие требованиям


class PolicySeverity(Enum):
    """Уровни строгости политик."""

    LOW = "low"  # Низкий - предупреждения, не блокирует
    MEDIUM = "medium"  # Средний - ограничения
    HIGH = "high"  # Высокий - запрещает небезопасные операции
    CRITICAL = "critical"  # Критический - полный контроль


class Decision(Enum):
    """Решения по результату проверки."""

    ALLOW = "allow"  # Разрешено
    DENY = "deny"  # Запрещено
    REQUIRE_CONDITION = "require_condition"  # Требует выполнения условия


# Действия (операции), контролируемые политиками
class Action:
    """Типы действий, контролируемых политиками."""

    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    CREATE_CONTAINER = "create_container"
    MOUNT_CONTAINER = "mount_container"
    UNMOUNT_CONTAINER = "unmount_container"
    ADD_FILE = "add_file"
    EXTRACT_FILE = "extract_file"
    DELETE_FILE = "delete_file"
    DELETE_CONTAINER = "delete_container"
    ROTATE_KEY = "rotate_key"
    BACKUP_KEY = "backup_key"
    RESTORE_KEY = "restore_key"
    AUDIT_VIEW = "audit_view"
    POLICY_MANAGE = "policy_manage"
    USER_MANAGE = "user_manage"
    INTEGRITY_CHECK = "integrity_check"
    EXPORT_DATA = "export_data"
    IMPORT_DATA = "import_data"


# Роли пользователей
class Role:
    """Роли пользователей в системе."""

    ADMIN = "admin"
    OPERATOR = "operator"
    USER = "user"
    GUEST = "guest"
    AUDITOR = "auditor"


# Пути и файлы
POLICIES_DIR = "policies"
POLICY_CONFIG_FILE = "policies.json"


# ============================================================================
# МЕТАДАННЫЕ ПОЛИТИКИ
# ============================================================================


@dataclass
class PolicyMetadata:
    """
    Метаданные политики безопасности.

    Хранит полное описание политики: какие действия разрешены,
    для каких ролей, с какими ограничениями.
    """

    # Основная информация
    policy_id: str
    name: str
    description: str = ""
    policy_type: PolicyType = PolicyType.ACCESS
    severity: PolicySeverity = PolicySeverity.MEDIUM
    status: PolicyStatus = PolicyStatus.ACTIVE

    # Разрешения
    allowed_actions: List[str] = field(default_factory=list)
    denied_actions: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)

    # Ограничения
    # Максимальный уровень защиты
    max_protection_level: Optional[str] = None
    # Минимальный размер ключа (байт)
    min_key_size: int = 0
    # Максимальный размер файла (байт)
    max_file_size: Optional[int] = None
    password_min_length: int = 8  # Мин. длина пароля
    require_mfa: bool = False  # Требовать MFA
    require_token: bool = False  # Требовать аппаратный токен

    # Временные ограничения
    valid_from: Optional[datetime] = None  # С какого времени действует
    # До какого времени действует
    valid_until: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    # Дополнительно
    conditions: Dict[str, Any] = field(default_factory=dict)  # Дополнительные условия
    metadata: Dict[str, Any] = field(default_factory=dict)  # Произвольные метаданные
    version: int = 1  # Версия политики
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Сериализовать в словарь."""
        return {
            "policy_id": self.policy_id,
            "name": self.name,
            "description": self.description,
            "policy_type": self.policy_type.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "allowed_actions": self.allowed_actions,
            "denied_actions": self.denied_actions,
            "roles": self.roles,
            "max_protection_level": self.max_protection_level,
            "min_key_size": self.min_key_size,
            "max_file_size": self.max_file_size,
            "password_min_length": self.password_min_length,
            "require_mfa": self.require_mfa,
            "require_token": self.require_token,
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "conditions": self.conditions,
            "metadata": self.metadata,
            "version": self.version,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyMetadata":
        """Десериализовать из словаря."""
        return cls(
            policy_id=data["policy_id"],
            name=data["name"],
            description=data.get("description", ""),
            policy_type=PolicyType(data["policy_type"]),
            severity=PolicySeverity(data["severity"]),
            status=PolicyStatus(data["status"]),
            allowed_actions=data.get("allowed_actions", []),
            denied_actions=data.get("denied_actions", []),
            roles=data.get("roles", []),
            max_protection_level=data.get("max_protection_level"),
            min_key_size=data.get("min_key_size", 0),
            max_file_size=data.get("max_file_size"),
            password_min_length=data.get("password_min_length", 8),
            require_mfa=data.get("require_mfa", False),
            require_token=data.get("require_token", False),
            valid_from=(
                datetime.fromisoformat(data["valid_from"])
                if data.get("valid_from")
                else None
            ),
            valid_until=(
                datetime.fromisoformat(data["valid_until"])
                if data.get("valid_until")
                else None
            ),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            conditions=data.get("conditions", {}),
            metadata=data.get("metadata", {}),
            version=data.get("version", 1),
            tags=data.get("tags", []),
        )


# ============================================================================
# РЕЗУЛЬТАТ ВАЛИДАЦИИ
# ============================================================================


@dataclass
class PolicyDecision:
    """
    Результат проверки политики.

    Содержит решение (разрешено/запрещено), применяемую политику,
    причины и рекомендации.
    """

    allowed: bool  # Разрешено или нет
    policy_id: Optional[str] = None  # ID применимой политики
    policy_name: Optional[str] = None  # Имя применяемой политики
    reasons: List[str] = field(default_factory=list)  # Причины решения
    conditions_required: List[str] = field(default_factory=list)  # Требуемые условия
    warnings: List[str] = field(default_factory=list)  # Предупреждения

    def to_dict(self) -> Dict[str, Any]:
        """Сериализовать в словарь."""
        return {
            "allowed": self.allowed,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "reasons": self.reasons,
            "conditions_required": self.conditions_required,
            "warnings": self.warnings,
            "decision": "allow" if self.allowed else "deny",
        }


# ============================================================================
# ИСКЛЮЧЕНИЯ
# ============================================================================


class PolicyManagerError(exceptions.PolicyError):
    """Базовое исключение для PolicyManager."""


class PolicyNotFoundError(PolicyManagerError, exceptions.PolicyNotFoundError):
    """Политика не найдена."""


class PolicyAlreadyExistsError(PolicyManagerError, exceptions.PolicyAlreadyExistsError):
    """Политика уже существует."""


class PolicyViolationError(PolicyManagerError, exceptions.PolicyViolationError):
    """Нарушение политики безопасности."""


class AccessDeniedError(PolicyManagerError, exceptions.AccessDeniedError):
    """Доступ запрещен политикой."""


class OperationNotAllowedError(PolicyManagerError, exceptions.OperationNotAllowedError):
    """Операция не разрешена политикой."""


class InvalidPolicyError(PolicyManagerError, exceptions.InvalidPolicyError):
    """Невалидная политика."""


class PolicyExpiredError(PolicyManagerError, exceptions.PolicyExpiredError):
    """Политика истекла."""


# ============================================================================
# ОСНОВНОЙ КЛАСС
# ============================================================================


class PolicyManager:
    """
    Менеджер политик безопасности SecureVault.

    Управляет жизненным циклом политик безопасности:
    - Создание, обновление, удаление политик
    - Валидация операций против политик
    - Проверка прав доступа
    - Аудит действий
    - Применение политик

    Назначение политик:
    - Определяют какие операции разрешены
    - Контролируют максимальный уровень защиты
    - Проверяют требования к паролям и MFA
    - Ограничивают операции по ролям

    Пример:
        pm = PolicyManager(storage_dir="/secure/vault/policies")

        # Создание политики
        policy = pm.create_policy(
            name="Secure Operations",
            description="Политика для администраторов",
            policy_type=PolicyType.ACCESS,
            severity=PolicySeverity.CRITICAL,
            allowed_actions=[
                Action.ENCRYPT,
                Action.DECRYPT,
                Action.CREATE_CONTAINER,
            ],
            roles=[Role.ADMIN, Role.OPERATOR],
            max_protection_level="hyper",
            require_mfa=True,
        )

        # Проверка доступа
        decision = pm.check_access(
            user_id="user1",
            action=Action.ENCRYPT,
            roles=[Role.ADMIN],
        )

        # Валидация операции
        decision = pm.validate_operation(
            action=Action.ENCRYPT,
            roles=[Role.ADMIN],
            protection_level="hyper",
            key_available=True,
        )

        # Аудит
        pm.audit_action("user1", Action.ENCRYPT, "success", {"file": "doc.pdf"})

        # Получение активных политик
        active = pm.get_active_policies()

        # Обновление политики
        pm.update_policy("pol-1", name="New Name", severity=PolicySeverity.HIGH)

        # Удаление политики
        pm.delete_policy("pol-1")
    """

    def __init__(
        self,
        storage_dir: Optional[str] = None,
        key_mgr: Optional[key_manager.KeyManager] = None,
        strict_mode: bool = True,
    ):
        """
        Инициализировать менеджер политик.

        Args:
            storage_dir: Директория для хранения политик.
                        По умолчанию: ~/.securevault/policies
            key_mgr: Менеджер ключей (для проверки ключей).
            strict_mode: Строгий режим - по умолчанию запрещать
                        операции без явного разрешения.
        """
        # Директория хранения
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            home = Path.home()
            self.storage_dir = home / ".securevault" / POLICIES_DIR

        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Менеджер ключей
        self.key_mgr = key_mgr or key_manager.KeyManager()

        # Режим строгости
        self.strict_mode = strict_mode

        # Политики
        self.policy_file = self.storage_dir / POLICY_CONFIG_FILE
        self.policies: Dict[str, PolicyMetadata] = {}

        # Журнал аудита
        self.audit_log: List[Dict[str, Any]] = []
        self._audit_limit = 10000  # Лимит записей аудита в памяти

        # Загрузка политик
        self._load_policies()

        # Инициализация политик по умолчанию
        self._ensure_default_policies()

        logger.info(f"PolicyManager initialized: storage={self.storage_dir}")

    # ------------------------------------------------------------------------
    # ЖИЗНЕННЫЙ ЦИКЛ
    # ------------------------------------------------------------------------

    def initialize(self) -> None:
        """Полная инициализация менеджера политик."""
        logger.info("Initializing PolicyManager...")
        self._load_policies()
        self._ensure_default_policies()
        logger.info(f"Loaded {len(self.policies)} policies")
        logger.info("PolicyManager initialization complete")

    def shutdown(self) -> None:
        """Завершение работы менеджера политик."""
        self._save_policies()
        logger.info("PolicyManager shutdown complete")

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    # ------------------------------------------------------------------------
    # УПРАВЛЕНИЕ ПОЛИТИКАМИ
    # ------------------------------------------------------------------------

    def create_policy(
        self,
        name: str,
        description: str = "",
        policy_type: PolicyType = PolicyType.ACCESS,
        severity: PolicySeverity = PolicySeverity.MEDIUM,
        allowed_actions: Optional[List[str]] = None,
        denied_actions: Optional[List[str]] = None,
        roles: Optional[List[str]] = None,
        max_protection_level: Optional[str] = None,
        min_key_size: int = 0,
        max_file_size: Optional[int] = None,
        password_min_length: int = 8,
        require_mfa: bool = False,
        require_token: bool = False,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        conditions: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
        policy_id: Optional[str] = None,
    ) -> PolicyMetadata:
        """
        Создать политику безопасности.

        Args:
            name: Имя политики.
            description: Описание политики.
            policy_type: Тип политики.
            severity: Уровень строгости.
            allowed_actions: Список разрешенных действий.
            denied_actions: Список запрещенных действий.
            roles: Роли, на которые распространяется политика.
            max_protection_level: Максимальный уровень защиты.
            min_key_size: Минимальный размер ключа (байт).
            max_file_size: Максимальный размер файла (байт).
            password_min_length: Минимальная длина пароля.
            require_mfa: Требовать многофакторную аутентификацию.
            require_token: Требовать аппаратный токен.
            valid_from: Начало действия политики.
            valid_until: Окончание действия политики.
            conditions: Дополнительные условия.
            metadata: Дополнительные метаданные.
            tags: Теги для категоризации.
            policy_id: Уникальный ID политики (если None, генерируется).

        Returns:
            Созданная политика.

        Raises:
            PolicyAlreadyExistsError: Если политика с таким ID уже существует.
            InvalidPolicyError: Если параметры невалидны.
        """
        # Валидация параметров
        self._validate_policy_params(
            name=name,
            allowed_actions=allowed_actions,
            denied_actions=denied_actions,
            roles=roles,
            max_protection_level=max_protection_level,
            min_key_size=min_key_size,
            password_min_length=password_min_length,
        )

        # Генерация ID
        if policy_id is None:
            policy_id = self._generate_policy_id(name)

        # Проверка существования
        if policy_id in self.policies:
            raise PolicyAlreadyExistsError(f"Policy {policy_id} already exists")

        # Создание метаданных
        policy = PolicyMetadata(
            policy_id=policy_id,
            name=name,
            description=description,
            policy_type=policy_type,
            severity=severity,
            status=PolicyStatus.ACTIVE,
            allowed_actions=allowed_actions or [],
            denied_actions=denied_actions or [],
            roles=roles or [],
            max_protection_level=max_protection_level,
            min_key_size=min_key_size,
            max_file_size=max_file_size,
            password_min_length=password_min_length,
            require_mfa=require_mfa,
            require_token=require_token,
            valid_from=valid_from,
            valid_until=valid_until,
            conditions=conditions or {},
            metadata=metadata or {},
            tags=tags or [],
        )

        # Сохранение политики
        self.policies[policy_id] = policy

        # Автоматическая проверка срока действия
        self._check_expiry(policy)

        self._save_policies()

        # Аудит создания
        self.audit_action(
            user_id="system",
            action=Action.POLICY_MANAGE,
            result="success",
            details={"event": "create_policy", "policy_id": policy_id, "name": name},
        )

        logger.info(f"Policy created: {policy_id} ({name})")
        return policy

    def get_policy(self, policy_id: str) -> PolicyMetadata:
        """
        Получить политику по ID.

        Args:
            policy_id: ID политики.

        Returns:
            Метаданные политики.

        Raises:
            PolicyNotFoundError: Если политика не найдена.
        """
        if policy_id not in self.policies:
            raise PolicyNotFoundError(f"Policy {policy_id} not found")

        policy = self.policies[policy_id]

        # Проверка срока действия
        self._check_expiry(policy)

        return policy

    def get_policies(
        self,
        status: Optional[PolicyStatus] = None,
        policy_type: Optional[PolicyType] = None,
    ) -> List[PolicyMetadata]:
        """
        Получить список политик.

        Args:
            status: Фильтр по статусу.
            policy_type: Фильтр по типу.

        Returns:
            Список политик.
        """
        result = list(self.policies.values())

        if status:
            result = [p for p in result if p.status == status]

        if policy_type:
            result = [p for p in result if p.policy_type == policy_type]

        return sorted(result, key=lambda p: p.created_at, reverse=True)

    def get_active_policies(
        self,
        roles: Optional[List[str]] = None,
        action: Optional[str] = None,
    ) -> List[PolicyMetadata]:
        """
        Получить активные политики.

        Args:
            roles: Фильтр по ролям.
            action: Фильтр по действию.

        Returns:
            Список активных политик, применимых к ролям/действию.
        """
        active = [p for p in self.policies.values() if p.status == PolicyStatus.ACTIVE]

        # Проверка срока действия
        result = []
        for policy in active:
            self._check_expiry(policy)
            if policy.status == PolicyStatus.ACTIVE:
                if roles and policy.roles and not set(roles) & set(policy.roles):
                    continue
                if (
                    action
                    and policy.allowed_actions
                    and action not in policy.allowed_actions
                ):
                    continue
                result.append(policy)

        return sorted(result, key=lambda p: p.priority if hasattr(p, "priority") else 0)

    def update_policy(
        self,
        policy_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        policy_type: Optional[PolicyType] = None,
        severity: Optional[PolicySeverity] = None,
        status: Optional[PolicyStatus] = None,
        allowed_actions: Optional[List[str]] = None,
        denied_actions: Optional[List[str]] = None,
        roles: Optional[List[str]] = None,
        max_protection_level: Optional[str] = None,
        min_key_size: Optional[int] = None,
        max_file_size: Optional[int] = None,
        password_min_length: Optional[int] = None,
        require_mfa: Optional[bool] = None,
        require_token: Optional[bool] = None,
        valid_from: Optional[datetime] = None,
        valid_until: Optional[datetime] = None,
        conditions: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> PolicyMetadata:
        """
        Обновить политику.

        Args:
            policy_id: ID обновляемой политики.
            Параметры аналогичны create_policy, но все необязательные.

        Returns:
            Обновленная политика.

        Raises:
            PolicyNotFoundError: Если политика не найдена.
            InvalidPolicyError: Если параметры невалидны.
        """
        if policy_id not in self.policies:
            raise PolicyNotFoundError(f"Policy {policy_id} not found")

        policy = self.policies[policy_id]

        # Проверка срока действия до обновления
        self._check_expiry(policy)

        # Валидация новых параметров
        self._validate_policy_params(
            name=name or policy.name,
            allowed_actions=(
                allowed_actions
                if allowed_actions is not None
                else policy.allowed_actions
            ),
            denied_actions=(
                denied_actions if denied_actions is not None else policy.denied_actions
            ),
            roles=roles if roles is not None else policy.roles,
            max_protection_level=(
                max_protection_level
                if max_protection_level is not None
                else policy.max_protection_level
            ),
            min_key_size=(
                min_key_size if min_key_size is not None else policy.min_key_size
            ),
            password_min_length=(
                password_min_length
                if password_min_length is not None
                else policy.password_min_length
            ),
        )

        # Обновление полей
        if name is not None:
            policy.name = name
        if description is not None:
            policy.description = description
        if policy_type is not None:
            policy.policy_type = policy_type
        if severity is not None:
            policy.severity = severity
        if status is not None:
            policy.status = status
        if allowed_actions is not None:
            policy.allowed_actions = allowed_actions
        if denied_actions is not None:
            policy.denied_actions = denied_actions
        if roles is not None:
            policy.roles = roles
        if max_protection_level is not None:
            policy.max_protection_level = max_protection_level
        if min_key_size is not None:
            policy.min_key_size = min_key_size
        if max_file_size is not None:
            policy.max_file_size = max_file_size
        if password_min_length is not None:
            policy.password_min_length = password_min_length
        if require_mfa is not None:
            policy.require_mfa = require_mfa
        if require_token is not None:
            policy.require_token = require_token
        if valid_from is not None:
            policy.valid_from = valid_from
        if valid_until is not None:
            policy.valid_until = valid_until
        if conditions is not None:
            policy.conditions = conditions
        if metadata is not None:
            policy.metadata = metadata
        if tags is not None:
            policy.tags = tags

        # Обновление версии и времени
        policy.version += 1
        policy.updated_at = datetime.utcnow()

        # Проверка срока действия после обновления
        self._check_expiry(policy)

        self._save_policies()

        # Аудит обновления
        self.audit_action(
            user_id="system",
            action=Action.POLICY_MANAGE,
            result="success",
            details={"event": "update_policy", "policy_id": policy_id},
        )

        logger.info(f"Policy updated: {policy_id} (version={policy.version})")
        return policy

    def delete_policy(self, policy_id: str, force: bool = False) -> None:
        """
        Удалить политику.

        Args:
            policy_id: ID политики.
            force: Принудительное удаление (даже если политика применяется).

        Raises:
            PolicyNotFoundError: Если политика не найдена.
            PolicyError: Если политика критически важна и force=False.
        """
        if policy_id not in self.policies:
            raise PolicyNotFoundError(f"Policy {policy_id} not found")

        # Защита встроенных политик
        if policy_id in self._default_policy_ids and not force:
            raise PolicyManagerError(
                f"Policy {policy_id} is a built-in policy. "
                "Use force=True to delete it."
            )

        # Удаление
        removed = self.policies.pop(policy_id)

        # Если это была последняя политика, восстановить дефолтные
        if not self.policies:
            self._ensure_default_policies()

        self._save_policies()

        # Аудит удаления
        self.audit_action(
            user_id="system",
            action=Action.POLICY_MANAGE,
            result="success",
            details={
                "event": "delete_policy",
                "policy_id": policy_id,
                "name": removed.name,
            },
        )

        logger.info(f"Policy deleted: {policy_id} ({removed.name})")

    # ------------------------------------------------------------------------
    # ПРОВЕРКА ПРАВ ДОСТУПА
    # ------------------------------------------------------------------------

    def check_access(
        self,
        user_id: str,
        action: str,
        roles: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        """
        Проверить доступ пользователя к операции.

        Args:
            user_id: ID пользователя.
            action: Действие (из Action).
            roles: Роли пользователя.
            context: Контекст операции (дополнительная информация).

        Returns:
            Решение о доступе.

        Пример:
            decision = pm.check_access(
                user_id="user1",
                action=Action.ENCRYPT,
                roles=[Role.ADMIN],
                context={"protection_level": "hyper"},
            )
        """
        context = context or {}

        # Находим применимые политики для ролей и действия
        active_policies = self._get_applicable_policies(
            roles=roles or [],
            action=action,
        )

        # Если политик нет и строгий режим - запрещаем
        if not active_policies:
            if self.strict_mode and roles:
                reasons = [f"No policy allows action '{action}' for roles {roles}"]
                return PolicyDecision(allowed=False, reasons=reasons)
            else:
                # В нестрогом режиме разрешаем, если нет запретов
                return PolicyDecision(allowed=True, warnings=["No policies found"])

        reasons = []
        warnings = []

        # Проверка явных запретов (имеют приоритет)
        for policy in active_policies:
            if action in policy.denied_actions:
                reasons.append(
                    f"Action '{action}' is explicitly denied by policy "
                    f"'{policy.name}' ({policy.policy_id})"
                )
                return PolicyDecision(
                    allowed=False,
                    policy_id=policy.policy_id,
                    policy_name=policy.name,
                    reasons=reasons,
                )

        # Проверка разрешений
        allowed_by_policy = None
        for policy in active_policies:
            if action in policy.allowed_actions:
                allowed_by_policy = policy
                break

        if allowed_by_policy is None:
            if self.strict_mode:
                reasons.append(
                    f"No active policy allows action '{action}' " f"for user {user_id}"
                )
                return PolicyDecision(allowed=False, reasons=reasons)
            else:
                warnings.append(
                    f"Action '{action}' not explicitly allowed by any policy"
                )

        # Проверка контекстных условий
        if allowed_by_policy:
            # Проверка максимального уровня защиты
            protection_level = context.get("protection_level")
            if protection_level and allowed_by_policy.max_protection_level:
                if not self._is_protection_level_allowed(
                    protection_level,
                    allowed_by_policy.max_protection_level,
                ):
                    reasons.append(
                        f"Protection level '{protection_level}' exceeds "
                        f"maximum '{allowed_by_policy.max_protection_level}' "
                        f"allowed by policy '{allowed_by_policy.name}'"
                    )
                    return PolicyDecision(
                        allowed=False,
                        policy_id=allowed_by_policy.policy_id,
                        policy_name=allowed_by_policy.name,
                        reasons=reasons,
                    )

            # Проверка размера файла
            file_size = context.get("file_size")
            if file_size and allowed_by_policy.max_file_size:
                if file_size > allowed_by_policy.max_file_size:
                    reasons.append(
                        f"File size {file_size} exceeds maximum "
                        f"{allowed_by_policy.max_file_size} allowed by policy "
                        f"'{allowed_by_policy.name}'"
                    )
                    return PolicyDecision(
                        allowed=False,
                        policy_id=allowed_by_policy.policy_id,
                        policy_name=allowed_by_policy.name,
                        reasons=reasons,
                    )

            # Проверка MFA
            mfa_verified = context.get("mfa_verified", False)
            if allowed_by_policy.require_mfa and not mfa_verified:
                reasons.append(
                    f"MFA is required by policy '{allowed_by_policy.name}' "
                    f"for action '{action}'"
                )
                return PolicyDecision(
                    allowed=False,
                    policy_id=allowed_by_policy.policy_id,
                    policy_name=allowed_by_policy.name,
                    reasons=reasons,
                    conditions_required=["mfa_verified"],
                )

            # Проверка токена
            token_verified = context.get("token_verified", False)
            if allowed_by_policy.require_token and not token_verified:
                reasons.append(
                    f"Hardware token is required by policy "
                    f"'{allowed_by_policy.name}' for action '{action}'"
                )
                return PolicyDecision(
                    allowed=False,
                    policy_id=allowed_by_policy.policy_id,
                    policy_name=allowed_by_policy.name,
                    reasons=reasons,
                    conditions_required=["token_verified"],
                )

        # Все проверки пройдены - разрешаем
        return PolicyDecision(
            allowed=True,
            policy_id=allowed_by_policy.policy_id if allowed_by_policy else None,
            policy_name=allowed_by_policy.name if allowed_by_policy else None,
            reasons=reasons or [f"Action '{action}' allowed"],
            warnings=warnings,
        )

    def validate_operation(
        self,
        action: str,
        roles: Optional[List[str]] = None,
        protection_level: Optional[str] = None,
        key_available: bool = True,
        key_size: Optional[int] = None,
        file_size: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
        user_id: str = "unknown",
    ) -> PolicyDecision:
        """
        Валидировать операцию перед выполнением.

        Проверяет, разрешена ли операция политиками, учитывая:
        - Роли пользователя
        - Уровень защиты
        - Наличие ключа
        - Размер ключа
        - Размер файла

        Args:
            action: Действие (из Action).
            roles: Роли пользователя.
            protection_level: Запрашиваемый уровень защиты.
            key_available: Доступен ли ключ.
            key_size: Размер ключа (байт).
            file_size: Размер файла (байт).
            context: Дополнительный контекст.
            user_id: ID пользователя.

        Returns:
            Решение о разрешении операции.

        Raises:
            AccessDeniedError: Если операция запрещена и raise_on_deny=True.
        """
        # Объединяем контекст
        context = context or {}
        if protection_level:
            context["protection_level"] = protection_level
        if file_size is not None:
            context["file_size"] = file_size
        if key_size is not None:
            context["key_size"] = key_size

        # Базовая проверка доступа
        decision = self.check_access(
            user_id=user_id,
            action=action,
            roles=roles,
            context=context,
        )

        if not decision.allowed:
            return decision

        # Дополнительные проверки для операций с ключами
        if action in (Action.ENCRYPT, Action.DECRYPT):
            config = context or {}

            # Проверка наличия ключа
            if not key_available:
                decision.allowed = False
                decision.reasons.append("No encryption key available")
                return decision

            # Проверка минимального размера ключа
            if key_size:
                min_size = self._get_min_key_size(roles or [])
                if min_size > 0 and key_size < min_size:
                    decision.allowed = False
                    decision.reasons.append(
                        f"Key size {key_size} bytes is less than "
                        f"minimum {min_size} bytes required"
                    )
                    return decision

        # Проверка уровня защиты
        if protection_level:
            # Проверяем, что уровень защиты поддерживается
            allowed_levels = self._get_allowed_protection_levels(roles or [])
            if allowed_levels and protection_level not in allowed_levels:
                decision.allowed = False
                decision.reasons.append(
                    f"Protection level '{protection_level}' is not allowed "
                    f"for roles {roles}. Allowed: {allowed_levels}"
                )
                return decision

        # Аудит валидации
        self.audit_action(
            user_id=user_id,
            action=action,
            result="success" if decision.allowed else "denied",
            details={
                "roles": roles,
                "protection_level": protection_level,
                "key_available": key_available,
                "decision": decision.to_dict(),
            },
        )

        return decision

    def enforce_policy(
        self,
        user_id: str,
        action: str,
        roles: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Применить политику (бросает исключение при запрете).

        В отличие от validate_operation, бросает исключение
        при нарушении политики, что останавливает операцию.

        Args:
            user_id: ID пользователя.
            action: Действие.
            roles: Роли пользователя.
            context: Контекст.

        Raises:
            AccessDeniedError: Если доступ запрещен.
            OperationNotAllowedError: Если операция не разрешена.
        """
        decision = self.check_access(
            user_id=user_id,
            action=action,
            roles=roles,
            context=context,
        )

        if not decision.allowed:
            # Формируем сообщение
            message = f"Access denied for user {user_id} to action '{action}'"
            if decision.reasons:
                message += ": " + "; ".join(decision.reasons)

            # Определяем тип исключения
            if any("denied" in r for r in decision.reasons):
                raise AccessDeniedError(message)
            else:
                raise OperationNotAllowedError(message)

    def can_perform(
        self,
        user_id: str,
        action: str,
        roles: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Быстрая проверка разрешения операции (без исключений).

        Args:
            user_id: ID пользователя.
            action: Действие.
            roles: Роли.
            context: Контекст.

        Returns:
            True если операция разрешена.
        """
        decision = self.check_access(
            user_id=user_id,
            action=action,
            roles=roles,
            context=context,
        )
        return decision.allowed

    # ------------------------------------------------------------------------
    # АУДИТ
    # ------------------------------------------------------------------------

    def audit_action(
        self,
        user_id: str,
        action: str,
        result: str,
        details: Optional[Dict[str, Any]] = None,
        policy_id: Optional[str] = None,
    ) -> None:
        """
        Записать действие в журнал аудита.

        Args:
            user_id: ID пользователя.
            action: Выполненное действие.
            result: Результат (success, denied, failed).
            details: Дополнительные детали.
            policy_id: ID примененной политики.
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "action": action,
            "result": result,
            "policy_id": policy_id,
            "details": details or {},
        }

        # Подпись записи (в идеале через audit_manager)
        entry["signature"] = self._sign_audit_entry(entry)

        self.audit_log.append(entry)

        # Ограничение размера журнала
        if len(self.audit_log) > self._audit_limit:
            self.audit_log = self.audit_log[-self._audit_limit :]

        logger.debug(f"Audit: {user_id} -> {action} ({result})")

    def get_audit_log(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Получить журнал аудита.

        Args:
            user_id: Фильтр по пользователю.
            action: Фильтр по действию.
            limit: Максимальное количество записей.

        Returns:
            Список записей аудита.
        """
        result = self.audit_log

        if user_id:
            result = [e for e in result if e["user_id"] == user_id]

        if action:
            result = [e for e in result if e["action"] == action]

        return result[-limit:][::-1]  # Последние записи первыми

    # ------------------------------------------------------------------------
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ - ПРОВЕРКИ
    # ------------------------------------------------------------------------

    def _get_applicable_policies(
        self,
        roles: List[str],
        action: str,
    ) -> List[PolicyMetadata]:
        """
        Получить политики, применимые к ролям и действию.

        Args:
            roles: Роли пользователя.
            action: Действие.

        Returns:
            Список политик, которые могут применяться.
        """
        applicable = []

        for policy in self.policies.values():
            # Проверка статуса
            if policy.status != PolicyStatus.ACTIVE:
                continue

            # Проверка срока действия
            self._check_expiry(policy)
            if policy.status != PolicyStatus.ACTIVE:
                continue

            # Проверка ролей (если указаны)
            if policy.roles and roles:
                if not set(roles) & set(policy.roles):
                    continue
            elif policy.roles and not roles:
                # Политика для конкретных ролей, но роли не указаны
                continue

            # Проверка действия
            if policy.allowed_actions and action not in policy.allowed_actions:
                # Может быть в denied_actions
                if action not in policy.denied_actions:
                    continue

            applicable.append(policy)

        # Сортировка по строгости (сначала более строгие)
        severity_order = {
            PolicySeverity.LOW: 0,
            PolicySeverity.MEDIUM: 1,
            PolicySeverity.HIGH: 2,
            PolicySeverity.CRITICAL: 3,
        }
        applicable.sort(
            key=lambda p: severity_order.get(p.severity, 0),
            reverse=True,
        )

        return applicable

    def _get_min_key_size(self, roles: List[str]) -> int:
        """Получить минимальный размер ключа для ролей."""
        sizes = []
        for policy in self.get_active_policies(roles=roles):
            if policy.min_key_size > 0:
                sizes.append(policy.min_key_size)
        return max(sizes) if sizes else 0

    def _get_allowed_protection_levels(self, roles: List[str]) -> List[str]:
        """Получить разрешенные уровни защиты для ролей."""
        # Все уровни
        all_levels = [
            constants.ProtectionLevel.ORIGINAL,
            constants.ProtectionLevel.INDIVIDUAL,
            constants.ProtectionLevel.CONTAINER,
            constants.ProtectionLevel.HYPER,
        ]

        # Максимально разрешенный уровень
        max_level = None
        for policy in self.get_active_policies(roles=roles):
            if policy.max_protection_level:
                if max_level is None or self._level_rank(
                    policy.max_protection_level
                ) < self._level_rank(max_level):
                    max_level = policy.max_protection_level

        if max_level is None:
            return all_levels

        max_rank = self._level_rank(max_level)
        return [level for level in all_levels if self._level_rank(level) <= max_rank]

    @staticmethod
    def _level_rank(level: str) -> int:
        """Получить ранг уровня защиты (чем выше, тем безопаснее)."""
        ranks = {
            constants.ProtectionLevel.ORIGINAL: 0,
            constants.ProtectionLevel.INDIVIDUAL: 1,
            constants.ProtectionLevel.CONTAINER: 2,
            constants.ProtectionLevel.HYPER: 3,
        }
        return ranks.get(level, 0)

    def _is_protection_level_allowed(self, requested: str, max_allowed: str) -> bool:
        """Проверить, что уровень защиты не превышает максимум."""
        return self._level_rank(requested) <= self._level_rank(max_allowed)

    def _check_expiry(self, policy: PolicyMetadata) -> None:
        """
        Проверить срок действия политики.
        Если политика истекла, обновить статус.
        """
        now = datetime.utcnow()

        if policy.valid_until and now > policy.valid_until:
            if policy.status != PolicyStatus.EXPIRED:
                policy.status = PolicyStatus.EXPIRED
                policy.updated_at = now
                self._save_policies()
                logger.warning(f"Policy {policy.policy_id} expired")

        elif policy.valid_from and now < policy.valid_from:
            if policy.status == PolicyStatus.ACTIVE:
                policy.status = PolicyStatus.PENDING
                policy.updated_at = now
                self._save_policies()

    def _validate_policy_params(
        self,
        name: str,
        allowed_actions: List[str],
        denied_actions: List[str],
        roles: List[str],
        max_protection_level: Optional[str],
        min_key_size: int,
        password_min_length: int,
    ) -> None:
        """Валидация параметров политики."""
        # Имя
        if not name or not name.strip():
            raise InvalidPolicyError("Policy name cannot be empty")
        if len(name) > 128:
            raise InvalidPolicyError("Policy name is too long (max 128 chars)")

        # Действия
        if allowed_actions:
            invalid = [a for a in allowed_actions if a not in constants.POLICY_ACTIONS]
            if invalid:
                raise InvalidPolicyError(f"Invalid actions: {invalid}")

        if denied_actions:
            invalid = [a for a in denied_actions if a not in constants.POLICY_ACTIONS]
            if invalid:
                raise InvalidPolicyError(f"Invalid actions: {invalid}")

        # Пересечение allowed и denied
        if set(allowed_actions) & set(denied_actions):
            raise InvalidPolicyError(
                f"Cannot have actions in both allowed and denied: "
                f"{set(allowed_actions) & set(denied_actions)}"
            )

        # Роли
        if roles:
            invalid = [r for r in roles if r not in constants.USER_ROLES]
            if invalid:
                raise InvalidPolicyError(f"Invalid roles: {invalid}")

        # Уровень защиты
        if max_protection_level:
            if max_protection_level not in constants.PROTECTION_LEVELS:
                raise InvalidPolicyError(
                    f"Invalid protection level: {max_protection_level}"
                )

        # Проверка размеров
        if min_key_size < 0 or min_key_size > 64:
            raise InvalidPolicyError("min_key_size must be 0..64 bytes")

        if password_min_length < 4 or password_min_length > 64:
            raise InvalidPolicyError("password_min_length must be 4..64 chars")

    # ------------------------------------------------------------------------
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ - ХРАНЕНИЕ
    # ------------------------------------------------------------------------

    def _generate_policy_id(self, name: str) -> str:
        """Генерация ID политики."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        name_hash = hashlib.sha256(name.encode()).hexdigest()[:8]
        return f"pol-{timestamp}-{name_hash}"

    def _sign_audit_entry(self, entry: Dict[str, Any]) -> str:
        """
        Подписать запись аудита.

        Использует HMAC-SHA256 с ключом, производным от имени
        политики и временной метки. В продакшене использовать
        ECDSA через audit_manager.
        """
        # Сериализация записи (без подписи)
        data = json.dumps(
            {k: v for k, v in entry.items() if k != "signature"},
            sort_keys=True,
            default=str,
        ).encode()

        # Вычисляем подпись
        import hashlib

        return hashlib.sha256(data).hexdigest()[:16]

    def _load_policies(self) -> None:
        """Загрузить политики из файла."""
        if not self.policy_file.exists():
            self.policies = {}
            return

        try:
            with open(self.policy_file, "r") as f:
                data = json.load(f)
                self.policies = {
                    policy_id: PolicyMetadata.from_dict(policy_data)
                    for policy_id, policy_data in data.items()
                }
            logger.debug(f"Loaded {len(self.policies)} policies")

        except Exception as e:
            logger.error(f"Failed to load policies: {e}")
            self.policies = {}

    def _save_policies(self) -> None:
        """Сохранить политики в файл."""
        try:
            data = {
                policy_id: policy.to_dict()
                for policy_id, policy in self.policies.items()
            }
            with open(self.policy_file, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved {len(self.policies)} policies")

        except Exception as e:
            logger.error(f"Failed to save policies: {e}")

    # ------------------------------------------------------------------------
    # ПОЛИТИКИ ПО УМОЛЧАНИЮ
    # ------------------------------------------------------------------------

    @property
    def _default_policy_ids(self) -> Set[str]:
        """ID встроенных политик."""
        return {"default-user", "default-admin", "default-auditor"}

    def _ensure_default_policies(self) -> None:
        """Создать политики по умолчанию, если их нет."""
        # Проверяем, есть ли хотя бы одна политика
        if self.policies:
            return

        logger.info("Creating default policies...")

        # 1. Политика для обычного пользователя
        self.create_policy(
            policy_id="default-user",
            name="Standard User",
            description="Политика для обычных пользователей SecureVault",
            policy_type=PolicyType.ACCESS,
            severity=PolicySeverity.MEDIUM,
            allowed_actions=[
                Action.ENCRYPT,
                Action.DECRYPT,
                Action.CREATE_CONTAINER,
                Action.MOUNT_CONTAINER,
                Action.UNMOUNT_CONTAINER,
                Action.ADD_FILE,
                Action.EXTRACT_FILE,
                Action.DELETE_FILE,
                Action.INTEGRITY_CHECK,
            ],
            roles=[Role.USER],
            max_protection_level=constants.ProtectionLevel.HYPER,
            password_min_length=12,
            require_mfa=False,
            require_token=False,
            tags=["default", "user"],
        )

        # 2. Политика для администратора
        self.create_policy(
            policy_id="default-admin",
            name="Administrator",
            description="Политика для администраторов SecureVault",
            policy_type=PolicyType.ACCESS,
            severity=PolicySeverity.CRITICAL,
            allowed_actions=constants.POLICY_ACTIONS,
            roles=[Role.ADMIN],
            max_protection_level=constants.ProtectionLevel.HYPER,
            password_min_length=14,
            require_mfa=True,
            require_token=True,
            tags=["default", "admin"],
        )

        # 3. Политика для аудитора
        self.create_policy(
            policy_id="default-auditor",
            name="Auditor",
            description="Политика для аудиторов SecureVault",
            policy_type=PolicyType.COMPLIANCE,
            severity=PolicySeverity.HIGH,
            allowed_actions=[
                Action.AUDIT_VIEW,
                Action.INTEGRITY_CHECK,
            ],
            roles=[Role.AUDITOR],
            max_protection_level=constants.ProtectionLevel.CONTAINER,
            password_min_length=12,
            require_mfa=True,
            require_token=False,
            tags=["default", "auditor"],
        )

        self._save_policies()
        logger.info(f"Created {len(self._default_policy_ids)} default policies")


# ============================================================================
# ФУНКЦИИ ВЫСОКОГО УРОВНЯ
# ============================================================================


def create_policy_manager(
    storage_dir: Optional[str] = None,
) -> PolicyManager:
    """
    Фабричная функция для создания PolicyManager.

    Args:
        storage_dir: Директория хранения политик.

    Returns:
        Инициализированный PolicyManager.
    """
    pm = PolicyManager(storage_dir=storage_dir)
    pm.initialize()
    return pm


def quick_check_access(
    action: str,
    roles: Optional[List[str]] = None,
) -> bool:
    """
    Быстрая проверка доступа без создания экземпляра.

    Args:
        action: Действие.
        roles: Роли.

    Returns:
        True если доступ разрешен.
    """
    pm = PolicyManager()
    return pm.can_perform("quick-check", action, roles=roles)


# ============================================================================
# ЭКСПОРТ
# ============================================================================

__all__ = [
    # Классы
    "PolicyManager",
    "PolicyMetadata",
    "PolicyDecision",
    # Константы
    "PolicyStatus",
    "PolicyType",
    "PolicySeverity",
    "Decision",
    "Action",
    "Role",
    # Исключения
    "PolicyManagerError",
    "PolicyNotFoundError",
    "PolicyAlreadyExistsError",
    "PolicyViolationError",
    "AccessDeniedError",
    "OperationNotAllowedError",
    "InvalidPolicyError",
    "PolicyExpiredError",
    # Функции
    "create_policy_manager",
    "quick_check_access",
]
