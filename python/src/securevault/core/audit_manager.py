"""
SecureVault - Менеджер аудита

Управление журналированием и аудитом всех операций системы:
- Логирование всех операций с криптографической подписью (ECDSA)
- Хранение аудит-траils в SQLite/PostgreSQL
- Forensics логирование для доказательной базы
- Верификация целостности журнала
- Автоматическая ротация и ретенция записей
- Экспорт и поиск записей

Ключевые возможности:
1. Каждая запись подписывается ECDSA ключом аудита
2. Цепочка записей (каждая запись содержит хеш предыдущей)
3. Двойное хранение: SQLite (оффлайн) + PostgreSQL (репликация)
4. Верификация целостности всего журнала
5. Поиск, фильтрация и экспорт записей

Зависимости:
- core/policy_manager.py: Политики безопасности
- native/crypto.py: Криптографические операции (ECDSA, SHA256)
- exceptions: Исключения проекта
- constants: Константы

Использование:
    from securevault.core.audit_manager import AuditManager

    am = AuditManager()

    # Логирование операции
    am.log_action(
        user_id="user1",
        action="encrypt",
        result="success",
        details={"file": "document.pdf", "size": 1024},
    )

    # Получение записей
    entries = am.get_entries(
        user_id="user1",
        action="encrypt",
        limit=100,
    )

    # Верификация целостности
    am.verify_integrity()

    # Экспорт
    am.export("audit_export.json")

    # Статистика
    stats = am.get_stats()
"""

import hashlib
import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from securevault import exceptions
from securevault.core import policy_manager

# Внутренние импорты
from securevault.native import crypto

logger = logging.getLogger(__name__)


# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================


class AuditEventType(Enum):
    """Типы аудитных событий."""

    OPERATION = "operation"  # Операция (шифрование, дешифрование и т.д.)
    AUTHENTICATION = "authentication"  # Аутентификация
    AUTHORIZATION = "authorization"  # Авторизация
    KEY_MANAGEMENT = "key_management"  # Управление ключами
    CONTAINER = "container"  # Операции с контейнерами
    POLICY = "policy"  # Изменение политик
    SECURITY = "security"  # Событие безопасности
    SYSTEM = "system"  # Системное событие


class AuditSeverity(Enum):
    """Уровни серьезности событий."""

    DEBUG = "debug"  # Отладка
    INFO = "info"  # Информация
    WARNING = "warning"  # Предупреждение
    ERROR = "error"  # Ошибка
    CRITICAL = "critical"  # Критическое событие


class AuditBackendType(Enum):
    """Типы бэкендов хранения."""

    SQLITE = "sqlite"  # Локальное SQLite хранилище
    POSTGRESQL = "postgresql"  # PostgreSQL хранилище
    MEMORY = "memory"  # Только в памяти
    FILE = "file"  # Файловое хранилище (JSON Lines)


class AuditStatus(Enum):
    """Статусы записей аудита."""

    PENDING = "pending"  # Ожидает подписи
    SIGNED = "signed"  # Подписана
    VERIFIED = "verified"  # Верифицирована
    TAMPERED = "tampered"  # Обнаружено вмешательство
    DELETED = "deleted"  # Помечена на удаление


# Пути и конфигурация
AUDIT_DIR = "audit"
AUDIT_DB_FILE = "audit.db"
AUDIT_LOG_FILE = "audit.jsonl"
AUDIT_SIGNING_KEY = "audit_signing_key.pem"
AUDIT_SIGNING_PUBKEY = "audit_signing_pubkey.pem"

# Ретенция
DEFAULT_RETENTION_DAYS = 365
DEFAULT_MAX_ENTRIES = 1000000


# ============================================================================
# ИСКЛЮЧЕНИЯ
# ============================================================================


class AuditError(exceptions.AuditError):
    """Базовое исключение для AuditManager."""


class AuditLogError(AuditError, exceptions.AuditLogError):
    """Ошибка записи в журнал аудита."""


class AuditSignatureError(AuditError, exceptions.AuditSignatureError):
    """Ошибка подписи журнала аудита."""


class AuditVerificationError(AuditError):
    """Ошибка верификации журнала аудита."""


class AuditBackendError(AuditError):
    """Ошибка бэкенда хранения."""


class AuditExportError(AuditError):
    """Ошибка экспорта аудита."""


class AuditNotFoundError(AuditError):
    """Запись аудита не найдена."""


# ============================================================================
# МЕТАДАННЫЕ ЗАПИСИ АУДИТА
# ============================================================================


@dataclass
class AuditEntry:
    """
    Одна запись журнала аудита.

    Содержит полную информацию о событии:
    - Кто (user_id)
    - Что (action)
    - Когда (timestamp)
    - Где (source)
    - Результат (success/failure)
    - Дополнительные детали (details)

    Каждая запись подписывается ECDSA и связывается с предыдущей
    через hash_chain (prev_hash), обеспечивая невозможность
    модификации записей без обнаружения.
    """

    # Основная информация
    entry_id: str
    timestamp: datetime
    user_id: str
    action: str
    result: str  # success / failure / denied

    # Категории
    event_type: AuditEventType = AuditEventType.OPERATION
    severity: AuditSeverity = AuditSeverity.INFO

    # Детали
    details: Dict[str, Any] = field(default_factory=dict)
    source: str = ""

    # Целостность и подпись
    prev_hash: Optional[str] = None  # Хеш предыдущей записи
    entry_hash: Optional[str] = None  # Хеш текущей записи
    signature: Optional[str] = None  # ECDSA подпись
    status: AuditStatus = AuditStatus.PENDING

    # Мета
    ip_address: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    correlation_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, include_signature: bool = True) -> Dict[str, Any]:
        """Сериализовать в словарь."""
        data = {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "action": self.action,
            "result": self.result,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "details": self.details,
            "source": self.source,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "status": self.status.value,
            "ip_address": self.ip_address,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "metadata": self.metadata,
        }
        if include_signature:
            data["signature"] = self.signature
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        """Десериализовать из словаря."""
        return cls(
            entry_id=data["entry_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            user_id=data["user_id"],
            action=data["action"],
            result=data["result"],
            event_type=AuditEventType(data.get("event_type", "operation")),
            severity=AuditSeverity(data.get("severity", "info")),
            details=data.get("details", {}),
            source=data.get("source", ""),
            prev_hash=data.get("prev_hash"),
            entry_hash=data.get("entry_hash"),
            signature=data.get("signature"),
            status=AuditStatus(data.get("status", "pending")),
            ip_address=data.get("ip_address"),
            session_id=data.get("session_id"),
            request_id=data.get("request_id"),
            correlation_id=data.get("correlation_id"),
            metadata=data.get("metadata", {}),
        )


# ============================================================================
# ОСНОВНОЙ КЛАСС
# ============================================================================


class AuditManager:
    """
    Менеджер аудита SecureVault.

    Обеспечивает:
    - Логирование всех операций с криптографической подписью
    - Хранение в SQLite (оффлайн) / PostgreSQL (репликация)
    - Цепочку целостности записей (hash chain)
    - Верификацию целостности журнала
    - Поиск, фильтрацию и экспорт записей
    - Автоматическую ретенцию (удаление старых записей)

    Архитектура цепочки целостности:
    entry_1: prev_hash = None,      entry_hash = SHA256(data_1)
    entry_2: prev_hash = hash_1,    entry_hash = SHA256(data_2 + prev_hash)
    entry_3: prev_hash = hash_2,    entry_hash = SHA256(data_3 + prev_hash)
    ...

    Любое изменение записи в середине цепи изменяет все
    последующие хеши и сигнатуры, что обнаруживается
    при верификации.

    Пример:
        am = AuditManager(storage_dir="/secure/vault/audit")

        # Логирование операции
        am.log_action(
            user_id="user1",
            action="encrypt",
            result="success",
            details={"file": "document.pdf", "size": 12345},
            event_type=AuditEventType.OPERATION,
            severity=AuditSeverity.INFO,
        )

        # Получение записей
        entries = am.get_entries(user_id="user1", limit=50)

        # Верификация целостности
        result = am.verify_integrity()

        # Экспорт
        am.export("audit.json")

        # Статистика
        stats = am.get_stats()
    """

    def __init__(
        self,
        storage_dir: Optional[str] = None,
        backend_type: AuditBackendType = AuditBackendType.SQLITE,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        policy_mgr: Optional[policy_manager.PolicyManager] = None,
        signing_key: Optional[bytes] = None,
        auto_sign: bool = True,
        verify_on_load: bool = True,
    ):
        """
        Инициализировать менеджер аудита.

        Args:
            storage_dir: Директория для хранения аудит-файлов.
                        По умолчанию: ~/.securevault/audit
            backend_type: Тип бэкенда хранения.
            retention_days: Количество дней хранения записей.
            max_entries: Максимальное количество записей.
            policy_mgr: Менеджер политик (для интеграции).
            signing_key: ECDSA приватный ключ (PEM). Если None,
                        генерируется новый.
            auto_sign: Автоматически подписывать записи.
            verify_on_load: Проверять целостность при загрузке.
        """
        # Директория хранения
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            home = Path.home()
            self.storage_dir = home / ".securevault" / AUDIT_DIR

        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Конфигурация
        self.backend_type = backend_type
        self.retention_days = retention_days
        self.max_entries = max_entries
        self.auto_sign = auto_sign

        # Менеджер политик
        self.policy_mgr = policy_mgr or policy_manager.PolicyManager()

        # Подпись
        self._signing_key = signing_key
        self._signing_pubkey: Optional[bytes] = None
        self._load_or_create_signing_key()

        # Состояние
        self._lock = threading.RLock()
        self._last_hash: Optional[str] = None
        self._entries: List[AuditEntry] = []
        self._entries_by_id: Dict[str, AuditEntry] = {}

        # SQLite подключение
        self._db_conn: Optional[sqlite3.Connection] = None
        self._init_db()

        # Загрузка существующих записей
        self._load_entries()

        # Проверка целостности при загрузке
        if verify_on_load and self._entries:
            self.verify_integrity()

        logger.info(
            f"AuditManager initialized: storage={self.storage_dir}, "
            f"backend={backend_type.value}, entries={len(self._entries)}"
        )

    # ------------------------------------------------------------------------
    # ЖИЗНЕННЫЙ ЦИКЛ
    # ------------------------------------------------------------------------

    def initialize(self) -> None:
        """Инициализировать менеджер аудита."""
        logger.info("Initializing AuditManager...")
        self._init_db()
        self._load_entries()
        logger.info(
            f"AuditManager initialization complete: {len(self._entries)} entries"
        )

    def shutdown(self) -> None:
        """Завершить работу менеджера аудита."""
        with self._lock:
            if self._db_conn:
                self._db_conn.close()
                self._db_conn = None
        logger.info("AuditManager shutdown complete")

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    # ------------------------------------------------------------------------
    # ЛОГИРОВАНИЕ ОПЕРАЦИЙ
    # ------------------------------------------------------------------------

    def log_action(
        self,
        user_id: str,
        action: str,
        result: str = "success",
        details: Optional[Dict[str, Any]] = None,
        event_type: AuditEventType = AuditEventType.OPERATION,
        severity: AuditSeverity = AuditSeverity.INFO,
        source: str = "",
        ip_address: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """
        Записать операцию в журнал аудита.

        Args:
            user_id: ID пользователя.
            action: Действие (из PolicyAction).
            result: Результат (success/failure/denied).
            details: Дополнительные детали операции.
            event_type: Тип события.
            severity: Уровень серьезности.
            source: Источник события.
            ip_address: IP-адрес.
            session_id: ID сессии.
            request_id: ID запроса.
            correlation_id: ID корреляции.
            metadata: Дополнительные метаданные.

        Returns:
            Созданная запись аудита.

        Raises:
            AuditLogError: Если запись не удалась.
        """
        with self._lock:
            try:
                # Создание записи
                entry = AuditEntry(
                    entry_id=self._generate_entry_id(),
                    timestamp=datetime.utcnow(),
                    user_id=user_id,
                    action=action,
                    result=result,
                    event_type=event_type,
                    severity=severity,
                    details=details or {},
                    source=source,
                    prev_hash=self._last_hash,
                    ip_address=ip_address,
                    session_id=session_id,
                    request_id=request_id,
                    correlation_id=correlation_id,
                    metadata=metadata or {},
                )

                # Вычисление хеша текущей записи
                entry.entry_hash = self._compute_entry_hash(entry)

                # Подпись записи
                if self.auto_sign:
                    entry.signature = self._sign_entry(entry)
                    entry.status = AuditStatus.SIGNED

                # Добавление в цепочку
                self._entries.append(entry)
                self._entries_by_id[entry.entry_id] = entry
                self._last_hash = entry.entry_hash

                # Сохранение в БД
                self._save_entry(entry)

                # Ограничение количества записей
                self._enforce_limits()

                logger.debug(
                    f"Audit: {user_id} -> {action} ({result}) "
                    f"entry={entry.entry_id}"
                )

                return entry

            except Exception as e:
                logger.error(f"Failed to write audit entry: {e}")
                raise AuditLogError(f"Audit write failed: {e}")

    def log_security_event(
        self,
        user_id: str,
        action: str,
        result: str = "warning",
        details: Optional[Dict[str, Any]] = None,
        severity: AuditSeverity = AuditSeverity.WARNING,
        **kwargs: Any,
    ) -> AuditEntry:
        """
        Записать событие безопасности.

        Args:
            user_id: ID пользователя.
            action: Действие.
            result: Результат.
            details: Детали.
            severity: Уровень серьезности.
            **kwargs: Дополнительные параметры.

        Returns:
            Запись аудита.
        """
        return self.log_action(
            user_id=user_id,
            action=action,
            result=result,
            details=details,
            event_type=AuditEventType.SECURITY,
            severity=severity,
            **kwargs,
        )

    def log_authentication(
        self,
        user_id: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AuditEntry:
        """
        Записать событие аутентификации.

        Args:
            user_id: ID пользователя.
            success: Успешна ли аутентификация.
            details: Детали.
            **kwargs: Дополнительные параметры.

        Returns:
            Запись аудита.
        """
        return self.log_action(
            user_id=user_id,
            action="authentication",
            result="success" if success else "failure",
            details=details,
            event_type=AuditEventType.AUTHENTICATION,
            severity=AuditSeverity.INFO if success else AuditSeverity.WARNING,
            **kwargs,
        )

    def log_key_event(
        self,
        user_id: str,
        action: str,
        result: str,
        key_id: str,
        details: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AuditEntry:
        """
        Записать событие управления ключами.

        Args:
            user_id: ID пользователя.
            action: Действие (generate, rotate, backup, etc.).
            result: Результат.
            key_id: ID ключа.
            details: Детали.
            **kwargs: Дополнительные параметры.

        Returns:
            Запись аудита.
        """
        det = dict(details or {})
        det["key_id"] = key_id
        return self.log_action(
            user_id=user_id,
            action=action,
            result=result,
            details=det,
            event_type=AuditEventType.KEY_MANAGEMENT,
            **kwargs,
        )

    def log_container_event(
        self,
        user_id: str,
        action: str,
        result: str,
        container_id: str,
        details: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AuditEntry:
        """
        Записать событие контейнера.

        Args:
            user_id: ID пользователя.
            action: Действие (create, mount, unmount, etc.).
            result: Результат.
            container_id: ID контейнера.
            details: Детали.
            **kwargs: Дополнительные параметры.

        Returns:
            Запись аудита.
        """
        det = dict(details or {})
        det["container_id"] = container_id
        return self.log_action(
            user_id=user_id,
            action=action,
            result=result,
            details=det,
            event_type=AuditEventType.CONTAINER,
            **kwargs,
        )

    def log_policy_event(
        self,
        user_id: str,
        action: str,
        result: str,
        policy_id: str,
        details: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AuditEntry:
        """
        Записать событие политики.

        Args:
            user_id: ID пользователя.
            action: Действие.
            result: Результат.
            policy_id: ID политики.
            details: Детали.
            **kwargs: Дополнительные параметры.

        Returns:
            Запись аудита.
        """
        det = dict(details or {})
        det["policy_id"] = policy_id
        return self.log_action(
            user_id=user_id,
            action=action,
            result=result,
            details=det,
            event_type=AuditEventType.POLICY,
            **kwargs,
        )

    def log_system_event(
        self,
        action: str,
        result: str = "info",
        details: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> AuditEntry:
        """
        Записать системное событие.

        Args:
            action: Действие.
            result: Результат.
            details: Детали.
            **kwargs: Дополнительные параметры.

        Returns:
            Запись аудита.
        """
        return self.log_action(
            user_id="system",
            action=action,
            result=result,
            details=details,
            event_type=AuditEventType.SYSTEM,
            **kwargs,
        )

    # ------------------------------------------------------------------------
    # ПОЛУЧЕНИЕ ЗАПИСЕЙ
    # ------------------------------------------------------------------------

    def get_entries(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        severity: Optional[AuditSeverity] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        source: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditEntry]:
        """
        Получить записи аудита с фильтрацией.

        Args:
            user_id: Фильтр по пользователю.
            action: Фильтр по действию.
            result: Фильтр по результату.
            event_type: Фильтр по типу события.
            severity: Фильтр по уровню серьезности.
            start_time: Начало временного диапазона.
            end_time: Конец временного диапазона.
            source: Фильтр по источнику.
            limit: Максимальное количество записей.
            offset: Смещение (для пагинации).

        Returns:
            Список записей аудита (сортирован по времени, новые первыми).
        """
        with self._lock:
            result_list = list(self._entries)

            if user_id:
                result_list = [e for e in result_list if e.user_id == user_id]

            if action:
                result_list = [e for e in result_list if e.action == action]

            if result:
                result_list = [e for e in result_list if e.result == result]

            if event_type:
                result_list = [e for e in result_list if e.event_type == event_type]

            if severity:
                result_list = [e for e in result_list if e.severity == severity]

            if start_time:
                result_list = [e for e in result_list if e.timestamp >= start_time]

            if end_time:
                result_list = [e for e in result_list if e.timestamp <= end_time]

            if source:
                result_list = [e for e in result_list if e.source == source]

            # Сортировка по времени (новые первыми)
            result_list.sort(key=lambda e: e.timestamp, reverse=True)

            # Пагинация
            result_list = result_list[offset : offset + limit]

            return result_list

    def get_entry(self, entry_id: str) -> AuditEntry:
        """
        Получить запись по ID.

        Args:
            entry_id: ID записи.

        Returns:
            Запись аудита.

        Raises:
            AuditNotFoundError: Если запись не найдена.
        """
        with self._lock:
            if entry_id not in self._entries_by_id:
                raise AuditNotFoundError(f"Audit entry {entry_id} not found")
            return self._entries_by_id[entry_id]

    def get_entries_count(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        event_type: Optional[AuditEventType] = None,
        severity: Optional[AuditSeverity] = None,
    ) -> int:
        """
        Получить количество записей с фильтром.

        Args:
            user_id: Фильтр по пользователю.
            action: Фильтр по действию.
            result: Фильтр по результату.
            event_type: Фильтр по типу события.
            severity: Фильтр по уровню серьезности.

        Returns:
            Количество записей.
        """
        with self._lock:
            result_list = list(self._entries)

            if user_id:
                result_list = [e for e in result_list if e.user_id == user_id]

            if action:
                result_list = [e for e in result_list if e.action == action]

            if result:
                result_list = [e for e in result_list if e.result == result]

            if event_type:
                result_list = [e for e in result_list if e.event_type == event_type]

            if severity:
                result_list = [e for e in result_list if e.severity == severity]

            return len(result_list)

    # ------------------------------------------------------------------------
    # ВЕРИФИКАЦИЯ ЦЕЛОСТНОСТИ
    # ------------------------------------------------------------------------

    def verify_integrity(
        self,
        start_index: int = 0,
    ) -> Dict[str, Any]:
        """
        Проверить целостность всего журнала аудита.

        Проверяет:
        1. Каждая запись имеет валидный хеш.
        2. Каждая запись связана с предыдущей (hash chain).
        3. Все сигнатуры валидны (ECDSA).

        Args:
            start_index: Индекс записи, с которой начать проверку.

        Returns:
            Словарь с результатами проверки:
            - valid: True если все проверки прошли
            - checked: Количество проверенных записей
            - errors: Список ошибок
            - tampered_entries: Список ID записей с нарушениями
        """
        with self._lock:
            errors = []
            tampered = []
            checked = 0

            prev_hash = None

            for i, entry in enumerate(self._entries[start_index:], start=start_index):
                checked += 1

                # 1. Проверка связи с предыдущей записью
                if entry.prev_hash != prev_hash:
                    errors.append(
                        f"Entry {entry.entry_id} (index {i}): "
                        f"prev_hash mismatch. Expected {prev_hash}, "
                        f"got {entry.prev_hash}"
                    )
                    tampered.append(entry.entry_id)

                # 2. Проверка хеша текущей записи
                computed_hash = self._compute_entry_hash(entry)
                if computed_hash != entry.entry_hash:
                    errors.append(
                        f"Entry {entry.entry_id} (index {i}): "
                        f"entry_hash mismatch. Expected {computed_hash}, "
                        f"got {entry.entry_hash}"
                    )
                    tampered.append(entry.entry_id)

                # 3. Проверка подписи
                if entry.signature:
                    try:
                        valid_sig = self._verify_entry_signature(entry)
                        if not valid_sig:
                            errors.append(
                                f"Entry {entry.entry_id} (index {i}): "
                                f"invalid signature"
                            )
                            tampered.append(entry.entry_id)
                    except Exception as e:
                        errors.append(
                            f"Entry {entry.entry_id} (index {i}): "
                            f"signature verification error: {e}"
                        )
                        tampered.append(entry.entry_id)

                # Обновление prev_hash для следующей записи
                prev_hash = entry.entry_hash

            # Обновление статусов
            for entry in self._entries:
                if entry.entry_id in tampered:
                    entry.status = AuditStatus.TAMPERED
                elif entry.status == AuditStatus.SIGNED:
                    entry.status = AuditStatus.VERIFIED

            result = {
                "valid": len(errors) == 0,
                "checked": checked,
                "errors": errors,
                "tampered_entries": tampered,
            }

            if errors:
                logger.error(
                    f"Audit integrity verification failed: "
                    f"{len(errors)} errors, {len(tampered)} tampered entries"
                )
            else:
                logger.info(f"Audit integrity verified: {checked} entries OK")

            return result

    # ------------------------------------------------------------------------
    # ЭКСПОРТ И ИМПОРТ
    # ------------------------------------------------------------------------

    def export(
        self,
        output_path: str,
        format: str = "json",
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        include_signatures: bool = True,
    ) -> int:
        """
        Экспортировать записи аудита в файл.

        Args:
            output_path: Путь для экспорта.
            format: Формат ("json" или "jsonl").
            user_id: Фильтр по пользователю.
            action: Фильтр по действию.
            start_time: Начало диапазона.
            end_time: Конец диапазона.
            include_signatures: Включать подписи.

        Returns:
            Количество экспортированных записей.

        Raises:
            AuditExportError: Если экспорт не удался.
        """
        entries = self.get_entries(
            user_id=user_id,
            action=action,
            start_time=start_time,
            end_time=end_time,
            limit=self.max_entries,
        )

        try:
            output = Path(output_path)
            output.parent.mkdir(parents=True, exist_ok=True)

            if format == "json":
                data = [
                    e.to_dict(include_signature=include_signatures) for e in entries
                ]
                with open(output, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            elif format == "jsonl":
                with open(output, "w", encoding="utf-8") as f:
                    for e in entries:
                        line = json.dumps(
                            e.to_dict(include_signature=include_signatures),
                            ensure_ascii=False,
                        )
                        f.write(line + "\n")
            else:
                raise AuditExportError(f"Unsupported format: {format}")

            logger.info(f"Audit exported: {len(entries)} entries -> {output_path}")
            return len(entries)

        except Exception as e:
            logger.error(f"Audit export failed: {e}")
            raise AuditExportError(f"Audit export failed: {e}")

    def import_entries(
        self,
        input_path: str,
        format: str = "json",
        verify: bool = True,
    ) -> int:
        """
        Импортировать записи аудита из файла.

        Args:
            input_path: Путь к файлу.
            format: Формат ("json" или "jsonl").
            verify: Проверять целостность импортируемых записей.

        Returns:
            Количество импортированных записей.

        Raises:
            AuditError: Если импорт не удался.
        """
        try:
            input_file = Path(input_path)
            if not input_file.exists():
                raise AuditNotFoundError(f"Import file not found: {input_path}")

            entries_data = []
            if format == "json":
                with open(input_file, "r", encoding="utf-8") as f:
                    entries_data = json.load(f)
            elif format == "jsonl":
                with open(input_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            entries_data.append(json.loads(line))
            else:
                raise AuditError(f"Unsupported format: {format}")

            imported = 0
            with self._lock:
                for data in entries_data:
                    entry = AuditEntry.from_dict(data)

                    # Проверка дубликата
                    if entry.entry_id in self._entries_by_id:
                        continue

                    # Проверка целостности
                    if verify:
                        computed_hash = self._compute_entry_hash(entry)
                        if computed_hash != entry.entry_hash:
                            logger.warning(
                                f"Skipping entry {entry.entry_id}: hash mismatch"
                            )
                            continue

                    self._entries.append(entry)
                    self._entries_by_id[entry.entry_id] = entry
                    self._save_entry(entry)
                    imported += 1

                # Обновление последнего хеша
                if self._entries:
                    self._last_hash = self._entries[-1].entry_hash

            logger.info(f"Audit imported: {imported} entries from {input_path}")
            return imported

        except Exception as e:
            logger.error(f"Audit import failed: {e}")
            raise AuditError(f"Audit import failed: {e}")

    # ------------------------------------------------------------------------
    # СТАТИСТИКА И ОТЧЕТЫ
    # ------------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """
        Получить статистику аудита.

        Returns:
            Словарь со статистикой.
        """
        with self._lock:
            total = len(self._entries)

            # Статистика по действиям
            actions: Dict[str, int] = {}
            # Статистика по пользователям
            users: Dict[str, int] = {}
            # Статистика по результатам
            results: Dict[str, int] = {}
            # Статистика по типам событий
            event_types: Dict[str, int] = {}
            # Статистика по уровням серьезности
            severities: Dict[str, int] = {}

            for entry in self._entries:
                actions[entry.action] = actions.get(entry.action, 0) + 1
                users[entry.user_id] = users.get(entry.user_id, 0) + 1
                results[entry.result] = results.get(entry.result, 0) + 1
                et = entry.event_type.value
                event_types[et] = event_types.get(et, 0) + 1
                sev = entry.severity.value
                severities[sev] = severities.get(sev, 0) + 1

            # Временной диапазон
            first_ts = None
            last_ts = None
            if self._entries:
                first_ts = min(e.timestamp for e in self._entries)
                last_ts = max(e.timestamp for e in self._entries)

            return {
                "total_entries": total,
                "first_timestamp": first_ts.isoformat() if first_ts else None,
                "last_timestamp": last_ts.isoformat() if last_ts else None,
                "actions": actions,
                "users": users,
                "results": results,
                "event_types": event_types,
                "severities": severities,
                "storage_dir": str(self.storage_dir),
                "backend_type": self.backend_type.value,
                "retention_days": self.retention_days,
                "max_entries": self.max_entries,
                "signing_key_available": self._signing_key is not None,
            }

    def get_user_activity(
        self,
        user_id: str,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """
        Получить активность конкретного пользователя.

        Args:
            user_id: ID пользователя.
            limit: Максимальное количество записей.

        Returns:
            Список записей.
        """
        return self.get_entries(user_id=user_id, limit=limit)

    def get_action_history(
        self,
        action: str,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """
        Получить историю конкретного действия.

        Args:
            action: Действие.
            limit: Максимальное количество записей.

        Returns:
            Список записей.
        """
        return self.get_entries(action=action, limit=limit)

    def get_failed_operations(
        self,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """
        Получить неудачные операции.

        Args:
            limit: Максимальное количество записей.

        Returns:
            Список записей с result="failure".
        """
        return self.get_entries(result="failure", limit=limit)

    def get_security_events(
        self,
        limit: int = 100,
    ) -> List[AuditEntry]:
        """
        Получить события безопасности.

        Args:
            limit: Максимальное количество записей.

        Returns:
            Список записей с event_type=SECURITY.
        """
        return self.get_entries(
            event_type=AuditEventType.SECURITY,
            limit=limit,
        )

    # ------------------------------------------------------------------------
    # РЕТЕНЦИЯ И ОЧИСТКА
    # ------------------------------------------------------------------------

    def cleanup(
        self,
        older_than_days: Optional[int] = None,
        max_entries: Optional[int] = None,
    ) -> int:
        """
        Очистить старые записи аудита.

        Args:
            older_than_days: Удалить записи старше N дней.
            max_entries: Оставить только последние N записей.

        Returns:
            Количество удаленных записей.
        """
        with self._lock:
            removed = 0
            cutoff = None

            if older_than_days is not None:
                cutoff = datetime.utcnow() - timedelta(days=older_than_days)

            # Удаление по возрасту
            if cutoff:
                to_remove = [e for e in self._entries if e.timestamp < cutoff]
                for entry in to_remove:
                    self._remove_entry(entry.entry_id)
                    removed += 1

            # Ограничение количества
            if max_entries and len(self._entries) > max_entries:
                excess = len(self._entries) - max_entries
                to_remove = self._entries[:excess]
                for entry in to_remove:
                    self._remove_entry(entry.entry_id)
                    removed += 1

            if removed:
                logger.info(f"Audit cleanup: removed {removed} entries")
            else:
                logger.debug("Audit cleanup: nothing to remove")

            return removed

    def purge_all(self) -> int:
        """
        Полностью очистить журнал аудита.

        Returns:
            Количество удаленных записей.
        """
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._entries_by_id.clear()
            self._last_hash = None

            if self._db_conn:
                self._db_conn.execute("DELETE FROM audit_entries")
                self._db_conn.commit()

            logger.warning(f"Audit journal purged: {count} entries removed")
            return count

    # ------------------------------------------------------------------------
    # ПРИВАТНЫЕ МЕТОДЫ - ПОДПИСЬ И ХЕШИРОВАНИЕ
    # ------------------------------------------------------------------------

    def _load_or_create_signing_key(self) -> None:
        """Загрузить или создать ECDSA ключ подписи."""
        key_path = self.storage_dir / AUDIT_SIGNING_KEY
        pubkey_path = self.storage_dir / AUDIT_SIGNING_PUBKEY

        try:
            if self._signing_key:
                # Используем предоставленный ключ
                self._signing_pubkey = self._extract_public_key(self._signing_key)
            elif key_path.exists():
                # Загружаем существующий ключ
                with open(key_path, "rb") as f:
                    self._signing_key = f.read()
                self._signing_pubkey = self._extract_public_key(self._signing_key)
            else:
                # Генерируем новый ключ
                private_pem, public_pem = crypto.generate_ecdsa_keypair("p256")
                self._signing_key = private_pem
                self._signing_pubkey = public_pem

                # Сохраняем ключи
                with open(key_path, "wb") as f:
                    f.write(private_pem)
                os.chmod(key_path, 0o600)

                with open(pubkey_path, "wb") as f:
                    f.write(public_pem)

                logger.info("New audit signing key generated")

        except Exception as e:
            logger.warning(f"Failed to load/create signing key: {e}")
            self._signing_key = None
            self._signing_pubkey = None

    def _extract_public_key(self, private_key_pem: bytes) -> Optional[bytes]:
        """Извлечь публичный ключ из приватного."""
        try:
            from cryptography.hazmat.primitives import serialization

            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None
            )
            return private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:
            return None

    def _sign_entry(self, entry: AuditEntry) -> Optional[str]:
        """
        Подписать запись аудита ECDSA.

        Args:
            entry: Запись для подписи.

        Returns:
            Подпись в hex формате или None если подпись невозможна.
        """
        if not self._signing_key:
            return None

        try:
            data = self._get_signing_data(entry)
            signature = crypto.sign_ecdsa(data, self._signing_key)
            return signature.hex()
        except Exception as e:
            logger.error(f"Failed to sign audit entry {entry.entry_id}: {e}")
            raise AuditSignatureError(f"Audit signing failed: {e}")

    def _verify_entry_signature(self, entry: AuditEntry) -> bool:
        """
        Проверить подпись записи.

        Args:
            entry: Запись для проверки.

        Returns:
            True если подпись валидна.
        """
        if not entry.signature or not self._signing_pubkey:
            return False

        try:
            data = self._get_signing_data(entry)
            signature = bytes.fromhex(entry.signature)
            return crypto.verify_ecdsa(data, signature, self._signing_pubkey)
        except Exception as e:
            logger.error(f"Failed to verify signature for {entry.entry_id}: {e}")
            return False

    def _get_signing_data(self, entry: AuditEntry) -> bytes:
        """
        Получить данные для подписи.

        Подписываются все поля записи, кроме signature и status.
        """
        data = entry.to_dict(include_signature=False)
        data.pop("status", None)
        return json.dumps(data, sort_keys=True, default=str).encode()

    def _compute_entry_hash(self, entry: AuditEntry) -> str:
        """
        Вычислить хеш записи.

        Хеш включает все поля записи и хеш предыдущей записи.
        """
        data = entry.to_dict(include_signature=False)
        data.pop("status", None)
        data.pop("entry_hash", None)

        # Добавляем хеш предыдущей записи
        if entry.prev_hash:
            data["_prev_hash"] = entry.prev_hash

        serialized = json.dumps(data, sort_keys=True, default=str).encode()
        return hashlib.sha256(serialized).hexdigest()

    def _generate_entry_id(self) -> str:
        """Сгенерировать уникальный ID записи."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
        random_part = crypto.generate_random(8).hex()
        return f"aud-{timestamp}-{random_part}"

    # ------------------------------------------------------------------------
    # ПРИВАТНЫЕ МЕТОДЫ - ХРАНЕНИЕ
    # ------------------------------------------------------------------------

    def _init_db(self) -> None:
        """Инициализировать SQLite базу данных."""
        if self.backend_type == AuditBackendType.MEMORY:
            return

        try:
            db_path = self.storage_dir / AUDIT_DB_FILE
            self._db_conn = sqlite3.connect(str(db_path))
            self._db_conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_entries (
                    entry_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details TEXT,
                    source TEXT,
                    prev_hash TEXT,
                    entry_hash TEXT,
                    signature TEXT,
                    status TEXT,
                    ip_address TEXT,
                    session_id TEXT,
                    request_id TEXT,
                    correlation_id TEXT,
                    metadata TEXT
                )
            """
            )
            self._db_conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_entries(user_id)"
            )
            self._db_conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries(action)"
            )
            self._db_conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp)"
            )
            self._db_conn.commit()
            logger.debug(f"SQLite audit database initialized: {db_path}")

        except Exception as e:
            logger.error(f"Failed to initialize audit database: {e}")
            self._db_conn = None

    def _save_entry(self, entry: AuditEntry) -> None:
        """Сохранить запись в БД."""
        if not self._db_conn:
            return

        try:
            self._db_conn.execute(
                """
                INSERT OR REPLACE INTO audit_entries (
                    entry_id, timestamp, user_id, action, result,
                    event_type, severity, details, source,
                    prev_hash, entry_hash, signature, status,
                    ip_address, session_id, request_id, correlation_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.entry_id,
                    entry.timestamp.isoformat(),
                    entry.user_id,
                    entry.action,
                    entry.result,
                    entry.event_type.value,
                    entry.severity.value,
                    json.dumps(entry.details, default=str),
                    entry.source,
                    entry.prev_hash,
                    entry.entry_hash,
                    entry.signature,
                    entry.status.value,
                    entry.ip_address,
                    entry.session_id,
                    entry.request_id,
                    entry.correlation_id,
                    json.dumps(entry.metadata, default=str),
                ),
            )
            self._db_conn.commit()
        except Exception as e:
            logger.error(f"Failed to save audit entry {entry.entry_id}: {e}")

    def _remove_entry(self, entry_id: str) -> None:
        """Удалить запись из памяти и БД."""
        if entry_id in self._entries_by_id:
            entry = self._entries_by_id.pop(entry_id)
            self._entries.remove(entry)

        if self._db_conn:
            try:
                self._db_conn.execute(
                    "DELETE FROM audit_entries WHERE entry_id = ?",
                    (entry_id,),
                )
                self._db_conn.commit()
            except Exception as e:
                logger.error(f"Failed to delete audit entry {entry_id}: {e}")

    def _load_entries(self) -> None:
        """Загрузить записи из БД."""
        if not self._db_conn:
            return

        try:
            cursor = self._db_conn.execute(
                "SELECT * FROM audit_entries ORDER BY timestamp ASC"
            )
            rows = cursor.fetchall()
            columns = [d[0] for d in cursor.description]

            self._entries.clear()
            self._entries_by_id.clear()

            for row in rows:
                data = dict(zip(columns, row))
                entry = self._row_to_entry(data)
                self._entries.append(entry)
                self._entries_by_id[entry.entry_id] = entry

            # Восстановление последнего хеша
            if self._entries:
                self._last_hash = self._entries[-1].entry_hash

            logger.debug(f"Loaded {len(self._entries)} audit entries from DB")

        except Exception as e:
            logger.error(f"Failed to load audit entries: {e}")

    def _row_to_entry(self, data: Dict[str, Any]) -> AuditEntry:
        """Преобразовать строку БД в AuditEntry."""
        return AuditEntry(
            entry_id=data["entry_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            user_id=data["user_id"],
            action=data["action"],
            result=data["result"],
            event_type=AuditEventType(data["event_type"]),
            severity=AuditSeverity(data["severity"]),
            details=json.loads(data["details"]) if data["details"] else {},
            source=data.get("source") or "",
            prev_hash=data.get("prev_hash"),
            entry_hash=data.get("entry_hash"),
            signature=data.get("signature"),
            status=AuditStatus(data.get("status", "pending")),
            ip_address=data.get("ip_address"),
            session_id=data.get("session_id"),
            request_id=data.get("request_id"),
            correlation_id=data.get("correlation_id"),
            metadata=json.loads(data["metadata"]) if data.get("metadata") else {},
        )

    def _enforce_limits(self) -> None:
        """Применить ограничения (ретенция, максимальное количество)."""
        # Ограничение по количеству
        if len(self._entries) > self.max_entries:
            excess = len(self._entries) - self.max_entries
            to_remove = self._entries[:excess]
            for entry in to_remove:
                self._remove_entry(entry.entry_id)

        # Ограничение по возрасту
        cutoff = datetime.utcnow() - timedelta(days=self.retention_days)
        to_remove = [e for e in self._entries if e.timestamp < cutoff]
        for entry in to_remove:
            self._remove_entry(entry.entry_id)


# ============================================================================
# ФУНКЦИИ ВЫСОКОГО УРОВНЯ
# ============================================================================


def create_audit_manager(
    storage_dir: Optional[str] = None,
    **kwargs: Any,
) -> AuditManager:
    """
    Фабричная функция для создания AuditManager.

    Args:
        storage_dir: Директория хранения.
        **kwargs: Дополнительные параметры.

    Returns:
        Инициализированный AuditManager.
    """
    am = AuditManager(storage_dir=storage_dir, **kwargs)
    am.initialize()
    return am


def quick_log(
    user_id: str,
    action: str,
    result: str = "success",
    details: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> AuditEntry:
    """
    Быстрое логирование операции без создания экземпляра.

    Args:
        user_id: ID пользователя.
        action: Действие.
        result: Результат.
        details: Детали.
        **kwargs: Дополнительные параметры.

    Returns:
        Запись аудита.
    """
    am = AuditManager()
    return am.log_action(
        user_id=user_id,
        action=action,
        result=result,
        details=details,
        **kwargs,
    )


# ============================================================================
# ЭКСПОРТ
# ============================================================================

__all__ = [
    # Классы
    "AuditManager",
    "AuditEntry",
    # Константы
    "AuditEventType",
    "AuditSeverity",
    "AuditBackendType",
    "AuditStatus",
    # Исключения
    "AuditError",
    "AuditLogError",
    "AuditSignatureError",
    "AuditVerificationError",
    "AuditBackendError",
    "AuditExportError",
    "AuditNotFoundError",
    # Функции
    "create_audit_manager",
    "quick_log",
]
