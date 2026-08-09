"""SecureVault - Модели базы данных.

Определяет структуру таблиц для SQLite/PostgreSQL.
"""

import json
from datetime import datetime
from typing import Any, Dict, Optional


class AuditRecord:
    """Модель записи аудита."""

    TABLE = "audit_entries"

    def __init__(
        self,
        entry_id: str,
        timestamp: str,
        user_id: str,
        action: str,
        result: str,
        event_type: str = "operation",
        severity: str = "info",
        details: Optional[Dict[str, Any]] = None,
        source: str = "",
        prev_hash: Optional[str] = None,
        entry_hash: Optional[str] = None,
        signature: Optional[str] = None,
        status: str = "pending",
        ip_address: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.entry_id = entry_id
        self.timestamp = timestamp
        self.user_id = user_id
        self.action = action
        self.result = result
        self.event_type = event_type
        self.severity = severity
        self.details = details or {}
        self.source = source
        self.prev_hash = prev_hash
        self.entry_hash = entry_hash
        self.signature = signature
        self.status = status
        self.ip_address = ip_address
        self.session_id = session_id
        self.request_id = request_id
        self.correlation_id = correlation_id
        self.metadata = metadata or {}

    @classmethod
    def columns(cls) -> str:
        """SQL определения колонок."""
        return """
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
        """

    @classmethod
    def create_table_sql(cls) -> str:
        """SQL для создания таблицы."""
        return f"""
            CREATE TABLE IF NOT EXISTS {cls.TABLE} (
                {cls.columns()}
            )
        """

    def to_db_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь для БД."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "action": self.action,
            "result": self.result,
            "event_type": self.event_type,
            "severity": self.severity,
            "details": json.dumps(self.details, default=str),
            "source": self.source,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
            "status": self.status,
            "ip_address": self.ip_address,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "metadata": json.dumps(self.metadata, default=str),
        }

    @classmethod
    def from_db_row(cls, row: Dict[str, Any]) -> "AuditRecord":
        """Создать из строки БД."""
        return cls(
            entry_id=row["entry_id"],
            timestamp=row["timestamp"],
            user_id=row["user_id"],
            action=row["action"],
            result=row["result"],
            event_type=row.get("event_type", "operation"),
            severity=row.get("severity", "info"),
            details=json.loads(row["details"]) if row.get("details") else {},
            source=row.get("source", ""),
            prev_hash=row.get("prev_hash"),
            entry_hash=row.get("entry_hash"),
            signature=row.get("signature"),
            status=row.get("status", "pending"),
            ip_address=row.get("ip_address"),
            session_id=row.get("session_id"),
            request_id=row.get("request_id"),
            correlation_id=row.get("correlation_id"),
            metadata=json.loads(row["metadata"]) if row.get("metadata") else {},
        )

    def to_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь."""
        return {
            "entry_id": self.entry_id,
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "action": self.action,
            "result": self.result,
            "event_type": self.event_type,
            "severity": self.severity,
            "details": self.details,
            "source": self.source,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
            "status": self.status,
            "ip_address": self.ip_address,
            "session_id": self.session_id,
            "request_id": self.request_id,
            "correlation_id": self.correlation_id,
            "metadata": self.metadata,
        }


class UserRecord:
    """Модель пользователя."""

    TABLE = "users"

    def __init__(
        self,
        user_id: str,
        username: str,
        roles: Optional[list] = None,
        email: Optional[str] = None,
        created_at: Optional[str] = None,
        last_login: Optional[str] = None,
        mfa_enabled: bool = False,
        status: str = "active",
    ):
        self.user_id = user_id
        self.username = username
        self.roles = roles or []
        self.email = email
        self.created_at = created_at or datetime.utcnow().isoformat()
        self.last_login = last_login
        self.mfa_enabled = mfa_enabled
        self.status = status

    @classmethod
    def create_table_sql(cls) -> str:
        """SQL для создания таблицы."""
        return f"""
            CREATE TABLE IF NOT EXISTS {cls.TABLE} (
                user_id TEXT PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                roles TEXT,
                email TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT,
                mfa_enabled INTEGER DEFAULT 0,
                status TEXT DEFAULT 'active'
            )
        """

    def to_db_dict(self) -> Dict[str, Any]:
        """Преобразовать в словарь для БД."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "roles": json.dumps(self.roles),
            "email": self.email,
            "created_at": self.created_at,
            "last_login": self.last_login,
            "mfa_enabled": int(self.mfa_enabled),
            "status": self.status,
        }

    @classmethod
    def from_db_row(cls, row: Dict[str, Any]) -> "UserRecord":
        """Создать из строки БД."""
        return cls(
            user_id=row["user_id"],
            username=row["username"],
            roles=json.loads(row["roles"]) if row.get("roles") else [],
            email=row.get("email"),
            created_at=row.get("created_at"),
            last_login=row.get("last_login"),
            mfa_enabled=bool(row.get("mfa_enabled", 0)),
            status=row.get("status", "active"),
        )


__all__ = ["AuditRecord", "UserRecord"]
