"""
SecureVault - Абстракция бэкендов хранения аудита

Предоставляет единый интерфейс для различных бэкендов хранения
аудит-записей:
- SQLite (локальное хранение)
- PostgreSQL (репликация)
- Файловое хранение (JSON Lines)
- Память (для тестов)

Использование:
    from securevault.audit.audit_backend import AuditBackend, create_backend

    backend = create_backend("sqlite", path="/secure/vault/audit/audit.db")
    backend.write(entry_dict)
    entries = backend.read(limit=100)
"""

import json
import logging
import sqlite3
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)


class AuditBackendError(Exception):
    """Ошибка бэкенда хранения аудита."""
    pass


class AuditBackend(ABC):
    """
    Абстрактный базовый класс для бэкендов хранения аудита.

    Все бэкенды должны реализовать:
    - write: Запись записи
    - read: Чтение записей
    - delete: Удаление записей
    - count: Количество записей
    - close: Закрытие бэкенда
    """

    @abstractmethod
    def write(self, entry: Dict[str, Any]) -> None:
        """Записать запись аудита."""
        pass

    @abstractmethod
    def read(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Прочитать записи аудита."""
        pass

    @abstractmethod
    def delete(self, entry_id: str) -> bool:
        """Удалить запись по ID."""
        pass

    @abstractmethod
    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Получить количество записей."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Закрыть бэкенд."""
        pass


class MemoryBackend(AuditBackend):
    """Бэкенд хранения в памяти (для тестов)."""

    def __init__(self):
        self._entries: List[Dict[str, Any]] = []

    def write(self, entry: Dict[str, Any]) -> None:
        self._entries.append(entry)

    def read(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        result = list(self._entries)
        if filters:
            for key, value in filters.items():
                result = [e for e in result if e.get(key) == value]
        result.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return result[offset:offset + limit]

    def delete(self, entry_id: str) -> bool:
        before = len(self._entries)
        self._entries = [e for e in self._entries if e.get("entry_id") != entry_id]
        return len(self._entries) < before

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        return len(self.read(limit=1000000, filters=filters))

    def close(self) -> None:
        self._entries.clear()


class SQLiteBackend(AuditBackend):
    """Бэкенд хранения в SQLite."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute("""
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
        """)
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_entries(user_id)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_entries(action)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_entries(timestamp)"
        )
        self._conn.commit()

    def write(self, entry: Dict[str, Any]) -> None:
        try:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO audit_entries (
                    entry_id, timestamp, user_id, action, result,
                    event_type, severity, details, source,
                    prev_hash, entry_hash, signature, status,
                    ip_address, session_id, request_id, correlation_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.get("entry_id"),
                    entry.get("timestamp"),
                    entry.get("user_id"),
                    entry.get("action"),
                    entry.get("result"),
                    entry.get("event_type"),
                    entry.get("severity"),
                    json.dumps(entry.get("details", {}), default=str),
                    entry.get("source"),
                    entry.get("prev_hash"),
                    entry.get("entry_hash"),
                    entry.get("signature"),
                    entry.get("status"),
                    entry.get("ip_address"),
                    entry.get("session_id"),
                    entry.get("request_id"),
                    entry.get("correlation_id"),
                    json.dumps(entry.get("metadata", {}), default=str),
                ),
            )
            self._conn.commit()
        except Exception as e:
            raise AuditBackendError(f"SQLite write failed: {e}")

    def read(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        try:
            query = "SELECT * FROM audit_entries"
            params = []

            if filters:
                conditions = []
                for key, value in filters.items():
                    if key in ("user_id", "action", "result", "event_type", "severity"):
                        conditions.append(f"{key} = ?")
                        params.append(value)
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = self._conn.execute(query, params)
            rows = cursor.fetchall()
            columns = [d[0] for d in cursor.description]

            result = []
            for row in rows:
                data = dict(zip(columns, row))
                if data.get("details"):
                    data["details"] = json.loads(data["details"])
                if data.get("metadata"):
                    data["metadata"] = json.loads(data["metadata"])
                result.append(data)

            return result

        except Exception as e:
            raise AuditBackendError(f"SQLite read failed: {e}")

    def delete(self, entry_id: str) -> bool:
        try:
            cursor = self._conn.execute(
                "DELETE FROM audit_entries WHERE entry_id = ?",
                (entry_id,),
            )
            self._conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            raise AuditBackendError(f"SQLite delete failed: {e}")

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        try:
            query = "SELECT COUNT(*) FROM audit_entries"
            params = []

            if filters:
                conditions = []
                for key, value in filters.items():
                    if key in ("user_id", "action", "result", "event_type", "severity"):
                        conditions.append(f"{key} = ?")
                        params.append(value)
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

            cursor = self._conn.execute(query, params)
            return cursor.fetchone()[0]
        except Exception as e:
            raise AuditBackendError(f"SQLite count failed: {e}")

    def close(self) -> None:
        self._conn.close()


class FileBackend(AuditBackend):
    """Бэкенд хранения в файле (JSON Lines)."""

    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, entry: Dict[str, Any]) -> None:
        try:
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False, default=str) + "\n")
        except Exception as e:
            raise AuditBackendError(f"File write failed: {e}")

    def read(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        try:
            if not self.file_path.exists():
                return []

            entries = []
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line))

            if filters:
                for key, value in filters.items():
                    entries = [e for e in entries if e.get(key) == value]

            entries.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
            return entries[offset:offset + limit]

        except Exception as e:
            raise AuditBackendError(f"File read failed: {e}")

    def delete(self, entry_id: str) -> bool:
        try:
            if not self.file_path.exists():
                return False

            entries = []
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        entries.append(json.loads(line))

            before = len(entries)
            entries = [e for e in entries if e.get("entry_id") != entry_id]

            if len(entries) < before:
                with open(self.file_path, "w", encoding="utf-8") as f:
                    for e in entries:
                        f.write(json.dumps(e, ensure_ascii=False, default=str) + "\n")
                return True
            return False

        except Exception as e:
            raise AuditBackendError(f"File delete failed: {e}")

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        return len(self.read(limit=1000000, filters=filters))

    def close(self) -> None:
        pass


def create_backend(
    backend_type: str,
    storage_path: Optional[str] = None,
    **kwargs: Any,
) -> AuditBackend:
    """
    Фабричная функция для создания бэкенда.

    Args:
        backend_type: Тип бэкенда ("sqlite", "memory", "file", "postgresql").
        storage_path: Путь для хранения.
        **kwargs: Дополнительные параметры.

    Returns:
        Экземпляр бэкенда.

    Raises:
        AuditBackendError: Если тип бэкенда не поддерживается.
    """
    if backend_type == "sqlite":
        if not storage_path:
            raise AuditBackendError("storage_path required for sqlite backend")
        return SQLiteBackend(storage_path)
    elif backend_type == "memory":
        return MemoryBackend()
    elif backend_type == "file":
        if not storage_path:
            raise AuditBackendError("storage_path required for file backend")
        return FileBackend(storage_path)
    elif backend_type == "postgresql":
        from securevault.audit.postgres_backend import PostgresBackend
        return PostgresBackend(**kwargs)
    else:
        raise AuditBackendError(f"Unsupported backend type: {backend_type}")


__all__ = [
    "AuditBackend",
    "AuditBackendError",
    "MemoryBackend",
    "SQLiteBackend",
    "FileBackend",
    "create_backend",
]