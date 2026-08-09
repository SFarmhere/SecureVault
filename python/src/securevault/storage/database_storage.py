"""SecureVault - Хранение метаданных в базе данных (SQLite/PostgreSQL).

Предоставляет слой хранения метаданных контейнеров, файлов, ключей
и пользователей через сессию БД (db.session.DatabaseSession).
"""

import json
import logging
from typing import Any, Dict, List, Optional

from securevault.db.session import DatabaseSession, get_session

logger = logging.getLogger(__name__)


class DatabaseStorageError(Exception):
    """Ошибка хранилища метаданных в БД."""
    pass


class DatabaseStorage:
    """Хранилище метаданных в базе данных."""

    def __init__(self, session: Optional[DatabaseSession] = None):
        self._session = session or get_session()

    @property
    def session(self) -> DatabaseSession:
        """Сессия БД."""
        return self._session

    # =========================================================================
    # ПОЛЬЗОВАТЕЛИ
    # =========================================================================

    def upsert_user(self, user: Dict[str, Any]) -> None:
        """Создать или обновить пользователя."""
        sql = """
            INSERT INTO users (
                user_id, username, roles, email, created_at, last_login,
                mfa_enabled, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                username = excluded.username,
                roles = excluded.roles,
                email = excluded.email,
                last_login = excluded.last_login,
                mfa_enabled = excluded.mfa_enabled,
                status = excluded.status
        """
        self._session.execute(sql, (
            user["user_id"],
            user.get("username", ""),
            json.dumps(user.get("roles", [])),
            user.get("email"),
            user.get("created_at", ""),
            user.get("last_login"),
            int(user.get("mfa_enabled", False)),
            user.get("status", "active"),
        ))

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Получить пользователя по ID."""
        cursor = self._session.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    def list_users(self) -> List[Dict[str, Any]]:
        """Список пользователей."""
        cursor = self._session.execute("SELECT * FROM users")
        return [dict(row) for row in cursor.fetchall()]

    # =========================================================================
    # КЛЮЧИ
    # =========================================================================

    def create_key(self, key: Dict[str, Any]) -> None:
        """Создать запись о ключе."""
        sql = """
            INSERT INTO keys (
                key_id, user_id, key_type, key_alias, key_status,
                key_handle, wrapped_key, security_level, created_at,
                rotated_at, expires_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self._session.execute(sql, (
            key["key_id"],
            key.get("user_id", ""),
            key.get("key_type", "aes-256"),
            key.get("key_alias"),
            key.get("key_status", "active"),
            key.get("key_handle"),
            key.get("wrapped_key"),
            key.get("security_level", "CONTAINER"),
            key.get("created_at", ""),
            key.get("rotated_at"),
            key.get("expires_at"),
            json.dumps(key.get("metadata", {})),
        ))

    def update_key_status(self, key_id: str, status: str) -> None:
        """Обновить статус ключа."""
        self._session.execute(
            "UPDATE keys SET key_status = ? WHERE key_id = ?", (status, key_id)
        )

    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Получить ключ по ID."""
        cursor = self._session.execute(
            "SELECT * FROM keys WHERE key_id = ?", (key_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def list_keys(self, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Список ключей пользователя."""
        if user_id:
            cursor = self._session.execute(
                "SELECT * FROM keys WHERE user_id = ?", (user_id,)
            )
        else:
            cursor = self._session.execute("SELECT * FROM keys")
        return [dict(row) for row in cursor.fetchall()]

    # =========================================================================
    # КОНТЕЙНЕРЫ
    # =========================================================================

    def create_container(self, container: Dict[str, Any]) -> None:
        """Создать запись о контейнере."""
        sql = """
            INSERT INTO containers (
                container_id, owner_id, name, format, security_level,
                path, total_size, used_size, file_count, dedup_enabled,
                chunk_size, compression, is_hidden, is_mounted,
                created_at, modified_at, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self._session.execute(sql, (
            container["container_id"],
            container.get("owner_id", ""),
            container.get("name", ""),
            container.get("format", "V1"),
            container.get("security_level", "CONTAINER"),
            container.get("path"),
            container.get("total_size", 0),
            container.get("used_size", 0),
            container.get("file_count", 0),
            int(container.get("dedup_enabled", True)),
            container.get("chunk_size", 65536),
            container.get("compression", "ZSTD"),
            int(container.get("is_hidden", False)),
            int(container.get("is_mounted", False)),
            container.get("created_at", ""),
            container.get("modified_at"),
            json.dumps(container.get("metadata", {})),
        ))

    def get_container(self, container_id: str) -> Optional[Dict[str, Any]]:
        """Получить контейнер по ID."""
        cursor = self._session.execute(
            "SELECT * FROM containers WHERE container_id = ?", (container_id,)
        )
        row = cursor.fetchone()
        return dict(row) if row else None

    def update_container_size(self, container_id: str, used_size: int,
                              file_count: int) -> None:
        """Обновить размер и число файлов контейнера."""
        self._session.execute(
            "UPDATE containers SET used_size = ?, file_count = ? "
            "WHERE container_id = ?",
            (used_size, file_count, container_id),
        )

    def list_containers(self, owner_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Список контейнеров."""
        if owner_id:
            cursor = self._session.execute(
                "SELECT * FROM containers WHERE owner_id = ?", (owner_id,)
            )
        else:
            cursor = self._session.execute("SELECT * FROM containers")
        return [dict(row) for row in cursor.fetchall()]

    def delete_container(self, container_id: str) -> None:
        """Удалить запись о контейнере."""
        self._session.execute(
            "DELETE FROM containers WHERE container_id = ?", (container_id,)
        )

    # =========================================================================
    # АУДИТ (цепочка целостности)
    # =========================================================================

    def append_audit_entry(self, entry: Dict[str, Any]) -> None:
        """Добавить запись аудита с hash-chain."""
        prev_hash = None
        cursor = self._session.execute(
            "SELECT entry_hash FROM audit_entries "
            "ORDER BY timestamp DESC LIMIT 1"
        )
        row = cursor.fetchone()
        if row:
            prev_hash = row["entry_hash"]
        entry["prev_hash"] = prev_hash
        entry["entry_hash"] = self._compute_entry_hash(entry, prev_hash)

        sql = """
            INSERT INTO audit_entries (
                entry_id, timestamp, user_id, action, result, event_type,
                severity, details, source, prev_hash, entry_hash, signature,
                status, ip_address, session_id, request_id, correlation_id,
                metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        self._session.execute(sql, (
            entry["entry_id"],
            entry.get("timestamp", ""),
            entry.get("user_id", ""),
            entry.get("action", ""),
            entry.get("result", "success"),
            entry.get("event_type", "operation"),
            entry.get("severity", "info"),
            json.dumps(entry.get("details", {})),
            entry.get("source", ""),
            entry.get("prev_hash"),
            entry.get("entry_hash"),
            entry.get("signature"),
            entry.get("status", "pending"),
            entry.get("ip_address"),
            entry.get("session_id"),
            entry.get("request_id"),
            entry.get("correlation_id"),
            json.dumps(entry.get("metadata", {})),
        ))

    def query_audit(self, filters: Optional[Dict[str, Any]] = None,
                    limit: int = 100) -> List[Dict[str, Any]]:
        """Запросить записи аудита."""
        sql = "SELECT * FROM audit_entries"
        params: list = []
        conditions = []
        filters = filters or {}

        if filters.get("user_id"):
            conditions.append("user_id = ?")
            params.append(filters["user_id"])
        if filters.get("action"):
            conditions.append("action = ?")
            params.append(filters["action"])
        if filters.get("result"):
            conditions.append("result = ?")
            params.append(filters["result"])
        if filters.get("event_type"):
            conditions.append("event_type = ?")
            params.append(filters["event_type"])

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor = self._session.execute(sql, tuple(params))
        return [dict(row) for row in cursor.fetchall()]

    def verify_audit_chain(self) -> bool:
        """Проверить целостность hash-chain аудита."""
        cursor = self._session.execute(
            "SELECT * FROM audit_entries ORDER BY timestamp ASC"
        )
        rows = cursor.fetchall()
        prev_hash = None
        for row in rows:
            computed = self._compute_entry_hash(dict(row), prev_hash)
            if computed != row["entry_hash"]:
                logger.error("Audit chain broken at entry %s", row["entry_id"])
                return False
            prev_hash = row["entry_hash"]
        return True

    # =========================================================================
    # ВСПОМОГАТЕЛЬНЫЕ
    # =========================================================================

    @staticmethod
    def _compute_entry_hash(entry: Dict[str, Any], prev_hash: Optional[str]) -> str:
        """Вычислить SHA-256 хеш записи аудита (включая prev_hash)."""
        import hashlib
        payload = {
            "entry_id": entry.get("entry_id", ""),
            "timestamp": entry.get("timestamp", ""),
            "user_id": entry.get("user_id", ""),
            "action": entry.get("action", ""),
            "result": entry.get("result", ""),
            "prev_hash": prev_hash,
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ).hexdigest()


__all__ = ["DatabaseStorage", "DatabaseStorageError"]