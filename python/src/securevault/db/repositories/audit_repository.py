"""SecureVault - Репозиторий аудит-записей.

Предоставляет слой доступа к данным аудита через сессию БД.
"""

import logging
from typing import List, Optional

from securevault.db.models import AuditRecord
from securevault.db.session import DatabaseSession, get_session

logger = logging.getLogger(__name__)


class AuditRepositoryError(Exception):
    """Ошибка репозитория аудита."""


class AuditRepository:
    """Репозиторий для работы с аудит-записями."""

    def __init__(self, session: Optional[DatabaseSession] = None):
        self.session = session or get_session()

    def create_table(self) -> None:
        """Создать таблицу."""
        self.session.execute(
            "CREATE TABLE IF NOT EXISTS audit_entries ("
            "entry_id TEXT PRIMARY KEY,"
            "timestamp TEXT NOT NULL,"
            "user_id TEXT NOT NULL,"
            "action TEXT NOT NULL,"
            "result TEXT NOT NULL,"
            "event_type TEXT NOT NULL,"
            "severity TEXT NOT NULL,"
            "details TEXT,"
            "source TEXT,"
            "prev_hash TEXT,"
            "entry_hash TEXT,"
            "signature TEXT,"
            "status TEXT,"
            "ip_address TEXT,"
            "session_id TEXT,"
            "request_id TEXT,"
            "correlation_id TEXT,"
            "metadata TEXT"
            ")"
        )
        self.session.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_action " "ON audit_entries(action)"
        )
        self.session.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_user " "ON audit_entries(user_id)"
        )
        self.session.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_ts " "ON audit_entries(timestamp)"
        )

    def save_record(self, record: AuditRecord) -> None:
        """Сохранить запись аудита."""
        data = record.to_db_dict()
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        self.session.execute(
            f"INSERT OR REPLACE INTO audit_entries ({columns}) "
            f"VALUES ({placeholders})",
            tuple(data.values()),
        )

    def get_entries(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[AuditRecord]:
        """Получить записи аудита."""
        query = "SELECT * FROM audit_entries"
        conditions = []
        params = []

        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)
        if action:
            conditions.append("action = ?")
            params.append(action)
        if result:
            conditions.append("result = ?")
            params.append(result)
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor = self.session.execute(query, tuple(params))
        rows = cursor.fetchall()

        result = []
        for row in rows:
            row_dict = (
                dict(row)
                if hasattr(row, "keys")
                else {col: row[i] for i, col in enumerate(cursor.description)}
            )
            result.append(AuditRecord.from_db_row(row_dict))
        return result

    def get_by_id(self, entry_id: str) -> Optional[AuditRecord]:
        """Получить запись по ID."""
        cursor = self.session.execute(
            "SELECT * FROM audit_entries WHERE entry_id = ?", (entry_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        row_dict = (
            dict(row)
            if hasattr(row, "keys")
            else {col: row[i] for i, col in enumerate(cursor.description)}
        )
        return AuditRecord.from_db_row(row_dict)

    def count(self) -> int:
        """Количество записей."""
        cursor = self.session.execute("SELECT COUNT(*) FROM audit_entries")
        return cursor.fetchone()[0]

    def delete(self, entry_id: str) -> bool:
        """Удалить запись."""
        cursor = self.session.execute(
            "DELETE FROM audit_entries WHERE entry_id = ?", (entry_id,)
        )
        return cursor.rowcount > 0

    def clear(self) -> int:
        """Очистить все записи."""
        cursor = self.session.execute("DELETE FROM audit_entries")
        return cursor.rowcount


__all__ = ["AuditRepository", "AuditRepositoryError"]
