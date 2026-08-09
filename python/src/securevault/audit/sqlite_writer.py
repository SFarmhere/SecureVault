"""
SecureVault - SQLite Writer для аудит-записей

Обеспечивает низкоуровневую запись аудит-записей в SQLite.

Использование:
    from securevault.audit.sqlite_writer import SQLiteWriter

    writer = SQLiteWriter("audit.db")
    writer.write(entry_data)
    entries = writer.read(limit=100)
    writer.close()
"""

import json
import logging
import sqlite3
import threading
from typing import Optional, List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class SQLiteWriterError(Exception):
    """Ошибка SQLite writer."""


class SQLiteWriter:
    """Низкоуровневый писатель аудит-записей в SQLite."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._lock = threading.RLock()
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
            "CREATE INDEX IF NOT EXISTS idx_user ON audit_entries(user_id)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_action ON audit_entries(action)"
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ts ON audit_entries(timestamp)"
        )
        self._conn.commit()

    def write(self, entry: Dict[str, Any]) -> None:
        """Записать запись."""
        with self._lock:
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
                raise SQLiteWriterError(f"Write failed: {e}")

    def write_batch(self, entries: List[Dict[str, Any]]) -> int:
        """Записать пачку записей."""
        with self._lock:
            for entry in entries:
                self.write(entry)
            return len(entries)

    def read(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Прочитать записи."""
        with self._lock:
            query = "SELECT * FROM audit_entries"
            params = []

            if filters:
                conds = []
                for key, value in filters.items():
                    if key in ("user_id", "action", "result"):
                        conds.append(f"{key} = ?")
                        params.append(value)
                if conds:
                    query += " WHERE " + " AND ".join(conds)

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

    def delete(self, entry_id: str) -> bool:
        """Удалить запись."""
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM audit_entries WHERE entry_id = ?",
                (entry_id,),
            )
            self._conn.commit()
            return cursor.rowcount > 0

    def count(self) -> int:
        """Количество записей."""
        with self._lock:
            cursor = self._conn.execute("SELECT COUNT(*) FROM audit_entries")
            return cursor.fetchone()[0]

    def clear(self) -> int:
        """Очистить все записи."""
        with self._lock:
            cursor = self._conn.execute("DELETE FROM audit_entries")
            self._conn.commit()
            return cursor.rowcount

    def close(self) -> None:
        """Закрыть соединение."""
        self._conn.close()


__all__ = ["SQLiteWriter", "SQLiteWriterError"]
