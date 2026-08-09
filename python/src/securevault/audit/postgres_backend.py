"""
SecureVault - PostgreSQL бэкенд для аудит-записей

Обеспечивает репликацию аудит-записей в PostgreSQL.

Использование:
    from securevault.audit.postgres_backend import PostgresBackend

    backend = PostgresBackend(
        host="localhost", port=5432,
        dbname="securevault", user="postgres", password="secret"
    )
    backend.write(entry_dict)
"""

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class PostgresBackendError(Exception):
    """Ошибка PostgreSQL бэкенда."""


class PostgresBackend:
    """Бэкенд хранения аудит-записей в PostgreSQL."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        dbname: str = "securevault",
        user: str = "postgres",
        password: str = "",
        table: str = "audit_entries",
    ):
        self.host = host
        self.port = port
        self.dbname = dbname
        self.user = user
        self.password = password
        self.table = table
        self._conn = None
        self._initialized = False

    def initialize(self) -> None:
        """Инициализировать подключение к PostgreSQL."""
        try:
            import psycopg2

            self._conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                dbname=self.dbname,
                user=self.user,
                password=self.password,
            )
            self._init_schema()
            self._initialized = True
            logger.info(
                f"PostgreSQL backend initialized: {self.host}:{self.port}/{self.dbname}"
            )
        except ImportError:
            raise PostgresBackendError(
                "psycopg2 not installed. Install with: pip install psycopg2-binary"
            )
        except Exception as e:
            raise PostgresBackendError(f"PostgreSQL connection failed: {e}")

    def _init_schema(self) -> None:
        """Создать таблицу если не существует."""
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.table} (
                    entry_id TEXT PRIMARY KEY,
                    timestamp TIMESTAMPTZ NOT NULL,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    details JSONB,
                    source TEXT,
                    prev_hash TEXT,
                    entry_hash TEXT,
                    signature TEXT,
                    status TEXT,
                    ip_address TEXT,
                    session_id TEXT,
                    request_id TEXT,
                    correlation_id TEXT,
                    metadata JSONB
                )
            """
            )
            cur.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{self.table}_action "
                f"ON {self.table}(action)"
            )
            cur.execute(
                f"CREATE INDEX IF NOT EXISTS idx_{self.table}_user "
                f"ON {self.table}(user_id)"
            )
            self._conn.commit()

    def write(self, entry: Dict[str, Any]) -> None:
        """Записать запись."""
        if not self._initialized:
            self.initialize()
        with self._conn.cursor() as cur:
            cur.execute(
                f"""
                INSERT INTO {self.table} (
                    entry_id, timestamp, user_id, action, result,
                    event_type, severity, details, source,
                    prev_hash, entry_hash, signature, status,
                    ip_address, session_id, request_id, correlation_id, metadata
                ) VALUES (%(entry_id)s, %(timestamp)s, %(user_id)s, %(action)s,
                          %(result)s, %(event_type)s, %(severity)s, %(details)s,
                          %(source)s, %(prev_hash)s, %(entry_hash)s, %(signature)s,
                          %(status)s, %(ip_address)s, %(session_id)s, %(request_id)s,
                          %(correlation_id)s, %(metadata)s)
                ON CONFLICT (entry_id) DO UPDATE SET
                    timestamp = EXCLUDED.timestamp,
                    action = EXCLUDED.action,
                    result = EXCLUDED.result
                """,
                {
                    "entry_id": entry.get("entry_id"),
                    "timestamp": entry.get("timestamp"),
                    "user_id": entry.get("user_id"),
                    "action": entry.get("action"),
                    "result": entry.get("result"),
                    "event_type": entry.get("event_type"),
                    "severity": entry.get("severity"),
                    "details": json.dumps(entry.get("details", {})),
                    "source": entry.get("source"),
                    "prev_hash": entry.get("prev_hash"),
                    "entry_hash": entry.get("entry_hash"),
                    "signature": entry.get("signature"),
                    "status": entry.get("status"),
                    "ip_address": entry.get("ip_address"),
                    "session_id": entry.get("session_id"),
                    "request_id": entry.get("request_id"),
                    "correlation_id": entry.get("correlation_id"),
                    "metadata": json.dumps(entry.get("metadata", {})),
                },
            )
            self._conn.commit()

    def read(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Прочитать записи."""
        if not self._initialized:
            self.initialize()
        with self._conn.cursor() as cur:
            query = f"SELECT * FROM {self.table}"
            conditions = []
            params = []

            if filters:
                for key, value in filters.items():
                    if key in ("user_id", "action", "result"):
                        conditions.append(f"{key} = %s")
                        params.append(value)
                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

            query += f" ORDER BY timestamp DESC LIMIT %s OFFSET %s"
            params.extend([limit, offset])

            cur.execute(query, params)
            rows = cur.fetchall()
            columns = [d[0] for d in cur.description]

            result = []
            for row in rows:
                data = dict(zip(columns, row))
                if data.get("details"):
                    data["details"] = (
                        json.loads(data["details"])
                        if isinstance(data["details"], str)
                        else data["details"]
                    )
                if data.get("metadata"):
                    data["metadata"] = (
                        json.loads(data["metadata"])
                        if isinstance(data["metadata"], str)
                        else data["metadata"]
                    )
                result.append(data)
            return result

    def delete(self, entry_id: str) -> bool:
        """Удалить запись."""
        if not self._initialized:
            self.initialize()
        with self._conn.cursor() as cur:
            cur.execute(
                f"DELETE FROM {self.table} WHERE entry_id = %s",
                (entry_id,),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def count(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Количество записей."""
        if not self._initialized:
            self.initialize()
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM {self.table}")
            return cur.fetchone()[0]

    def close(self) -> None:
        """Закрыть подключение."""
        if self._conn:
            self._conn.close()
            self._conn = None
            self._initialized = False


__all__ = ["PostgresBackend", "PostgresBackendError"]
