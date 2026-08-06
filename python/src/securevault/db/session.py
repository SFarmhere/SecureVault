"""SecureVault - Сессии базы данных.

Предоставляет управление подключениями к SQLite/PostgreSQL.
"""

import logging
import sqlite3
from typing import Optional, Any, Dict
from pathlib import Path

logger = logging.getLogger(__name__)


class DatabaseSessionError(Exception):
    """Ошибка сессии БД."""
    pass


class DatabaseSession:
    """Менеджер подключений к базе данных."""

    def __init__(self, db_path: Optional[str] = None, backend: str = "sqlite"):
        self.backend = backend
        self._path = db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._initialized = False

    def initialize(self) -> None:
        """Инициализировать подключение."""
        if self.backend == "sqlite":
            if not self._path:
                home = Path.home()
                self._path = str(home / ".securevault" / "securevault.db")
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self._path)
            self._conn.row_factory = sqlite3.Row
            self._initialized = True
            logger.info(f"SQLite session initialized: {self._path}")
        elif self.backend == "postgresql":
            try:
                import psycopg2
                from securevault.utils.config import get_config
                cfg = get_config().get("database", {})
                self._conn = psycopg2.connect(
                    host=cfg.get("host", "localhost"),
                    port=cfg.get("port", 5432),
                    dbname=cfg.get("dbname", "securevault"),
                    user=cfg.get("user", "postgres"),
                    password=cfg.get("password", ""),
                )
                self._initialized = True
                logger.info("PostgreSQL session initialized")
            except ImportError:
                raise DatabaseSessionError("psycopg2 not installed")
        else:
            raise DatabaseSessionError(f"Unsupported backend: {self.backend}")

    def get_connection(self) -> Any:
        """Получить соединение."""
        if not self._initialized or self._conn is None:
            self.initialize()
        return self._conn

    def execute(self, query: str, params: tuple = ()) -> Any:
        """Выполнить запрос."""
        conn = self.get_connection()
        cursor = conn.execute(query, params)
        conn.commit()
        return cursor

    def close(self) -> None:
        """Закрыть соединение."""
        if self._conn:
            self._conn.close()
            self._conn = None
            self._initialized = False
            logger.info("Database session closed")

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


_default_session: Optional[DatabaseSession] = None


def get_session() -> DatabaseSession:
    """Получить глобальную сессию БД."""
    global _default_session
    if _default_session is None:
        _default_session = DatabaseSession()
    return _default_session


__all__ = ["DatabaseSession", "DatabaseSessionError", "get_session"]