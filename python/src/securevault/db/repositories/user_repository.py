"""SecureVault - Репозиторий пользователей.

Слой доступа к записям пользователей через сессию БД (модель UserRecord).
"""

from __future__ import annotations

import logging
from typing import List, Optional

from securevault.db.models import UserRecord
from securevault.db.session import DatabaseSession, get_session

logger = logging.getLogger(__name__)


class UserRepository:
    """Репозиторий для работы с пользователями."""

    TABLE = "users"

    def __init__(self, session: Optional[DatabaseSession] = None):
        self.session = session or get_session()

    def create_table(self) -> None:
        self.session.execute(UserRecord.create_table_sql())

    def save(self, record: UserRecord) -> None:
        data = record.to_db_dict()
        columns = ", ".join(data.keys())
        placeholders = ", ".join(["?"] * len(data))
        self.session.execute(
            f"INSERT OR REPLACE INTO {self.TABLE} ({columns}) VALUES ({placeholders})",
            tuple(data.values()),
        )

    def get(self, user_id: str) -> Optional[UserRecord]:
        cursor = self.session.execute(
            f"SELECT * FROM {self.TABLE} WHERE user_id = ?", (user_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return UserRecord.from_db_row(self._row_dict(cursor, row))

    def get_by_username(self, username: str) -> Optional[UserRecord]:
        cursor = self.session.execute(
            f"SELECT * FROM {self.TABLE} WHERE username = ?", (username,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return UserRecord.from_db_row(self._row_dict(cursor, row))

    def list(self, status: Optional[str] = None) -> List[UserRecord]:
        query = f"SELECT * FROM {self.TABLE}"
        params: tuple = ()
        if status:
            query += " WHERE status = ?"
            params = (status,)
        cursor = self.session.execute(query, params)
        return [
            UserRecord.from_db_row(self._row_dict(cursor, row))
            for row in cursor.fetchall()
        ]

    def update_last_login(self, user_id: str, last_login: str) -> None:
        self.session.execute(
            f"UPDATE {self.TABLE} SET last_login = ? WHERE user_id = ?",
            (last_login, user_id),
        )

    def delete(self, user_id: str) -> bool:
        cursor = self.session.execute(
            f"DELETE FROM {self.TABLE} WHERE user_id = ?", (user_id,)
        )
        return cursor.rowcount > 0

    def count(self) -> int:
        cursor = self.session.execute(f"SELECT COUNT(*) FROM {self.TABLE}")
        return cursor.fetchone()[0]

    @staticmethod
    def _row_dict(cursor, row):
        if hasattr(row, "keys"):
            return dict(row)
        return {col: row[i] for i, col in enumerate(cursor.description)}


__all__ = ["UserRepository"]
