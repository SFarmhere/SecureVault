"""SecureVault - Репозиторий политик безопасности.

Слой доступа к политикам через сессию БД. Правила политики хранятся
в виде JSON-массива.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from securevault.db.session import DatabaseSession, get_session

logger = logging.getLogger(__name__)


@dataclass
class PolicyRecord:
    """Политика безопасности."""

    policy_id: str
    name: str
    description: str = ""
    rules: List[Dict[str, Any]] = field(default_factory=list)
    enabled: bool = True
    created_at: str = ""
    updated_at: str = ""

    @classmethod
    def from_db_row(cls, row: Dict[str, Any]) -> "PolicyRecord":
        return cls(
            policy_id=row["policy_id"],
            name=row["name"],
            description=row.get("description", ""),
            rules=json.loads(row["rules"]) if row.get("rules") else [],
            enabled=bool(row.get("enabled", 1)),
            created_at=row.get("created_at", ""),
            updated_at=row.get("updated_at", ""),
        )


class PolicyRepository:
    """Репозиторий для работы с политиками."""

    TABLE = "policies"

    def __init__(self, session: Optional[DatabaseSession] = None):
        self.session = session or get_session()

    def create_table(self) -> None:
        self.session.execute(
            f"CREATE TABLE IF NOT EXISTS {self.TABLE} ("
            "policy_id TEXT PRIMARY KEY,"
            "name TEXT NOT NULL UNIQUE,"
            "description TEXT,"
            "rules TEXT,"
            "enabled INTEGER DEFAULT 1,"
            "created_at TEXT,"
            "updated_at TEXT)"
        )

    def save(self, record: PolicyRecord) -> None:
        pd = {
            "policy_id": record.policy_id,
            "name": record.name,
            "description": record.description,
            "rules": json.dumps(record.rules, default=str),
            "enabled": int(record.enabled),
            "created_at": record.created_at,
            "updated_at": record.updated_at,
        }
        columns = ", ".join(pd.keys())
        placeholders = ", ".join(["?"] * len(pd))
        self.session.execute(
            f"INSERT OR REPLACE INTO {self.TABLE} ({columns}) VALUES ({placeholders})",
            tuple(pd.values()),
        )

    def get(self, policy_id: str) -> Optional[PolicyRecord]:
        cursor = self.session.execute(
            f"SELECT * FROM {self.TABLE} WHERE policy_id = ?", (policy_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return PolicyRecord.from_db_row(self._row_dict(cursor, row))

    def get_by_name(self, name: str) -> Optional[PolicyRecord]:
        cursor = self.session.execute(
            f"SELECT * FROM {self.TABLE} WHERE name = ?", (name,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return PolicyRecord.from_db_row(self._row_dict(cursor, row))

    def list(self, enabled_only: bool = False) -> List[PolicyRecord]:
        query = f"SELECT * FROM {self.TABLE}"
        params: tuple = ()
        if enabled_only:
            query += " WHERE enabled = 1"
        cursor = self.session.execute(query, params)
        return [
            PolicyRecord.from_db_row(self._row_dict(cursor, row))
            for row in cursor.fetchall()
        ]

    def delete(self, policy_id: str) -> bool:
        cursor = self.session.execute(
            f"DELETE FROM {self.TABLE} WHERE policy_id = ?", (policy_id,)
        )
        return cursor.rowcount > 0

    @staticmethod
    def _row_dict(cursor, row) -> Dict[str, Any]:
        if hasattr(row, "keys"):
            return dict(row)
        return {col: row[i] for i, col in enumerate(cursor.description)}


__all__ = ["PolicyRepository", "PolicyRecord"]
