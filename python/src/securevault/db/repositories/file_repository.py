"""SecureVault - Репозиторий файлов.

Слой доступа к метаданным зашифрованных файлов через сессию БД.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from securevault.db.session import DatabaseSession, get_session

logger = logging.getLogger(__name__)


@dataclass
class FileRecord:
    """Метаданные зашифрованного файла."""

    file_id: str
    path: str
    size: int = 0
    sha256: str = ""
    protection_level: str = "individual"
    algorithm: str = "aes-256-gcm"
    owner: str = ""
    container_id: Optional[str] = None
    created_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_db_row(cls, row: Dict[str, Any]) -> "FileRecord":
        return cls(
            file_id=row["file_id"],
            path=row["path"],
            size=row.get("size", 0),
            sha256=row.get("sha256", ""),
            protection_level=row.get("protection_level", "individual"),
            algorithm=row.get("algorithm", "aes-256-gcm"),
            owner=row.get("owner", ""),
            container_id=row.get("container_id"),
            created_at=row.get("created_at", ""),
            metadata=json.loads(row["metadata"]) if row.get("metadata") else {},
        )


class FileRepository:
    """Репозиторий для работы с файлами."""

    TABLE = "files"

    def __init__(self, session: Optional[DatabaseSession] = None):
        self.session = session or get_session()

    def create_table(self) -> None:
        self.session.execute(
            f"CREATE TABLE IF NOT EXISTS {self.TABLE} ("
            "file_id TEXT PRIMARY KEY,"
            "path TEXT NOT NULL,"
            "size INTEGER DEFAULT 0,"
            "sha256 TEXT,"
            "protection_level TEXT,"
            "algorithm TEXT,"
            "owner TEXT,"
            "container_id TEXT,"
            "created_at TEXT,"
            "metadata TEXT)"
        )
        self.session.execute(
            f"CREATE INDEX IF NOT EXISTS idx_files_path ON {self.TABLE}(path)"
        )

    def save(self, record: FileRecord) -> None:
        fd = {
            "file_id": record.file_id,
            "path": record.path,
            "size": record.size,
            "sha256": record.sha256,
            "protection_level": record.protection_level,
            "algorithm": record.algorithm,
            "owner": record.owner,
            "container_id": record.container_id,
            "created_at": record.created_at,
            "metadata": json.dumps(record.metadata, default=str),
        }
        columns = ", ".join(fd.keys())
        placeholders = ", ".join(["?"] * len(fd))
        self.session.execute(
            f"INSERT OR REPLACE INTO {self.TABLE} ({columns}) VALUES ({placeholders})",
            tuple(fd.values()),
        )

    def get(self, file_id: str) -> Optional[FileRecord]:
        cursor = self.session.execute(
            f"SELECT * FROM {self.TABLE} WHERE file_id = ?", (file_id,)
        )
        row = cursor.fetchone()
        if not row:
            return None
        return FileRecord.from_db_row(self._row_dict(cursor, row))

    def list(self, owner: Optional[str] = None, limit: int = 100) -> List[FileRecord]:
        query = f"SELECT * FROM {self.TABLE}"
        params: list = []
        if owner:
            query += " WHERE owner = ?"
            params.append(owner)
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        cursor = self.session.execute(query, tuple(params))
        return [
            FileRecord.from_db_row(self._row_dict(cursor, row))
            for row in cursor.fetchall()
        ]

    def delete(self, file_id: str) -> bool:
        cursor = self.session.execute(
            f"DELETE FROM {self.TABLE} WHERE file_id = ?", (file_id,)
        )
        return cursor.rowcount > 0

    def count(self) -> int:
        cursor = self.session.execute(f"SELECT COUNT(*) FROM {self.TABLE}")
        return cursor.fetchone()[0]

    @staticmethod
    def _row_dict(cursor, row) -> Dict[str, Any]:
        if hasattr(row, "keys"):
            return dict(row)
        return {col: row[i] for i, col in enumerate(cursor.description)}


__all__ = ["FileRepository", "FileRecord"]
