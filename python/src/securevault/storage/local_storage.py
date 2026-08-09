"""SecureVault - Локальное хранилище файлов и контейнеров."""

import hashlib
import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from securevault.storage.backend import StorageMetadata

logger = logging.getLogger(__name__)


class LocalStorageError(Exception):
    """Ошибка локального хранилища."""


class FileLock:
    """Простая файловая блокировка (cross-platform)."""

    def __init__(self, path: Path):
        self._path = path
        self._lock_file = path.with_suffix(path.suffix + ".lock")
        self._fd: Optional[int] = None

    def acquire(self) -> bool:
        try:
            self._fd = os.open(
                str(self._lock_file), os.O_CREAT | os.O_EXCL | os.O_WRONLY
            )
            return True
        except FileExistsError:
            return False

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        if self._lock_file.exists():
            self._lock_file.unlink()

    def __enter__(self):
        if not self.acquire():
            raise LocalStorageError(f"File locked: {self._path}")
        return self

    def __exit__(self, *args):
        self.release()


class LocalStorage:
    """Локальное хранилище файлов с метаданными и целостностью."""

    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _resolve(self, file_id: str) -> Path:
        safe = hashlib.sha256(file_id.encode()).hexdigest()
        return self.base_dir / safe[:2] / safe[2:]

    def _meta_path(self, path: Path) -> Path:
        return path.with_suffix(path.suffix + ".meta")

    def store(
        self, file_id: str, data: bytes, metadata: Optional[StorageMetadata] = None
    ) -> str:
        with self._lock:
            path = self._resolve(file_id)
            path.parent.mkdir(parents=True, exist_ok=True)
            with FileLock(path):
                path.write_bytes(data)
                if metadata:
                    meta = metadata.to_dict()
                    meta["sha256"] = hashlib.sha256(data).hexdigest()
                    meta["size"] = len(data)
                    self._meta_path(path).write_text(json.dumps(meta))
            return file_id

    def retrieve(self, file_id: str) -> Optional[bytes]:
        with self._lock:
            path = self._resolve(file_id)
            if not path.exists():
                return None
            return path.read_bytes()

    def delete(self, file_id: str, secure: bool = False) -> bool:
        with self._lock:
            path = self._resolve(file_id)
            if not path.exists():
                return False
            if secure:
                self._secure_wipe(path)
            path.unlink(missing_ok=True)
            self._meta_path(path).unlink(missing_ok=True)
            return True

    def exists(self, file_id: str) -> bool:
        return self._resolve(file_id).exists()

    def get_metadata(self, file_id: str) -> Optional[Dict[str, Any]]:
        path = self._resolve(file_id)
        meta_path = self._meta_path(path)
        if not meta_path.exists():
            return None
        return json.loads(meta_path.read_text())

    def list_files(self) -> List[str]:
        with self._lock:
            return [
                p.stem
                for p in self.base_dir.rglob("*")
                if p.is_file() and p.suffix != ".meta"
            ]

    def verify_integrity(self, file_id: str) -> bool:
        path = self._resolve(file_id)
        if not path.exists():
            return False
        meta = self.get_metadata(file_id)
        if not meta or "sha256" not in meta:
            return True
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        return actual == meta["sha256"]

    @staticmethod
    def _secure_wipe(path: Path) -> None:
        size = path.stat().st_size
        with path.open("r+b") as f:
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())

    def disk_usage(self) -> Dict[str, int]:
        total = sum(f.stat().st_size for f in self.base_dir.rglob("*") if f.is_file())
        return {"total_bytes": total, "file_count": len(self.list_files())}


__all__ = ["LocalStorage", "LocalStorageError", "FileLock"]
