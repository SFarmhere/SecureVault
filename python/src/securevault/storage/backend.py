"""SecureVault - Бэкенд хранения (локальное, облачное, БД)."""

import hashlib
import json
import logging
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from securevault.storage.cache_manager import get_cache
from securevault.storage.database_storage import DatabaseStorage
from securevault.storage.deduplication_chunking import CdcChunker, ManifestStore

logger = logging.getLogger(__name__)


@dataclass
class StorageMetadata:
    """Метаданные файла/контейнера."""

    path: str
    size: int = 0
    sha256: str = ""
    created_at: str = ""
    modified_at: str = ""
    security_level: str = "CONTAINER"
    compression: str = "ZSTD"
    encrypted: bool = True
    container_id: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


class StorageBackend(ABC):
    """Абстрактный базовый класс бэкенда хранения."""

    @abstractmethod
    def store(
        self, key: str, data: bytes, metadata: Optional[StorageMetadata] = None
    ) -> str: ...

    @abstractmethod
    def retrieve(self, key: str) -> Optional[bytes]: ...

    @abstractmethod
    def delete(self, key: str) -> bool: ...

    @abstractmethod
    def exists(self, key: str) -> bool: ...

    @abstractmethod
    def list_keys(self) -> List[str]: ...


class LocalStorageBackend(StorageBackend):
    """Локальный файловый бэкенд."""

    def __init__(self, base_dir: str):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    def _key_path(self, key: str) -> Path:
        safe = hashlib.sha256(key.encode()).hexdigest()
        return self.base_dir / safe[:2] / safe[2:]

    def store(
        self, key: str, data: bytes, metadata: Optional[StorageMetadata] = None
    ) -> str:
        with self._lock:
            path = self._key_path(key)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            if metadata:
                meta_path = path.with_suffix(path.suffix + ".meta")
                meta_path.write_text(json.dumps(metadata.to_dict()))
            return key

    def retrieve(self, key: str) -> Optional[bytes]:
        with self._lock:
            path = self._key_path(key)
            return path.read_bytes() if path.exists() else None

    def delete(self, key: str) -> bool:
        with self._lock:
            path = self._key_path(key)
            if path.exists():
                path.unlink()
                meta = path.with_suffix(path.suffix + ".meta")
                if meta.exists():
                    meta.unlink()
                return True
            return False

    def exists(self, key: str) -> bool:
        return self._key_path(key).exists()

    def list_keys(self) -> List[str]:
        with self._lock:
            return [
                p.stem
                for p in self.base_dir.rglob("*")
                if p.is_file() and p.suffix != ".meta"
            ]


class DeduplicatingStorageBackend(StorageBackend):
    """Бэкенд с дедупликацией блоков (CDC)."""

    def __init__(self, base_dir: str, cache=None):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._cache = cache or get_cache()
        self._manifest = ManifestStore()
        self._chunker = CdcChunker()
        self._lock = threading.RLock()

    def store(
        self, key: str, data: bytes, metadata: Optional[StorageMetadata] = None
    ) -> str:
        with self._lock:
            chunks = self._chunker.chunk(data)
            for chunk in chunks:
                if not self._cache.has(chunk.hash_val):
                    block_path = self._block_path(chunk.hash_val)
                    block_path.parent.mkdir(parents=True, exist_ok=True)
                    block_path.write_bytes(chunk.data)
                    self._cache.put(chunk.hash_val, chunk.data)
            self._manifest.add_file(key, chunks)
            return key

    def retrieve(self, key: str) -> Optional[bytes]:
        with self._lock:
            hashes = self._manifest.get_blocks(key)
            if not hashes:
                return None
            parts = []
            for h in hashes:
                data = self._cache.get(h)
                if data is None:
                    block_path = self._block_path(h)
                    if not block_path.exists():
                        return None
                    data = block_path.read_bytes()
                    self._cache.put(h, data)
                parts.append(data)
            return b"".join(parts)

    def delete(self, key: str) -> bool:
        with self._lock:
            self._manifest.remove_file(key)
            return True

    def exists(self, key: str) -> bool:
        return bool(self._manifest.get_blocks(key))

    def list_keys(self) -> List[str]:
        with self._lock:
            return list(self._manifest._files.keys())

    def _block_path(self, hash_val: str) -> Path:
        return self.base_dir / "blocks" / hash_val[:2] / hash_val[2:]

    def collect_garbage(self) -> int:
        with self._lock:
            removed = self._manifest.collect_garbage()
            count = 0
            for h in removed:
                path = self._block_path(h)
                if path.exists():
                    path.unlink()
                    count += 1
            return count


class StorageBackendManager:
    """Менеджер бэкендов хранения (локальный + облачный + БД)."""

    def __init__(
        self,
        local_dir: str,
        db_session=None,
        cloud_backend: Optional[StorageBackend] = None,
    ):
        self.local = LocalStorageBackend(local_dir)
        self.dedup = DeduplicatingStorageBackend(
            str(Path(local_dir) / "dedup"), cache=get_cache()
        )
        self.cloud = cloud_backend
        self.db = DatabaseStorage(db_session) if db_session else None
        self._lock = threading.RLock()

    def store_file(
        self,
        file_id: str,
        data: bytes,
        metadata: Optional[StorageMetadata] = None,
        use_dedup: bool = True,
    ) -> str:
        backend = self.dedup if use_dedup else self.local
        backend.store(file_id, data, metadata)
        if self.db and metadata:
            self.db.create_container(
                {
                    "container_id": file_id,
                    "owner_id": metadata.extra.get("owner_id", ""),
                    "name": metadata.path,
                    "path": str(metadata.path),
                    "total_size": metadata.size,
                    "used_size": metadata.size,
                    "file_count": 1,
                    "security_level": metadata.security_level,
                    "compression": metadata.compression,
                    "created_at": metadata.created_at,
                    "modified_at": metadata.modified_at,
                }
            )
        return file_id

    def retrieve_file(self, file_id: str, use_dedup: bool = True) -> Optional[bytes]:
        backend = self.dedup if use_dedup else self.local
        return backend.retrieve(file_id)

    def delete_file(self, file_id: str, use_dedup: bool = True) -> bool:
        backend = self.dedup if use_dedup else self.local
        return backend.delete(file_id)

    def file_exists(self, file_id: str, use_dedup: bool = True) -> bool:
        backend = self.dedup if use_dedup else self.local
        return backend.exists(file_id)

    def sync_to_cloud(self, file_id: str) -> bool:
        if not self.cloud:
            return False
        data = self.retrieve_file(file_id)
        if data is None:
            return False
        self.cloud.store(file_id, data)
        return True

    def sync_from_cloud(self, file_id: str) -> bool:
        if not self.cloud:
            return False
        data = self.cloud.retrieve(file_id)
        if data is None:
            return False
        self.store_file(file_id, data)
        return True

    def gc_dedup(self) -> int:
        return self.dedup.collect_garbage()


__all__ = [
    "StorageBackend",
    "LocalStorageBackend",
    "DeduplicatingStorageBackend",
    "StorageBackendManager",
    "StorageMetadata",
]
