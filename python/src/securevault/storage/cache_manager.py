"""SecureVault - Кэширование блоков и файлов.

Предоставляет уведомления об изменениях файлов и кэш блоков
для контейнеров с дедупликацией.
"""

import hashlib
import logging
import threading
import time
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class CacheEntry:
    """Запись кэша блока."""

    __slots__ = ("hash", "data", "size", "last_access", "access_count")

    def __init__(self, hash_val: str, data: bytes):
        self.hash = hash_val
        self.data = data
        self.size = len(data)
        self.last_access = time.monotonic()
        self.access_count = 0

    def touch(self) -> None:
        """Обновить время доступа."""
        self.last_access = time.monotonic()
        self.access_count += 1


class BlockCache:
    """LRU-кэш блоков с дедупликацией."""

    def __init__(self, max_entries: int = 10000, max_bytes: int = 64 * 1024 * 1024):
        self._max_entries = max_entries
        self._max_bytes = max_bytes
        self._cache: Dict[str, CacheEntry] = {}
        self._total_bytes = 0
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0

    def get(self, block_hash: str) -> Optional[bytes]:
        """Получить блок по хешу (возвращает копию)."""
        with self._lock:
            entry = self._cache.get(block_hash)
            if entry is None:
                self._misses += 1
                return None
            entry.touch()
            self._hits += 1
            return entry.data

    def put(self, block_hash: str, data: bytes) -> None:
        """Добавить блок в кэш."""
        with self._lock:
            if block_hash in self._cache:
                return
            entry = CacheEntry(block_hash, data)
            self._cache[block_hash] = entry
            self._total_bytes += entry.size
            self._evict_if_needed()

    def has(self, block_hash: str) -> bool:
        """Проверить наличие блока."""
        with self._lock:
            return block_hash in self._cache

    def remove(self, block_hash: str) -> bool:
        """Удалить блок из кэша."""
        with self._lock:
            entry = self._cache.pop(block_hash, None)
            if entry is None:
                return False
            self._total_bytes -= entry.size
            return True

    def clear(self) -> None:
        """Очистить кэш."""
        with self._lock:
            self._cache.clear()
            self._total_bytes = 0

    def _evict_if_needed(self) -> None:
        """Вытеснить LRU-записи при превышении лимитов."""
        while (
            len(self._cache) > self._max_entries or self._total_bytes > self._max_bytes
        ):
            if not self._cache:
                break
            # Найти самую старую запись
            oldest_hash = min(self._cache, key=lambda h: self._cache[h].last_access)
            entry = self._cache.pop(oldest_hash)
            self._total_bytes -= entry.size

    @property
    def size(self) -> int:
        """Число записей в кэше."""
        with self._lock:
            return len(self._cache)

    @property
    def total_bytes(self) -> int:
        """Общий размер кэша в байтах."""
        with self._lock:
            return self._total_bytes

    @property
    def hit_rate(self) -> float:
        """Доля попаданий в кэше."""
        total = self._hits + self._misses
        return self._hits / total if total else 0.0

    @staticmethod
    def hash_block(data: bytes) -> str:
        """Вычислить SHA-256 хеш блока."""
        return hashlib.sha256(data).hexdigest()


class FileEvent:
    """Событие изменения файла."""

    __slots__ = ("path", "event_type", "size", "timestamp")

    def __init__(self, path: str, event_type: str, size: int = 0):
        self.path = path
        self.event_type = event_type  # created, modified, deleted, renamed
        self.size = size
        self.timestamp = time.time()


class FileChangeNotifier:
    """Уведомитель об изменениях файлов."""

    def __init__(self):
        self._listeners: Dict[str, List[Callable[[FileEvent], None]]] = {}
        self._lock = threading.Lock()

    def subscribe(self, event_type: str, callback: Callable[[FileEvent], None]) -> None:
        """Подписаться на событие."""
        with self._lock:
            self._listeners.setdefault(event_type, []).append(callback)

    def unsubscribe(
        self, event_type: str, callback: Callable[[FileEvent], None]
    ) -> None:
        """Отписаться от события."""
        with self._lock:
            callbacks = self._listeners.get(event_type, [])
            if callback in callbacks:
                callbacks.remove(callback)

    def notify(self, event: FileEvent) -> None:
        """Уведомить подписчиков."""
        with self._lock:
            callbacks = list(self._listeners.get(event.event_type, []))
            callbacks.extend(self._listeners.get("*", []))
        for cb in callbacks:
            try:
                cb(event)
            except Exception as exc:
                logger.warning("Listener error for %s: %s", event.event_type, exc)

    def notify_file_created(self, path: str, size: int = 0) -> None:
        self.notify(FileEvent(path, "created", size))

    def notify_file_modified(self, path: str, size: int = 0) -> None:
        self.notify(FileEvent(path, "modified", size))

    def notify_file_deleted(self, path: str) -> None:
        self.notify(FileEvent(path, "deleted"))

    def notify_file_renamed(self, path: str) -> None:
        self.notify(FileEvent(path, "renamed"))


_default_cache: Optional[BlockCache] = None
_default_notifier: Optional[FileChangeNotifier] = None


def get_cache() -> BlockCache:
    """Получить глобальный кэш блоков."""
    global _default_cache
    if _default_cache is None:
        _default_cache = BlockCache()
    return _default_cache


def get_notifier() -> FileChangeNotifier:
    """Получить глобальный уведомитель."""
    global _default_notifier
    if _default_notifier is None:
        _default_notifier = FileChangeNotifier()
    return _default_notifier


__all__ = [
    "BlockCache",
    "CacheEntry",
    "FileChangeNotifier",
    "FileEvent",
    "get_cache",
    "get_notifier",
]
