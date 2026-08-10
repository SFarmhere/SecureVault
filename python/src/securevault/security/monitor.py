"""SecureVault - Мониторинг файловой системы и ключевых каталогов.

Отслеживает изменения, размеры и аномалии в каталогах хранения.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


class FileSnapshot:
    """Снимок состояния файла (для сравнения между проверками)."""

    def __init__(self, path: str, size: int, mtime: float, sha256: str = ""):
        self.path = path
        self.size = size
        self.mtime = mtime
        self.sha256 = sha256


class FileMonitor:
    """Периодический мониторинг директории с обнаружением изменений."""

    def __init__(self, root: str, interval: float = 5.0):
        self.root = Path(root)
        self.interval = interval
        self._snapshots: Dict[str, FileSnapshot] = {}
        self._lock = threading.RLock()
        self._listeners: List[Callable[[str, str, str], None]] = []
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # События
    # ------------------------------------------------------------------
    def on_change(self, callback: Callable[[str, str, str], None]) -> None:
        """Подписаться на изменения: callback(event, path, detail)."""
        self._listeners.append(callback)

    def _notify(self, event: str, path: str, detail: str = "") -> None:
        for cb in self._listeners:
            try:
                cb(event, path, detail)
            except Exception as e:  # noqa: BLE001
                logger.error(f"Listener error: {e}")

    # ------------------------------------------------------------------
    # Сбор / сравнение
    # ------------------------------------------------------------------
    def capture(self) -> None:
        """Снять полный снимок состояния."""
        with self._lock:
            self._snapshots = self._scan()

    def _scan(self) -> Dict[str, FileSnapshot]:
        snap: Dict[str, FileSnapshot] = {}
        for p in self.root.rglob("*"):
            if not p.is_file():
                continue
            try:
                st = p.stat()
                snap[str(p)] = FileSnapshot(str(p), st.st_size, st.st_mtime)
            except OSError:
                continue
        return snap

    def poll(self) -> None:
        """Сравнить текущее состояние с предыдущим снимком."""
        with self._lock:
            current = self._scan()
            paths = set(self._snapshots) | set(current)

            for path in sorted(paths):
                old = self._snapshots.get(path)
                new = current.get(path)
                if old is None and new is not None:
                    self._notify("created", path)
                elif old is not None and new is None:
                    self._notify("deleted", path)
                elif old and new and (old.size != new.size or old.mtime != new.mtime):
                    self._notify("modified", path, f"size {old.size}->{new.size}")

            self._snapshots = current

    # ------------------------------------------------------------------
    # Фоновый поток
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Запустить фоновый цикл мониторинга."""
        if self._thread and self._thread.is_alive():
            return
        self.capture()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        logger.info(f"FileMonitor started: {self.root}")

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.poll()
            except Exception as e:  # noqa: BLE001
                logger.error(f"Monitor poll failed: {e}")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        logger.info("FileMonitor stopped")


__all__ = ["FileMonitor", "FileSnapshot"]
