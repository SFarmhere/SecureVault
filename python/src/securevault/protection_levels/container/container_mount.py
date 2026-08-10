"""SecureVault - Монтирование контейнеров (уровень CONTAINER).

Обеспечивает «монтирование» контейнера: открытие, изменение и
атомарную фиксацию изменений в рамках контекстного менеджера.
"""

from __future__ import annotations

import logging

from securevault.protection_levels.container.container_manager import (
    ContainerEntry,
    ContainerFormat,
    ContainerFormatError,
)

logger = logging.getLogger(__name__)


class ContainerMountError(Exception):
    """Ошибка монтирования контейнера."""


class ContainerMount:
    """Контекстный менеджер безопасного изменения контейнера.

    Изменения применяются к in-memory контейнеру; фиксация происходит
    только при ``commit()`` или успешном завершении контекста.
    """

    def __init__(self, container: ContainerFormat):
        self.container = container
        self._dirty = False

    @property
    def is_dirty(self) -> bool:
        return self._dirty

    def add_file(
        self, name: str, data: bytes, mime: str = "application/octet-stream"
    ) -> None:
        """Добавить файл в контейнер (в память)."""
        self.container.add(ContainerEntry(name, data, mime))
        self._dirty = True

    def extract_file(self, name: str) -> bytes:
        """Извлечь содержимое файла из контейнера."""
        entry = self.container.get(name)
        if entry is None:
            raise ContainerFormatError(f"File not found in container: {name}")
        return entry.data

    def delete_file(self, name: str) -> bool:
        """Удалить файл из контейнера."""
        removed = self.container.remove(name)
        if removed:
            self._dirty = True
        return removed

    def list_files(self) -> list:
        return self.container.names()

    def commit(self) -> bytes:
        """Зафиксировать изменения и вернуть упакованный контейнер."""
        packed = self.container.pack()
        self._dirty = False
        return packed

    def rollback(self) -> None:
        """Отменить накопленные изменения."""
        self._dirty = False
        logger.info("Container mount rolled back")

    def __enter__(self) -> "ContainerMount":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if exc_type is None and self._dirty:
            self.commit()
        return False


__all__ = ["ContainerMount", "ContainerMountError"]
