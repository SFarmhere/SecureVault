"""SecureVault - Уровень CONTAINER (whole-container шифрование).

Высокоуровневая работа с зашифрованными контейнерами: создание из набора
файлов, открытие, добавление/извлечение. Использует ContainerFormat
для упаковки и AES-256-GCM для шифрования контейнера ключом.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from securevault.protection_levels.container import (
    ContainerEntry,
    ContainerFormat,
    ContainerFormatError,
)

logger = logging.getLogger(__name__)


class ContainerLevel:
    """Работа с контейнером на уровне защиты CONTAINER."""

    def __init__(self, container_id: Optional[str] = None, format_version: int = 1):
        self.container_id = container_id
        self.format_version = format_version

    def create(self, files: Dict[str, bytes], key: bytes) -> bytes:
        """Создать зашифрованный контейнер из словаря {name: data}.

        Returns:
            Зашифрованные байты контейнера.
        """
        container = ContainerFormat(
            container_id=self.container_id,
            format_version=self.format_version,
        )
        for name, data in files.items():
            container.add(ContainerEntry(name, data))
        return container.encrypt_payload(key, container_id=self.container_id)

    def open(self, ciphertext: bytes, key: bytes) -> Dict[str, bytes]:
        """Расшифровать и открыть контейнер как {name: data}."""
        container = ContainerFormat.decrypt_payload(ciphertext, key)
        return {name: entry.data for name, entry in container.entries.items()}

    def add_file(self, ciphertext: bytes, key: bytes, name: str, data: bytes) -> bytes:
        """Добавить файл в существующий зашифрованный контейнер."""
        container = ContainerFormat.decrypt_payload(ciphertext, key)
        container.add(ContainerEntry(name, data))
        return container.encrypt_payload(key, container_id=container.container_id)

    def extract_file(self, ciphertext: bytes, key: bytes, name: str) -> bytes:
        """Извлечь файл из зашифрованного контейнера."""
        container = ContainerFormat.decrypt_payload(ciphertext, key)
        entry = container.get(name)
        if entry is None:
            raise ContainerFormatError(f"File not found: {name}")
        return entry.data

    def list_files(self, ciphertext: bytes, key: bytes) -> list:
        """Список файлов в контейнере (без извлечения)."""
        container = ContainerFormat.decrypt_payload(ciphertext, key)
        return container.names()


__all__ = ["ContainerLevel"]
