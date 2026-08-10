"""SecureVault - Нативный контейнерный модуль (Python-адаптер).

Предоставляет контейнерные операции с автоматическим выбором между
нативной библиотекой (если доступна) и чистой Python-реализацией.
"""

from __future__ import annotations

import logging
from typing import Dict, Optional

from securevault.native import get_native_manager

logger = logging.getLogger(__name__)


def is_available() -> bool:
    """Доступна ли нативная (компилированная) реализация контейнеров."""
    try:
        manager = get_native_manager()
        return bool(manager.is_container_available())
    except Exception:  # noqa: BLE001
        return False


def create_container(
    files: Dict[str, bytes],
    key: bytes,
    container_id: Optional[str] = None,
    format_version: int = 1,
) -> bytes:
    """Создать зашифрованный контейнер из набора файлов.

    Args:
        files: Словарь {name: data}.
        key: Ключ контейнера (AES-256).
        container_id: Идентификатор контейнера.
        format_version: Версия формата (1 - обычный, 2 - скрытый).

    Returns:
        Сериализованный зашифрованный контейнер.
    """
    from securevault.protection_levels.container import ContainerEntry, ContainerFormat

    container = ContainerFormat(
        container_id=container_id,
        format_version=format_version,
    )
    for name, data in files.items():
        container.add(ContainerEntry(name, data))
    return container.encrypt_payload(key, container_id=container_id)


def open_container(ciphertext: bytes, key: bytes) -> Dict[str, bytes]:
    """Расшифровать и открыть контейнер как {name: data}."""
    from securevault.protection_levels.container import ContainerFormat

    container = ContainerFormat.decrypt_payload(ciphertext, key)
    return {name: entry.data for name, entry in container.entries.items()}


def list_files(ciphertext: bytes, key: bytes) -> list:
    """Список файлов в контейнере (без извлечения)."""
    return list(open_container(ciphertext, key).keys())


__all__ = [
    "is_available",
    "create_container",
    "open_container",
    "list_files",
]
