"""SecureVault - Безопасный ввод/вывод (затирание памяти и файлов).

Программные реализации операций Secure I/O поверх stdlib.
"""

from __future__ import annotations

import logging
from pathlib import Path

from securevault.utils import file_utils

logger = logging.getLogger(__name__)

WIPE_PASSES = 3


def wipe_memory(data: bytearray) -> None:
    """Безвозвратно затереть данные в памяти."""
    for i in range(len(data)):
        data[i] = 0


def wipe_buffer(buf: memoryview) -> None:
    """Затереть memoryview-буфер."""
    for i in range(len(buf)):
        buf[i] = 0


def secure_write(path: str, data: bytes, sync: bool = True) -> Path:
    """Безопасная запись файла (атомарная, с fsync)."""
    return file_utils.atomic_write(path, data)


def secure_wipe_file(path: str, passes: int = WIPE_PASSES) -> bool:
    """Криптографически затереть и удалить файл."""
    return file_utils.secure_delete(path, passes)


def protect_against_swap() -> None:
    """Попытка минимизации свопа (no-op, требует root/пр. политик)."""
    logger.info("Memory swap protection not applied (requires OS-level config)")


__all__ = [
    "wipe_memory",
    "wipe_buffer",
    "secure_write",
    "secure_wipe_file",
    "protect_against_swap",
    "WIPE_PASSES",
]
