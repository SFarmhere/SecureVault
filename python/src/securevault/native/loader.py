"""SecureVault - Загрузчик нативных библиотек.

Поиск и загрузка разделяемых библиотек с поддержкой нескольких
платформ (Windows/Linux/macOS).
"""

from __future__ import annotations

import ctypes
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from securevault import exceptions

logger = logging.getLogger(__name__)

# Расширения библиотек по платформам
if sys.platform == "win32":
    _EXT = [".dll"]
elif sys.platform == "darwin":
    _EXT = [".dylib"]
else:
    _EXT = [".so"]


def _candidates(name: str) -> List[str]:
    """Возможные имена файла библиотеки для поиска."""
    names = [name]
    stem, dot, ext = name.rpartition(".")
    if not dot:  # нет расширения — добавить подходящее
        names = [name, f"lib{name}"] if sys.platform != "win32" else [name]
    return names


def search_paths() -> List[str]:
    """Дополнительные пути поиска библиотек."""
    third_party = Path(os.path.expanduser("~")) / ".securevault" / "libs"
    paths = [
        str(third_party),
        os.getcwd(),
        os.environ.get("SECUREVAULT_LIB_PATH", ""),
    ]
    return [p for p in paths if p]


def find_library(name: str, search_names: Optional[List[str]] = None) -> Optional[str]:
    """Найти путь к библиотеке по имени.

    Returns:
        Полный путь к библиотеке или None.
    """
    if os.path.isabs(name) and os.path.exists(name):
        return name
    for candidate in search_names or _candidates(name):
        if Path(candidate).suffix.lower() in _EXT and os.path.exists(candidate):
            return os.path.abspath(candidate)
        # поиск по путям поиска
        for base in search_paths():
            for ext in _EXT:
                full = Path(base) / (candidate + ext)
                if full.exists():
                    return str(full)
    return None


def load_library(name: str, search_names: Optional[List[str]] = None) -> ctypes.CDLL:
    """Загрузить библиотеку.

    Raises:
        LibraryNotFoundError, LibraryLoadError.
    """
    try:
        return ctypes.CDLL(find_library(name, search_names) or name)
    except OSError as e:
        raise exceptions.LibraryLoadError(f"Failed to load '{name}': {e}") from e


__all__ = ["find_library", "load_library", "search_paths"]
