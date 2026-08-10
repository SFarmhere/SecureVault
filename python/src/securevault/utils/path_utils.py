"""SecureVault - Утилиты работы с путями.

Безопасная работа с файловой системой: проверка путей, ограничение
выхода за пределы базовой директории (path traversal), создание каталогов.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable, List

from securevault import constants

logger = logging.getLogger(__name__)


def user_home() -> Path:
    """Домашняя директория пользователя."""
    return Path.home()


def securevault_dir() -> Path:
    """Базовая директория приложения (~/.securevault)."""
    return Path.home() / constants.SECUREVAULT_DIR_NAME


def ensure_dir(path: str | os.PathLike) -> Path:
    """Создать директорию (включая родительские), вернуть Path."""
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


def resolve_secured(base: str | os.PathLike, relative: str | os.PathLike) -> Path:
    """Разрешить относительный путь, не позволяя выйти за пределы base.

    Предотвращает path traversal (символические ссылки и '..').

    Args:
        base: Базовая директория.
        relative: Относительный путь (может содержать подкаталоги).

    Returns:
        Абсолютный путь внутри base.

    Raises:
        ValueError: При попытке выйти за пределы base.
    """
    base_path = Path(base).resolve()
    target = (base_path / Path(relative)).resolve()
    if not (target == base_path or base_path in target.parents):
        raise ValueError(f"Path escapes base directory: {relative}")
    return target


def safe_join(base: str | os.PathLike, *parts: str) -> Path:
    """Безопасная конкатенация пути с проверкой выхода за базовый."""
    relative = os.path.join(*parts) if parts else "."
    return resolve_secured(base, relative)


def list_files(directory: str | os.PathLike, pattern: str = "*") -> List[Path]:
    """Список файлов в директории по шаблону (рекурсивно)."""
    return sorted(Path(directory).rglob(pattern))


def list_dirs(directory: str | os.PathLike) -> List[Path]:
    """Список подкаталогов в директории."""
    return sorted(p for p in Path(directory).iterdir() if p.is_dir())


def is_within(base: str | os.PathLike, target: str | os.PathLike) -> bool:
    """Проверить, что target находится внутри base."""
    base_path = Path(base).resolve()
    target_path = Path(target).resolve()
    return target_path == base_path or base_path in target_path.parents


def safe_filename(name: str, max_length: int | None = None) -> str:
    """Санитизировать имя файла, убрав опасные символы."""
    import re

    name = Path(name).name  # отбрасываем пути
    name = re.sub(r"[\x00-\x1f\\/:*?\"<>|]", "_", name).strip()
    limit = max_length or constants.MAX_FILENAME_LENGTH
    if not name or name in (".", ".."):
        raise ValueError("Invalid filename")
    return name[:limit]


def free_disk_space(path: str | os.PathLike) -> int:
    """Свободное место (в байтах) в файловой системе пути."""
    import shutil

    return shutil.disk_usage(Path(path)).free


def is_writable(path: str | os.PathLike) -> bool:
    """Проверить доступность пути для записи."""
    try:
        test = Path(path)
        if test.exists():
            return os.access(test, os.W_OK)
        test.parent.mkdir(parents=True, exist_ok=True)
        return os.access(test.parent, os.W_OK)
    except OSError:
        return False


def iter_bounded(
    directory: str | os.PathLike, max_entries: int = 100_000
) -> Iterable[Path]:
    """Рекурсивный обход с ограничением числа записей."""
    count = 0
    for root, dirs, files in os.walk(directory):
        for name in dirs + files:
            if count >= max_entries:
                logger.warning(f"Reached max entries ({max_entries}) in {directory}")
                return
            count += 1
            yield Path(root) / name


__all__ = [
    "user_home",
    "securevault_dir",
    "ensure_dir",
    "resolve_secured",
    "safe_join",
    "list_files",
    "list_dirs",
    "is_within",
    "safe_filename",
    "free_disk_space",
    "is_writable",
    "iter_bounded",
]
