"""SecureVault - Утилиты работы с файлами.

Безопасное чтение/запись, атомарная запись, затирание и проверка
целостности файлов.
"""

from __future__ import annotations

import hashlib
import logging
import os
import tempfile
from pathlib import Path
from typing import Optional

from securevault import exceptions

logger = logging.getLogger(__name__)


def read_bytes(path: str | os.PathLike) -> bytes:
    """Прочитать файл как байты."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    try:
        return p.read_bytes()
    except OSError as e:
        raise exceptions.StorageError(f"Failed to read {p}: {e}") from e


def write_bytes(path: str | os.PathLike, data: bytes) -> Path:
    """Записать байты в файл (создавая родительские каталоги)."""
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p
    except OSError as e:
        raise exceptions.StorageError(f"Failed to write {p}: {e}") from e


def read_text(path: str | os.PathLike, encoding: str = "utf-8") -> str:
    """Прочитать текстовый файл."""
    return read_bytes(path).decode(encoding)


def write_text(path: str | os.PathLike, content: str, encoding: str = "utf-8") -> Path:
    """Записать текст в файл."""
    return write_bytes(path, content.encode(encoding))


def atomic_write(
    path: str | os.PathLike, data: bytes, temp_dir: Optional[str] = None
) -> Path:
    """Атомарная запись: пишем во временный файл, затем переименовываем.

    Гарантирует, что читатели увидят либо старое, либо новое содержимое,
    но не частично записанное.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    base = Path(temp_dir) if temp_dir else p.parent
    fd, tmp_name = tempfile.mkstemp(prefix=f".{p.name}.", suffix=".tmp", dir=str(base))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, p)
        return p
    finally:
        # На случай ошибки удаляем возможный временный файл
        if os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def file_checksum(path: str | os.PathLike, algorithm: str = "sha256") -> str:
    """Вычислить контрольную сумму файла."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def secure_delete(path: str | os.PathLike, passes: int = 3) -> bool:
    """Криптографическое затирание и удаление файла."""
    p = Path(path)
    if not p.exists():
        return False
    size = p.stat().st_size
    with open(p, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(os.urandom(size))
            f.flush()
            os.fsync(f.fileno())
    p.unlink()
    return True


def make_temp_dir(prefix: str = "securevault-") -> Path:
    """Создать временную директорию."""
    return Path(tempfile.mkdtemp(prefix=prefix))


def ensure_parent_dir(path: str | os.PathLike) -> Path:
    """Создать родительскую директорию файла, вернуть Path файла."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


__all__ = [
    "read_bytes",
    "write_bytes",
    "read_text",
    "write_text",
    "atomic_write",
    "file_checksum",
    "secure_delete",
    "make_temp_dir",
    "ensure_parent_dir",
]
