"""SecureVault - Тестовые данные (константы и генераторы)."""

from __future__ import annotations

import os

TEST_SECRET = b"classified material for tests " * 40
TEST_PASSWORD = "SuperSecretPass1!"
WEAK_PASSWORD = "abc"


def make_temp_file(dir_path, name: str = "file.txt", size: int = 1024) -> str:
    """Создать временный файл заданного размера."""
    path = os.path.join(str(dir_path), name)
    with open(path, "wb") as fh:
        fh.write(os.urandom(size))
    return path


def random_key(size: int = 32) -> bytes:
    return os.urandom(size)


__all__ = [
    "TEST_SECRET",
    "TEST_PASSWORD",
    "WEAK_PASSWORD",
    "make_temp_file",
    "random_key",
]
