"""SecureVault - Общие фикстуры pytest.

Добавляет каталог src в sys.path, чтобы пакет был импортируем,
и предоставляет вспомогательные фикстуры для модульных тестов.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Путь к каталогу src пакета securevault
SRC = Path(__file__).resolve().parents[2] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture
def temp_dir(tmp_path):
    """Временная директория во временной папке pytest."""
    return tmp_path


@pytest.fixture
def key_manager(tmp_path):
    """KeyManager с изолированным хранилищем."""
    from securevault.core.key_manager import KeyManager

    km = KeyManager(storage_dir=str(tmp_path / "keys"))
    km.initialize()
    return km


@pytest.fixture
def sample_data() -> bytes:
    """Небольшой набор открытых данных для тестов."""
    return b"SecureVault test payload " * 64


@pytest.fixture(autouse=True)
def _isolate_securevault_home(monkeypatch, tmp_path):
    """Изолировать ~/.securevault, чтобы тесты не портили реальные данные."""
    from securevault.utils.config import reset_config

    reset_config()
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    yield
    reset_config()
