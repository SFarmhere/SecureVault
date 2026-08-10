"""SecureVault - Настройка журналирования.

Предоставляет единую конфигурацию логирования для всего приложения:
- Вывод в консоль и файл
- Ротация по размеру
- Форматы с временной меткой
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from securevault import constants

DEFAULT_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
FILE_FORMAT = (
    "%(asctime)s | %(levelname)-8s | %(name)s | %(pathname)s:%(lineno)d | %(message)s"
)


def get_log_formatter(fmt: str = DEFAULT_FORMAT) -> logging.Formatter:
    """Вернуть formatter с указанным шаблоном."""
    return logging.Formatter(fmt)


def setup_console_handler(logger: logging.Logger, level: int = logging.INFO) -> None:
    """Добавить обработчик вывода в консоль."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(get_log_formatter())
    logger.addHandler(handler)


def setup_file_handler(
    logger: logging.Logger,
    log_file: Optional[str] = None,
    level: int = logging.INFO,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
) -> Optional[RotatingFileHandler]:
    """Добавить ротируемый файловый обработчик."""
    path = (
        Path(log_file)
        if log_file
        else Path.home() / constants.SECUREVAULT_DIR_NAME / constants.LOG_FILE
    )
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            str(path),
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        handler.setLevel(level)
        handler.setFormatter(get_log_formatter(FILE_FORMAT))
        logger.addHandler(handler)
        return handler
    except OSError as e:
        logger.warning(f"Cannot setup file logging to {path}: {e}")
        return None


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[str] = None,
    file_level: Optional[int] = None,
    propagate_root: bool = False,
) -> logging.Logger:
    """Настроить корневой логгер SecureVault.

    Args:
        level: Уровень для консоли.
        log_file: Путь к файлу журнала (None - файл в ~/.securevault).
        file_level: Уровень для файла (по умолчанию равен level).
        propagate_root: Пробрасывать ли записи в корневой логгер.

    Returns:
        Настроенный корневой логгер 'securevault'.
    """
    root = logging.getLogger("securevault")
    root.setLevel(level)
    root.propagate = propagate_root

    # Избегаем дублирования обработчиков при повторном вызове
    for handler in list(root.handlers):
        root.removeHandler(handler)

    setup_console_handler(root, level=level)
    if log_file is None or log_file:
        setup_file_handler(root, log_file=log_file, level=file_level or level)
    return root


def get_logger(name: str) -> logging.Logger:
    """Вернуть логгер внутри пространства имён securevault."""
    return logging.getLogger(f"securevault.{name}")


__all__ = [
    "setup_logging",
    "setup_console_handler",
    "setup_file_handler",
    "get_logger",
    "DEFAULT_FORMAT",
    "FILE_FORMAT",
]
