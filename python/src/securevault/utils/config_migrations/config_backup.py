"""SecureVault - Резервное копирование конфигураций.

Создание временных копий конфигурационных файлов перед миграцией
с возможностью восстановления.
"""

from __future__ import annotations

import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class ConfigBackup:
    """Управление резервными копиями конфигурационных файлов."""

    def __init__(self, backup_dir: Optional[str] = None):
        self.backup_dir = (
            Path(backup_dir)
            if backup_dir
            else Path.home() / ".securevault" / "backups" / "configs"
        )
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def backup(self, config_path: str) -> Path:
        """Скопировать конфигурационный файл в резервную копию.

        Args:
            config_path: Путь к исходному файлу конфигурации.

        Returns:
            Путь к созданной резервной копии.
        """
        src = Path(config_path)
        if not src.exists():
            raise FileNotFoundError(f"Config not found: {src}")
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        target = self.backup_dir / f"{src.stem}.{stamp}{src.suffix}"
        shutil.copy2(src, target)
        logger.info(f"Backed up config {src} -> {target}")
        return target

    def list_backups(self) -> list:
        """Список резервных копий (от новых к старым)."""
        return sorted(self.backup_dir.glob("*"), reverse=True)

    def restore(self, backup_path: str, target_path: str) -> Path:
        """Восстановить конфигурацию из резервной копии."""
        src = Path(backup_path)
        if not src.exists():
            raise FileNotFoundError(f"Backup not found: {src}")
        target = Path(target_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        logger.info(f"Restored config {src} -> {target}")
        return target


__all__ = ["ConfigBackup"]
