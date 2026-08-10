"""SecureVault - Запуск миграций конфигураций.

Определяет схему миграций и последовательный порядок их применения.
"""

from __future__ import annotations

import logging
from typing import Callable, Dict, Optional

from securevault.utils.config_migrations.config_backup import ConfigBackup
from securevault.utils.config_migrations.v1_to_v2 import migrate_v1_to_v2
from securevault.utils.config_migrations.v2_to_v3 import migrate_v2_to_v3

logger = logging.getLogger(__name__)

# Реестр миграций: { 'из_версии->в_версию': функция }
_MIGRATIONS: Dict[str, Callable[[dict], dict]] = {
    "1->2": migrate_v1_to_v2,
    "2->3": migrate_v2_to_v3,
}


class MigrationRunner:
    """Последовательное применение миграций к конфигурации."""

    def __init__(self, backup_dir: Optional[str] = None, backup: bool = True):
        self.backup_enabled = backup
        self.backup = ConfigBackup(backup_dir) if backup else None

    def get_schema_version(self, config: dict) -> int:
        """Определить версию схемы конфигурации."""
        version = config.get("schema_version")
        if version is None:
            # Декомпозиция по ключам как fallback
            if "protection" in config or "hardware" in config:
                return 1
            return 1
        return int(version)

    def migrate(
        self, config: dict, from_version: Optional[int] = None, to_version: int = 3
    ) -> dict:
        """Мигрировать конфигурацию до целевой версии схемы."""
        current = (
            from_version
            if from_version is not None
            else self.get_schema_version(config)
        )
        if current >= to_version:
            logger.debug(f"Config already at schema v{current}; no migration needed")
            return config

        result = dict(config)
        while current < to_version:
            key = f"{current}->{current + 1}"
            if key not in _MIGRATIONS:
                logger.warning(f"Missing migration step: {key}")
                break
            logger.info(f"Applying migration {key}")
            result = _MIGRATIONS[key](result)
            result["schema_version"] = current + 1
            current += 1
        return result


def run_migrations(
    config: dict, backup_dir: Optional[str] = None, target_version: int = 3
) -> dict:
    """Удобная функция: запустить миграции и вернуть результат."""
    runner = MigrationRunner(backup_dir)
    return runner.migrate(config, to_version=target_version)


__all__ = ["MigrationRunner", "run_migrations"]
