"""SecureVault - Миграция конфигураций между версиями.

Позволяет плавно переводить пользовательскую конфигурацию со старой
схемы на новую с созданием резервных копий.
"""

from securevault.utils.config_migrations.migration_runner import (  # noqa: F401
    MigrationRunner,
    run_migrations,
)

__all__ = ["MigrationRunner", "run_migrations"]
