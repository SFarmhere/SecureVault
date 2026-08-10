"""SecureVault - Модульные тесты миграций конфигураций."""

from securevault.utils.config_migrations import MigrationRunner


def test_v1_to_v3_pipeline():
    runner = MigrationRunner()
    old = {"auto_lock": 100, "algorithm": "aes", "schema_version": 1}
    migrated = runner.migrate(old, to_version=3)
    assert migrated["schema_version"] == 3
    assert migrated["security"].get("auto_lock_after") == 100
    assert migrated["encryption"].get("default_algorithm") == "aes"
    assert migrated["sync"].get("enabled") is False


def test_already_latest_no_op():
    runner = MigrationRunner()
    cfg = {"schema_version": 3}
    result = runner.migrate(cfg, to_version=3)
    assert result is cfg


def test_unknown_migration_stops_gracefully():
    runner = MigrationRunner()
    result = runner.migrate({"schema_version": 1}, to_version=5)
    assert result["schema_version"] >= 1
