"""SecureVault - Модульные тесты конфигурации."""

from securevault.utils.config import SecureVaultConfig, get_config


def test_defaults():
    cfg = SecureVaultConfig()
    assert cfg.get("app.name") == "SecureVault"
    assert cfg.get("database.backend") == "sqlite"
    assert cfg.get("missing.key") is None


def test_set_get():
    cfg = SecureVaultConfig()
    cfg.set("security.auto_lock_after", 60)
    assert cfg.get("security.auto_lock_after") == 60


def test_json_roundtrip(tmp_path):
    cfg = SecureVaultConfig()
    cfg.set("app.data_dir", str(tmp_path))
    path = tmp_path / "cfg.json"
    cfg.save(str(path))
    loaded = SecureVaultConfig().load(str(path))
    assert loaded.get("app.data_dir") == str(tmp_path)


def test_load_can_be_read_back():
    cfg = SecureVaultConfig(data={"database": {"backend": "postgresql"}})
    assert cfg.get("database.backend") == "postgresql"
    # defaults сохраняются после merge
    assert cfg.get("audit.sign_entries") is True


def test_global_get_config():
    cfg = get_config()
    assert cfg.get("app.name") == "SecureVault"


def test_missing_file_returns_defaults(tmp_path):
    cfg = SecureVaultConfig().load(str(tmp_path / "nope.json"))
    assert cfg.get("app.name") == "SecureVault"
