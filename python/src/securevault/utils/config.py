"""SecureVault - Управление конфигурацией.

Нагрузка, сохранение и доступ к конфигурации приложения (JSON/YAML).
Использование:
    from securevault.utils.config import get_config
    cfg = get_config()
    db_cfg = cfg.get("database", {})
"""

from __future__ import annotations

import json
import logging
import threading
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, Optional

from securevault import constants

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: Dict[str, Any] = {
    "app": {"name": "SecureVault", "version": "0.1.0", "data_dir": None},
    "database": {
        "backend": "sqlite",
        "path": None,
        "host": "localhost",
        "port": 5432,
        "dbname": "securevault",
        "user": "postgres",
        "password": "",
    },
    "audit": {
        "enabled": True,
        "backend": "sqlite",
        "retention_days": constants.AUDIT_RETENTION_DAYS,
        "sign_entries": True,
        "batch_size": constants.AUDIT_BATCH_SIZE,
    },
    "encryption": {
        "default_algorithm": "aes-256-gcm",
        "default_integrity": "hmac-sha256",
        "chunk_size": constants.DEFAULT_CHUNK_SIZE,
        "compression": False,
        "deduplication": False,
    },
    "security": {"anti_debug": True, "integrity_check": True, "auto_lock_after": 0},
    "storage": {"backend": "local", "base_dir": None},
    "sync": {"enabled": False, "providers": []},
}


class SecureVaultConfig:
    """Обёртка над словарём конфигурации."""

    def __init__(
        self, data: Optional[Dict[str, Any]] = None, path: Optional[str] = None
    ):
        self._path = Path(path) if path else None
        self._data = deepcopy(DEFAULT_CONFIG)
        if data:
            self._merge(self._data, deepcopy(data))

    def get(self, key: str, default: Any = None) -> Any:
        """Получить значение по точечному ключу ('database.host')."""
        node: Any = self._data
        for part in key.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def __getitem__(self, key: str) -> Any:
        value = self.get(key)
        if value is None:
            raise KeyError(f"Config key not found: {key}")
        return value

    def set(self, key: str, value: Any) -> None:
        """Установить значение по точечному ключу."""
        parts = key.split(".")
        node = self._data
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def as_dict(self) -> Dict[str, Any]:
        return deepcopy(self._data)

    @property
    def data_dir(self) -> Path:
        path = self.get("app.data_dir")
        if path:
            return Path(path).expanduser()
        return Path.home() / constants.SECUREVAULT_DIR_NAME

    @property
    def config_path(self) -> Path:
        if self._path:
            return self._path
        return self.data_dir / constants.CONFIG_DIR / constants.CONFIG_FILE

    def _merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                self._merge(base[k], v)
            else:
                base[k] = v

    def load(self, path: Optional[str] = None) -> "SecureVaultConfig":
        p = Path(path) if path else self.config_path
        if not p.exists():
            logger.debug(f"Config file not found, using defaults: {p}")
            return self
        try:
            suffix = p.suffix.lower()
            if suffix == ".json":
                data = json.loads(p.read_text(encoding="utf-8"))
            elif suffix in (".yaml", ".yml"):
                import yaml

                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            else:
                logger.warning(f"Unsupported config format: {suffix}")
                return self
            if isinstance(data, dict):
                self._merge(self._data, data)
            self._path = p
            logger.info(f"Config loaded from {p}")
        except Exception as e:
            logger.error(f"Failed to load config {p}: {e}")
        return self

    def save(self, path: Optional[str] = None) -> None:
        p = Path(path) if path else self.config_path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(self._data, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info(f"Config saved to {p}")


_default: Optional[SecureVaultConfig] = None
_lock = threading.Lock()


def load_config(path: Optional[str] = None) -> SecureVaultConfig:
    """Загрузить конфигурацию и сделать её глобальной."""
    global _default
    cfg = SecureVaultConfig(path=path)
    cfg.load(path)
    with _lock:
        _default = cfg
    return cfg


def get_config() -> SecureVaultConfig:
    """Вернуть глобальную конфигурацию, при необходимости загрузив её."""
    global _default
    with _lock:
        if _default is None:
            _default = SecureVaultConfig()
            _default.load()
        return _default


def reset_config() -> None:
    """Сбросить глобальную конфигурацию (для тестов)."""
    global _default
    with _lock:
        _default = None


__all__ = [
    "SecureVaultConfig",
    "load_config",
    "get_config",
    "reset_config",
    "DEFAULT_CONFIG",
]
