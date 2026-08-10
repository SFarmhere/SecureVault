"""SecureVault - Миграция схемы конфигурации v2 -> v3.

Изменения:
- Добавлен раздел ``sync`` (облачная синхронизация).
- Раздел ``audit`` расширен параметрами подписи и ретенции.
"""

from __future__ import annotations


def migrate_v2_to_v3(config: dict) -> dict:
    """Преобразовать конфигурацию версии 2 в версию 3."""
    result = dict(config)
    result["schema_version"] = 3

    result.setdefault("sync", {"enabled": False, "providers": []})

    audit = result.setdefault("audit", {})
    audit.setdefault("sign_entries", True)
    audit.setdefault("retention_days", 365)
    audit.setdefault("enabled", True)

    return result


__all__ = ["migrate_v2_to_v3"]
