"""SecureVault - Миграция схемы конфигурации v1 -> v2.

Изменения:
- Введён раздел ``security`` вместо разрозненных опций.
- Параметры шифрования перенесены в ``encryption``.
"""

from __future__ import annotations


def migrate_v1_to_v2(config: dict) -> dict:
    """Преобразовать конфигурацию версии 1 в версию 2."""
    result = dict(config)
    result["schema_version"] = 2

    # Плоские ключи v1 -> вложенные
    if "auto_lock" in result or "anti_debug" in result:
        security = result.setdefault("security", {})
        if "auto_lock" in result:
            security["auto_lock_after"] = result.pop("auto_lock")
        if "anti_debug" in result:
            security["anti_debug"] = result.pop("anti_debug")

    # Шифрование
    encryption = result.setdefault("encryption", {})
    for flat_key, nested_key in (
        ("algorithm", "default_algorithm"),
        ("chunk_size", "chunk_size"),
        ("compression", "compression"),
    ):
        if flat_key in result:
            encryption[nested_key] = result.pop(flat_key)

    return result


__all__ = ["migrate_v1_to_v2"]
