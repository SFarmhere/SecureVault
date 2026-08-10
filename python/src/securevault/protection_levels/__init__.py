"""SecureVault - Уровни защиты данных.

Реализация 4-уровневой модели безопасности:
- ORIGINAL: без шифрования (публичные данные)
- INDIVIDUAL: каждый файл зашифрован отдельным ключом (AES-256-GCM)
- CONTAINER: контейнер с файлами, шифруемый ключом контейнера
- HYPER: двойное шифрование (Double AES), скрытые контейнеры
"""

from enum import Enum


class ProtectionLevel(Enum):
    """Идентификаторы уровней защиты."""

    ORIGINAL = "original"
    INDIVIDUAL = "individual"
    CONTAINER = "container"
    HYPER = "hyper"


from securevault.protection_levels.base import AbstractProtectionLevel  # noqa: E402
from securevault.protection_levels.factory import ProtectionLevelFactory  # noqa: E402

__all__ = [
    "ProtectionLevel",
    "AbstractProtectionLevel",
    "ProtectionLevelFactory",
]
