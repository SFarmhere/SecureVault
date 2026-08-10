"""SecureVault - Фабрика уровней защиты.

Сопоставляет идентификатор уровня защиты (enum или строку) с его
реализацией, инкапсулируя логику создания объектов.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Type

from securevault.protection_levels.base import AbstractProtectionLevel
from securevault.protection_levels.container import ContainerProtectionLevel
from securevault.protection_levels.hyper import HyperProtectionLevel
from securevault.protection_levels.individual import IndividualProtectionLevel
from securevault.protection_levels.original import OriginalProtectionLevel


class ProtectionLevelFactory:
    """Фабрика, возвращающая реализацию уровня защиты по идентификатору."""

    _registry: Dict[str, Type[AbstractProtectionLevel]] = {
        "original": OriginalProtectionLevel,
        "individual": IndividualProtectionLevel,
        "container": ContainerProtectionLevel,
        "hyper": HyperProtectionLevel,
    }

    def __init__(
        self, registry: Dict[str, Type[AbstractProtectionLevel]] | None = None
    ):
        if registry is not None:
            self._registry = dict(registry)

    def register(
        self, level: str, implementation: Type[AbstractProtectionLevel]
    ) -> None:
        """Зарегистрировать реализацию уровня защиты."""
        self._registry[level] = implementation

    @staticmethod
    def _resolve_key(level: object) -> str:
        """Привести уровень к строковому ключу реестра."""
        if isinstance(level, Enum):
            return str(level.value)
        return str(level)

    def create_protection(self, level: object) -> AbstractProtectionLevel:
        """Создать экземпляр реализации уровня защиты.

        Args:
            level: Член Enum или строка (ключ уровня).

        Returns:
            Экземпляр AbstractProtectionLevel.

        Raises:
            ValueError: Если уровень неизвестен.
        """
        key = self._resolve_key(level)
        cls = self._registry.get(key)
        if cls is None:
            raise ValueError(f"Unknown protection level: {level!r}")
        return cls()

    # Алиас для единообразия API
    create = create_protection

    def list_levels(self) -> list:
        """Список зарегистрированных уровней защиты."""
        return sorted(self._registry.keys())


__all__ = ["ProtectionLevelFactory"]
