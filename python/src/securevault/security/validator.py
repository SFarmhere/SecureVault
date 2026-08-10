"""SecureVault - Валидатор безопасности.

Проверка конфигурации и окружения на соответствие требованиям
безопасности перед выполнением критических операций.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List

logger = logging.getLogger(__name__)


class SecurityValidationError(Exception):
    """Нарушение требований безопасности."""


class SecurityValidator:
    """Проверка условий безопасности перед операциями."""

    def __init__(self):
        self._checks: List[Callable[[], None]] = []
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register(self._check_anti_debug)

    def register(self, check: Callable[[], None]) -> None:
        """Зарегистрировать произвольную проверку."""
        self._checks.append(check)

    def _check_anti_debug(self) -> None:
        try:
            from securevault.security.anti_debug import AntiDebug

            detector = AntiDebug()
            detector.check()
            if detector.is_debugger_detected():
                raise SecurityValidationError("Debugger detected")
        except ImportError:
            pass  # модуль не обязателен

    def validate(self, context: Dict[str, Any] | None = None) -> List[str]:
        """Выполнить все проверки, собрав ошибки.

        Returns:
            Список сообщений о нарушениях (пустой, если всё в порядке).
        """
        errors: List[str] = []
        for check in self._checks:
            try:
                check()
            except SecurityValidationError as e:
                errors.append(str(e))
            except Exception as e:  # noqa: BLE001
                logger.warning(f"Check {check.__name__} raised: {e}")
        return errors

    def assert_valid(self, context: Dict[str, Any] | None = None) -> None:
        """Поднять исключение, если есть нарушения безопасности."""
        errors = self.validate(context)
        if errors:
            raise SecurityValidationError("; ".join(errors))


__all__ = ["SecurityValidator", "SecurityValidationError"]
