"""SecureVault - Валидация входных данных.

Единые функции проверки строк, перечислений, длин и форматов.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Any, Optional, Sequence

from securevault import constants, exceptions

# Часто используемые регулярные выражения
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def validate_non_empty(value: Any, name: str = "value") -> str:
    """Проверить, что значение — непустая строка."""
    if not isinstance(value, str) or not value.strip():
        raise exceptions.ValidationError(f"{name} must be a non-empty string")
    return value.strip()


def validate_in_range(
    value: int, min_value: int, max_value: int, name: str = "value"
) -> int:
    """Проверить, что целое число находится в диапазоне."""
    if not isinstance(value, int):
        raise exceptions.ValidationError(f"{name} must be an integer")
    if not (min_value <= value <= max_value):
        raise exceptions.ValidationError(
            f"{name} must be in range [{min_value}, {max_value}]"
        )
    return value


def validate_length(
    value: str, min_len: int = 0, max_len: int = 1_000_000, name: str = "value"
) -> str:
    """Проверить длину строки."""
    validate_non_empty(value, name) if min_len else None
    if len(value) < min_len or len(value) > max_len:
        raise exceptions.ValidationError(
            f"{name} length must be in range [{min_len}, {max_len}]"
        )
    return value


def validate_choice(value: Any, allowed: Sequence[Any], name: str = "value") -> Any:
    """Проверить, что значение принадлежит допустимому набору."""
    if value not in allowed:
        allowed_str = ", ".join(str(a) for a in allowed)
        raise exceptions.ValidationError(f"{name} must be one of: {allowed_str}")
    return value


def validate_enum(value: Any, enum_cls: type[Enum], name: str = "value") -> Enum:
    """Проверить/привести значение к члену Enum."""
    try:
        if isinstance(value, enum_cls):
            return value
        return enum_cls(value)
    except (ValueError, TypeError) as e:
        raise exceptions.ValidationError(f"Invalid {name}: {value}") from e


def validate_email(value: str) -> str:
    """Проверить корректность email."""
    value = validate_non_empty(value, "email")
    if not EMAIL_RE.match(value):
        raise exceptions.ValidationError(f"Invalid email: {value}")
    return value


def validate_password(
    value: str,
    min_length: int = constants.MIN_PASSWORD_LENGTH,
    max_length: int = constants.MAX_PASSWORD_LENGTH,
) -> str:
    """Проверить пароль на соответствие требованиям длины."""
    value = validate_non_empty(value, "password")
    if not (min_length <= len(value) <= max_length):
        raise exceptions.ValidationError(
            f"Password length must be in range [{min_length}, {max_length}]"
        )
    return value


def validate_hex(
    value: str, expected_length: Optional[int] = None, name: str = "value"
) -> str:
    """Проверить шестнадцатеричную строку."""
    value = validate_non_empty(value, name)
    if not HEX_RE.match(value):
        raise exceptions.ValidationError(f"{name} must be a hex string")
    if expected_length is not None and len(value) != expected_length:
        raise exceptions.ValidationError(
            f"{name} must be exactly {expected_length} hex chars"
        )
    return value


def validate_protection_level(value: Any) -> str:
    """Проверить уровень защиты."""
    return (
        validate_choice(
            value,
            constants.PROTECTION_LEVELS,
            "protection_level",
        ).value
        if isinstance(value, Enum)
        else validate_choice(
            value, [lv.value for lv in constants.PROTECTION_LEVELS], "protection_level"
        )
    )


__all__ = [
    "validate_non_empty",
    "validate_in_range",
    "validate_length",
    "validate_choice",
    "validate_enum",
    "validate_email",
    "validate_password",
    "validate_hex",
    "validate_protection_level",
]
