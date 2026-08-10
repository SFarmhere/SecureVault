"""SecureVault - Работа со временем и временными метками.

Единые helpers для UTC-времени, ISO-строк и временных меток аудита.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Дефолтный формат ISO-строк времени аудита
ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
SIMPLE_FORMAT = "%Y-%m-%d %H:%M:%S"


def utcnow() -> datetime:
    """Текущее время в UTC (timezone-aware)."""
    return datetime.now(timezone.utc)


def utctimestamp() -> float:
    """Текущая Unix-метка времени (float)."""
    return utcnow().timestamp()


def iso_now() -> str:
    """Текущее UTC-время в ISO-формате."""
    return utcnow().strftime(ISO_FORMAT)


def simple_now() -> str:
    """Текущее UTC-время в человекочитаемом формате."""
    return utcnow().strftime(SIMPLE_FORMAT)


def to_iso(dt: datetime | None = None) -> str:
    """Преобразовать datetime (или текущее) в ISO-строку с 'Z'."""
    if dt is None:
        dt = utcnow()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime(ISO_FORMAT)


def from_iso(value: str) -> datetime:
    """Разобрать ISO-строку в datetime (UTC)."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def is_expired(timestamp: str, max_age_seconds: int) -> bool:
    """Проверить, что ISO-метка старше указанного периода."""
    try:
        dt = from_iso(timestamp)
        age = (utcnow() - dt).total_seconds()
        return age > max_age_seconds
    except (ValueError, TypeError):
        return True


def age_seconds(timestamp: str) -> float:
    """Возраст ISO-метки в секундах (0 для невалидных)."""
    try:
        return max(0.0, (utcnow() - from_iso(timestamp)).total_seconds())
    except (ValueError, TypeError):
        return 0.0


__all__ = [
    "utcnow",
    "utctimestamp",
    "iso_now",
    "simple_now",
    "to_iso",
    "from_iso",
    "is_expired",
    "age_seconds",
    "ISO_FORMAT",
    "SIMPLE_FORMAT",
]
