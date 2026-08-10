"""SecureVault - JSON-форматирование вывода CLI."""

from __future__ import annotations

import json
from typing import Any


class JsonFormatter:
    """Сериализация результатов команд в JSON."""

    def __init__(self, pretty: bool = True, ensure_ascii: bool = False):
        self.pretty = pretty
        self.ensure_ascii = ensure_ascii

    def format(self, data: Any) -> str:
        """Преобразовать объект в JSON-строку."""
        kwargs = {"ensure_ascii": self.ensure_ascii}
        if self.pretty:
            kwargs["indent"] = 2
        return json.dumps(data, default=str, **kwargs)


def to_json(data: Any, pretty: bool = True) -> str:
    """Удобная функция быстрой сериализации."""
    return JsonFormatter(pretty=pretty).format(data)


__all__ = ["JsonFormatter", "to_json"]
