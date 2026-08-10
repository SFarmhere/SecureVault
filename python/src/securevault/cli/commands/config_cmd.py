"""SecureVault - Команда управления конфигурацией (CLI)."""

from __future__ import annotations

from typing import Any, Dict

from securevault.cli.output.json_formatter import to_json


def add_arguments(parser) -> None:
    parser.add_argument("--get", help="Ключ для чтения (например, database.host)")
    parser.add_argument(
        "--set", nargs=2, metavar=("KEY", "VALUE"), help="Установить значение"
    )
    parser.add_argument("--path", help="Путь к файлу конфигурации")
    parser.add_argument("--show", action="store_true", help="Показать всю конфигурацию")


def run(args: Any) -> Dict[str, Any]:
    from securevault.utils.config import load_config, reset_config

    reset_config()
    cfg = load_config(getattr(args, "path", None))

    if getattr(args, "set", None):
        key, value = args.set
        cfg.set(key, _coerce(value))
        cfg.save(getattr(args, "path", None))

    if getattr(args, "get", None):
        return {"status": "ok", "key": args.get, "value": cfg.get(args.get)}

    if getattr(args, "show", False) or not (
        getattr(args, "set", None) or getattr(args, "get", None)
    ):
        print(to_json(cfg.as_dict()))
        return {"status": "ok", "config": cfg.as_dict()}

    return {"status": "ok"}


def _coerce(value: str):
    lowered = value.lower()
    if lowered in ("true", "false"):
        return lowered == "true"
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


__all__ = ["add_arguments", "run"]
