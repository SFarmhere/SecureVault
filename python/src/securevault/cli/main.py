"""SecureVault - Главная точка входа CLI.

Использование:
    securevault encrypt file.txt -o file.enc --protection individual
    securevault decrypt file.enc -o file.txt
    securevault list -d .
    securevault config --show
    securevault tokens --list
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any, Dict, Optional

from securevault import __version__
from securevault.cli.output import json_formatter
from securevault.utils.logging import setup_logging

# Реестр подкоманд
_COMMANDS: Dict[str, Any] = {}


def _register(name: str) -> Any:
    import importlib

    mod = importlib.import_module(f"securevault.cli.commands.{name}_cmd")
    _COMMANDS[name] = mod
    return mod


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="securevault",
        description="SecureVault - многоуровневая система криптографической защиты файлов.",
    )
    parser.add_argument(
        "--version", action="version", version=f"securevault {__version__}"
    )
    parser.add_argument("--verbose", action="store_true", help="Детальный вывод")
    parser.add_argument(
        "--format", choices=["text", "json"], default="text", help="Формат вывода"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in ("encrypt", "decrypt", "list", "token", "config", "sync"):
        mod = _register(name)
        sp = subparsers.add_parser(name, help=mod.run.__doc__)
        mod.add_arguments(sp)

    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    level = logging.DEBUG if getattr(args, "verbose", False) else logging.INFO
    setup_logging(level=level)

    try:
        mod = _COMMANDS[args.command]
        result = mod.run(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except Exception as e:  # noqa: BLE001
        logger = logging.getLogger(__name__)
        logger.error(f"Command '{args.command}' failed: {e}")
        if getattr(args, "verbose", False):
            raise
        return 1

    if getattr(args, "format", "text") == "json":
        print(json_formatter.to_json(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
