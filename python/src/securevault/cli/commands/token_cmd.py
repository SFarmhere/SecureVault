"""SecureVault - Команда управления токенами (CLI)."""

from __future__ import annotations

from typing import Any, Dict, List

from securevault.cli.output.table_formatter import TableFormatter


def add_arguments(parser) -> None:
    parser.add_argument("--list", action="store_true", help="Список токенов")
    parser.add_argument("--detect", action="store_true", help="Обнаружение токенов")
    parser.add_argument("--library", help="Путь к PKCS#11 библиотеке")


def run(args: Any) -> Dict[str, Any]:
    from securevault.native.pkcs11 import PKCS11Module

    library = getattr(args, "library", None)
    module = PKCS11Module(library_path=library)

    results: List[dict] = []
    if getattr(args, "list", False) or getattr(args, "detect", False):
        slots = module.list_slots() if hasattr(module, "list_slots") else []
        for slot in slots:
            info = (
                slot.to_dict()
                if hasattr(slot, "to_dict")
                else {"slot_id": getattr(slot, "slot_id", None)}
            )
            results.append(info)

    if results:
        headers = list(results[0].keys()) if results else ["slot_id"]
        table = TableFormatter(
            headers, [[r.get(h, "") for h in headers] for r in results]
        )
        print(table.render())
    else:
        print("No tokens detected.")

    return {"status": "ok", "action": "token", "tokens": results}


__all__ = ["add_arguments", "run"]
