"""SecureVault - Команда просмотра файлов/контейнеров (CLI)."""

from __future__ import annotations

from typing import Any, Dict, List

from securevault.cli.output.table_formatter import TableFormatter


def add_arguments(parser) -> None:
    parser.add_argument("-d", "--dir", help="Директория для сканирования")
    parser.add_argument(
        "--encrypted-only",
        action="store_true",
        help="Показывать только зашифрованные файлы",
    )


def run(args: Any) -> Dict[str, Any]:
    import os

    from securevault.core.encryption_service import is_encrypted_file

    target = getattr(args, "dir", None) or "."
    found: List[dict] = []
    for root, _dirs, files in os.walk(target):
        for name in files:
            path = os.path.join(root, name)
            enc = is_encrypted_file(path)
            if getattr(args, "encrypted_only", False) and not enc:
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                size = 0
            found.append(
                {
                    "path": path,
                    "size": size,
                    "encrypted": enc,
                    "level": _level_of(path) if enc else "plain",
                }
            )

    if found:
        headers = ["Path", "Size", "Protection", "Encrypted"]
        table = TableFormatter(
            headers,
            [
                [f["path"], f["size"], f["level"], "yes" if f["encrypted"] else "no"]
                for f in found
            ],
        )
        print(table.render())
    else:
        print("No files found.")

    return {"status": "ok", "action": "list", "count": len(found), "files": found}


def _level_of(path: str) -> str:
    from securevault.core.encryption_service import get_encryption_info

    info = get_encryption_info(path)
    return info.get("protection_level", "unknown") if info else "unknown"


__all__ = ["add_arguments", "run"]
