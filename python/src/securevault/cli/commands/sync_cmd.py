"""SecureVault - Команда облачной синхронизации (CLI)."""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def add_arguments(parser) -> None:
    parser.add_argument(
        "--provider",
        default="s3",
        choices=["s3", "dropbox", "google_drive", "mega", "yandex_disk"],
    )
    parser.add_argument("--push", help="Локальный файл для загрузки")
    parser.add_argument("--pull", help="Удалённый ключ для скачивания")
    parser.add_argument("--local-dir", help="Директория для сохранения")
    parser.add_argument("--list", action="store_true", help="Список удалённых файлов")


def run(args: Any) -> Dict[str, Any]:
    from securevault.storage import cloud_storage

    provider_factory = {
        "s3": cloud_storage.S3Storage,
        "dropbox": cloud_storage.DropboxStorage,
        "google_drive": cloud_storage.GoogleDriveStorage,
        "mega": cloud_storage.MegaStorage,
        "yandex_disk": cloud_storage.YandexDiskStorage,
    }
    cls = provider_factory.get(args.provider)
    if cls is None:
        return {"status": "error", "message": f"Unknown provider: {args.provider}"}

    client = cls(credentials={}, bucket=args.local_dir or "")
    result = {"status": "ok", "provider": args.provider}

    if getattr(args, "push", None):
        result["uploaded"] = client.upload(args.push)
    if getattr(args, "pull", None):
        data = client.download(args.pull)
        result["downloaded_exists"] = data is not None
    if getattr(args, "list", False):
        result["files"] = client.list_files() if hasattr(client, "list_files") else []

    return result


__all__ = ["add_arguments", "run"]
