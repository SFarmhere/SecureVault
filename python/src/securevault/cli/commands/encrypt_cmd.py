"""SecureVault - Команда шифрования файлов (CLI)."""

from __future__ import annotations

import logging
from typing import Any, Dict

from securevault.core.encryption_service import EncryptionService
from securevault.core.key_manager import KeyManager
from securevault.utils import security_utils

logger = logging.getLogger(__name__)


def add_arguments(parser) -> None:
    """Добавить аргументы подкоманды encrypt."""
    parser.add_argument("input", help="Путь к файлу")
    parser.add_argument("-o", "--output", help="Путь результата (.enc)")
    parser.add_argument(
        "-p",
        "--protection",
        default="individual",
        choices=["original", "individual", "container", "hyper"],
        help="Уровень защиты",
    )
    parser.add_argument("--password", help="Пароль (безопаснее через --password-file)")
    parser.add_argument("--password-file", help="Файл с паролем")
    parser.add_argument("--chunk-size", type=int, default=65536, help="Размер чанка")


def run(args: Any) -> Dict[str, Any]:
    """Выполнить команду шифрования."""
    password = _read_password(args)
    if password and not security_utils.is_strong_password(password):
        logger.warning("Password is weak; consider a stronger password")

    km = KeyManager()
    km.initialize()
    key_id: str | None = None
    if password:
        key, _ = km.derive_key_from_password(password)
        key_id = (
            f"pwd-{__import__('hashlib').sha256(password.encode()).hexdigest()[:8]}"
        )
        km.store_key_securely(key, key_id)

    service = EncryptionService(key_mgr=km)
    from securevault.core.encryption_service import ProtectionLevel

    metadata = service.encrypt_file(
        args.input,
        args.output,
        key_id=key_id,
        protection_level=ProtectionLevel(args.protection),
    )
    return {"status": "ok", "action": "encrypt", **metadata.to_dict()}


def _read_password(args) -> str | None:
    if getattr(args, "password", None):
        return args.password
    if getattr(args, "password_file", None):
        with open(args.password_file, "r", encoding="utf-8") as f:
            return f.read().strip()
    return None


__all__ = ["add_arguments", "run"]
