"""SecureVault - Команда дешифрования файлов (CLI)."""

from __future__ import annotations

import logging
from typing import Any, Dict

from securevault.core.decryption_service import DecryptionService
from securevault.core.key_manager import KeyManager

logger = logging.getLogger(__name__)


def add_arguments(parser) -> None:
    parser.add_argument("input", help="Путь к зашифрованному файлу")
    parser.add_argument("-o", "--output", help="Путь результата")
    parser.add_argument("--password", help="Пароль")
    parser.add_argument("--password-file", help="Файл с паролем")
    parser.add_argument("--key-id", help="ID существующего ключа")


def run(args: Any) -> Dict[str, Any]:
    key_id = getattr(args, "key_id", None)
    password = getattr(args, "password", None)
    if getattr(args, "password_file", None):
        with open(args.password_file, "r", encoding="utf-8") as f:
            password = f.read().strip()

    if not key_id and password:
        import hashlib

        key_id = f"pwd-{hashlib.sha256(password.encode()).hexdigest()[:8]}"

    km = KeyManager()
    km.initialize()
    if key_id and not km.metadata.get(key_id):
        if password:
            key, _ = km.derive_key_from_password(password)
            km.store_key_securely(key, key_id)

    service = DecryptionService(key_mgr=km)
    result = service.decrypt_file(args.input, args.output, key_id=key_id)
    return {"status": "ok", "action": "decrypt", **result.__dict__}


__all__ = ["add_arguments", "run"]
