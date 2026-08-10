"""SecureVault - Уровень защиты CONTAINER (per-file шифрование).

Адаптер для интерфейса AbstractProtectionLevel: шифрует отдельный файл
ключом контейнера (AES-256-GCM) и помечает принадлежность к контейнеру
в метаданных.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from securevault.native import crypto
from securevault.protection_levels.base import AbstractProtectionLevel


class ContainerProtectionLevel(AbstractProtectionLevel):
    """Уровень CONTAINER - файл в составе зашифрованного контейнера."""

    name = "container"

    def __init__(self, container_id: Optional[str] = None):
        self.container_id = container_id

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        algorithm: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Зашифровать файл ключом контейнера (AES-256-GCM)."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        encrypted = crypto.encrypt_aes_gcm(bytes(plaintext), key)
        container_id = kwargs.get("container_id", self.container_id)
        metadata = {
            "level": self.name,
            "algorithm": "aes-256-gcm",
            "container_id": container_id,
            "encrypted": True,
        }
        return encrypted, metadata

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        algorithm: Optional[str] = None,
        **kwargs: Any,
    ) -> bytes:
        """Расшифровать файл ключом контейнера."""
        return crypto.decrypt_aes_gcm(bytes(ciphertext), key)


__all__ = ["ContainerProtectionLevel"]
