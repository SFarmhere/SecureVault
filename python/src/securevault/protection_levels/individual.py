"""SecureVault - Уровень защиты INDIVIDUAL.

Каждый файл шифруется отдельным ключом с помощью AES-256-GCM.
Формат результата: ``nonce + ciphertext + tag`` (как у native.crypto).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from securevault.native import crypto
from securevault.protection_levels.base import AbstractProtectionLevel


class IndividualProtectionLevel(AbstractProtectionLevel):
    """Уровень INDIVIDUAL - индивидуальное шифрование файла."""

    name = "individual"

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        algorithm: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Зашифровать AES-256-GCM.

        Args:
            plaintext: Открытые данные.
            key: Ключ (16/24/32 байта).
            algorithm: Игнорируется (всегда GCM).

        Returns:
            Кортеж (ciphertext, metadata).
        """
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        encrypted = crypto.encrypt_aes_gcm(bytes(plaintext), key)
        metadata = {
            "level": self.name,
            "algorithm": "aes-256-gcm",
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
        """Расшифровать AES-256-GCM."""
        return crypto.decrypt_aes_gcm(bytes(ciphertext), key)


__all__ = ["IndividualProtectionLevel"]
