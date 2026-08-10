"""SecureVault - Уровень защиты ORIGINAL.

Данные хранятся без шифрования (публичная информация).
Обеспечивает обратную совместимость и быстрый доступ.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from securevault.protection_levels.base import AbstractProtectionLevel


class OriginalProtectionLevel(AbstractProtectionLevel):
    """Уровень ORIGINAL - без криптографической трансформации."""

    name = "original"

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        algorithm: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Вернуть данные без изменений."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        metadata = {
            "level": self.name,
            "encrypted": False,
            "algorithm": None,
        }
        return bytes(plaintext), metadata

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        algorithm: Optional[str] = None,
        **kwargs: Any,
    ) -> bytes:
        """Вернуть данные без изменений."""
        return bytes(ciphertext)


__all__ = ["OriginalProtectionLevel"]
