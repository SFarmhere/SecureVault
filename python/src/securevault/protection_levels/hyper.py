"""SecureVault - Уровень защиты HYPER.

Максимальная защита: двойное шифрование (Double AES). Плайнтекст
шифруется дважды производными ключами, обеспечивая скрытый контейнер
с предварительно зашифрованными файлами.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, Optional, Tuple

from securevault.native import crypto
from securevault.protection_levels.base import AbstractProtectionLevel

# Контексты для деривации двух слоёв ключей (HKDF-подобный подход)
_LAYER_1_CTX = b"securevault-hyper-layer-1"
_LAYER_2_CTX = b"securevault-hyper-layer-2"


class HyperProtectionLevel(AbstractProtectionLevel):
    """Уровень HYPER - двойное шифрование производными ключами."""

    name = "hyper"

    @staticmethod
    def _derive_layer_keys(master: bytes) -> Tuple[bytes, bytes]:
        """Деривировать два независимых ключа из мастер-ключа."""
        k1 = hmac.new(master, _LAYER_1_CTX, hashlib.sha256).digest()
        k2 = hmac.new(master, _LAYER_2_CTX, hashlib.sha256).digest()
        return k1, k2

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        algorithm: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Двойное шифрование: encrypt(key1) -> encrypt(key2)."""
        if not isinstance(plaintext, (bytes, bytearray)):
            raise TypeError("plaintext must be bytes")
        k1, k2 = self._derive_layer_keys(key)
        layer1 = crypto.encrypt_aes_gcm(bytes(plaintext), k1)
        layer2 = crypto.encrypt_aes_gcm(layer1, k2)
        metadata = {
            "level": self.name,
            "algorithm": "aes-256-gcm",
            "layers": 2,
            "encrypted": True,
        }
        return layer2, metadata

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        algorithm: Optional[str] = None,
        **kwargs: Any,
    ) -> bytes:
        """Двойное дешифрование (обратный порядок слоёв)."""
        k1, k2 = self._derive_layer_keys(key)
        layer1 = crypto.decrypt_aes_gcm(bytes(ciphertext), k2)
        return crypto.decrypt_aes_gcm(layer1, k1)


__all__ = ["HyperProtectionLevel"]
