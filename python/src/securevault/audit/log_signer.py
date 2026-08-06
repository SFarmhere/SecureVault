"""
SecureVault - Подпись аудит-записей

Обеспечивает криптографическую подпись записей аудита ECDSA P-256.

Использование:
    from securevault.audit.log_signer import LogSigner

    signer = LogSigner()
    signer.initialize()
    signature = signer.sign(entry_data)
    is_valid = signer.verify(entry_data, signature)
"""

import json
import logging
from typing import Optional, Dict, Any

from securevault.native import crypto

logger = logging.getLogger(__name__)


class LogSignerError(Exception):
    """Ошибка подписи аудит-записей."""
    pass


class LogSigner:
    """Подписант аудит-записей (ECDSA P-256)."""

    DEFAULT_CURVE = "p256"

    def __init__(self, private_key: Optional[bytes] = None):
        self._private_key = private_key
        self._public_key: Optional[bytes] = None
        self._initialized = False

    def initialize(self) -> None:
        """Инициализировать ключевую пару."""
        try:
            if self._private_key:
                self._public_key = self._extract_public_key(self._private_key)
            else:
                private_pem, public_pem = crypto.generate_ecdsa_keypair(
                    self.DEFAULT_CURVE
                )
                self._private_key = private_pem
                self._public_key = public_pem
            self._initialized = True
            logger.info("LogSigner initialized")
        except Exception as e:
            logger.error(f"LogSigner initialization failed: {e}")
            raise LogSignerError(f"LogSigner initialization failed: {e}")

    def sign(self, entry: Dict[str, Any]) -> str:
        """Подписать запись аудита."""
        if not self._initialized or not self._private_key:
            raise LogSignerError("LogSigner not initialized")
        try:
            data = self._serialize(entry)
            signature = crypto.sign_ecdsa(data, self._private_key)
            return signature.hex()
        except Exception as e:
            logger.error(f"Signing failed: {e}")
            raise LogSignerError(f"Signing failed: {e}")

    def verify(self, entry: Dict[str, Any], signature: str) -> bool:
        """Проверить подпись записи."""
        if not self._initialized or not self._public_key:
            raise LogSignerError("LogSigner not initialized")
        try:
            data = self._serialize(entry)
            sig_bytes = bytes.fromhex(signature)
            return crypto.verify_ecdsa(data, sig_bytes, self._public_key)
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    def get_public_key(self) -> Optional[bytes]:
        """Получить публичный ключ (PEM)."""
        return self._public_key

    def get_private_key(self) -> Optional[bytes]:
        """Получить приватный ключ (PEM)."""
        return self._private_key

    @staticmethod
    def _serialize(entry: Dict[str, Any]) -> bytes:
        """Сериализовать запись для подписи."""
        data = dict(entry)
        data.pop("signature", None)
        data.pop("status", None)
        return json.dumps(data, sort_keys=True, default=str).encode()

    @staticmethod
    def _extract_public_key(private_key_pem: bytes) -> Optional[bytes]:
        """Извлечь публичный ключ из приватного."""
        try:
            from cryptography.hazmat.primitives import serialization
            private_key = serialization.load_pem_private_key(
                private_key_pem, password=None
            )
            return private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        except Exception:
            return None


__all__ = ["LogSigner", "LogSignerError"]