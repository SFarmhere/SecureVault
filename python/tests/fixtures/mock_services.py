"""SecureVault - Мок-сервисы и вспомогательные объекты для тестов."""

from __future__ import annotations

from typing import Any, Dict, Optional


class FakeKeyManager:
    """In-memory заглушка KeyManager без обращения к диску/токену."""

    def __init__(self):
        self._keys: Dict[str, bytes] = {}

    def initialize(self) -> None:
        return None

    def generate_file_key(self, size: int = 32) -> bytes:
        import secrets

        return secrets.token_bytes(size)

    def generate_session_key(self, size: int = 32) -> bytes:
        return self.generate_file_key(size)

    def store_key_securely(self, key: bytes, key_id: str) -> None:
        self._keys[key_id] = key

    def retrieve_key(self, key_id: str) -> bytes:
        if key_id not in self._keys:
            raise KeyError(f"Key not found: {key_id}")
        return self._keys[key_id]

    def derive_key_from_password(self, password: str, salt: Optional[bytes] = None):
        import hashlib

        salt = salt or b"fixed-salt"
        key = hashlib.sha256(salt + password.encode("utf-8")).digest()
        return key, salt

    @property
    def metadata(self) -> Dict[str, Any]:
        return {k: {"key_id": k} for k in self._keys}


class FakeCrypto:
    """Заглушка native.crypto, где каждый алгоритм — реальный крипто (через крypto)."""

    @staticmethod
    def encrypt_aes_gcm(data, key, associated_data=None):
        from securevault.native import crypto

        return crypto.encrypt_aes_gcm(data, key, associated_data)

    @staticmethod
    def decrypt_aes_gcm(ciphertext, key, associated_data=None):
        from securevault.native import crypto

        return crypto.decrypt_aes_gcm(ciphertext, key, associated_data)


__all__ = ["FakeKeyManager", "FakeCrypto"]
