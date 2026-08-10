"""SecureVault - Сервис дешифрования.

Высокоуровневый фасад дешифрования, дополняющий EncryptionService:
- Дешифрование файлов и данных в памяти
- Извлечение и проверка метаданных
- Быстрые функции для автоматических конвейеров
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from securevault import exceptions
from securevault.core.encryption_service import EncryptionService
from securevault.core.key_manager import KeyManager

logger = logging.getLogger(__name__)


@dataclass
class DecryptionResult:
    """Результат дешифрования файла."""

    plaintext_path: str
    original_size: int
    protection_level: str
    algorithm: str
    key_id: str


class DecryptionService:
    """Фасад операций дешифрования."""

    def __init__(
        self,
        key_mgr: Optional[KeyManager] = None,
        encryption_service: Optional[EncryptionService] = None,
    ):
        self.key_mgr = key_mgr or KeyManager()
        self.encryption = encryption_service or EncryptionService(key_mgr=self.key_mgr)

    # ------------------------------------------------------------------
    # Файлы
    # ------------------------------------------------------------------
    def decrypt_file(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        key_id: Optional[str] = None,
    ) -> DecryptionResult:
        """Дешифровать файл.

        Args:
            input_path: Путь к зашифрованному файлу.
            output_path: Путь для результата (None - убрать .enc).
            key_id: ID ключа (если None, берётся из метаданных).

        Returns:
            DecryptionResult с метаданными дешифрования.
        """
        metadata = self.encryption.decrypt_file(input_path, output_path, key_id)
        resolved = Path(output_path) if output_path else None
        if resolved is None:
            src = Path(input_path)
            resolved = src if not str(src).endswith(".enc") else Path(str(src)[:-4])
        return DecryptionResult(
            plaintext_path=str(resolved),
            original_size=metadata.original_size,
            protection_level=metadata.protection_level.value,
            algorithm=metadata.algorithm.value,
            key_id=metadata.key_id,
        )

    def decrypt_data(
        self,
        encrypted_data: bytes,
        key_id: Optional[str] = None,
        key: Optional[bytes] = None,
    ) -> bytes:
        """Дешифровать данные в памяти.

        Args:
            encrypted_data: Зашифрованные данные.
            key_id: ID сохранённого ключа (если key не передан).
            key: Непосредственный ключ (приоритетнее key_id).

        Returns:
            Открытый текст.
        """
        if key is None and key_id is not None:
            key = self.key_mgr.retrieve_key(key_id)
        return self.encryption.decrypt_data(encrypted_data, key=key)

    def decrypt_stream(
        self,
        input_path: str,
        output_path: str,
        key_id: Optional[str] = None,
        chunk_size: int = 65536,
    ) -> DecryptionResult:
        """Потоковое дешифрование большого файла."""
        return self.decrypt_file(input_path, output_path, key_id)

    # ------------------------------------------------------------------
    # Метаданные
    # ------------------------------------------------------------------
    def get_metadata(self, input_path: str) -> Optional[Dict[str, Any]]:
        """Получить метаданные зашифрованного файла без дешифрования."""
        from securevault.core.encryption_service import get_encryption_info

        info = get_encryption_info(input_path)
        return info

    def verify_integrity(self, input_path: str, key_id: Optional[str] = None) -> bool:
        """Проверить целостность файла (попытка дешифрования)."""
        try:
            self.encryption.decrypt_file(input_path, key_id=key_id)
            return True
        except (exceptions.IntegrityError, exceptions.DecryptionError) as e:
            logger.warning(f"Integrity verification failed for {input_path}: {e}")
            return False


# ------------------------------------------------------------------------
# Быстрые функции
# ------------------------------------------------------------------------
def quick_decrypt_file(
    input_path: str,
    output_path: Optional[str] = None,
    password: Optional[str] = None,
) -> DecryptionResult:
    """Быстрое дешифрование файла (пароль или существующий ключ)."""
    import hashlib

    km = KeyManager()
    km.initialize()
    key_id = None
    if password:
        key_id = f"pwd-{hashlib.sha256(password.encode()).hexdigest()[:8]}"
        key, salt = km.derive_key_from_password(password)
        km.store_key_securely(key, key_id)
    return DecryptionService(key_mgr=km).decrypt_file(input_path, output_path, key_id)


def quick_decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    """Быстрое дешифрование данных по паролю."""
    import hashlib

    km = KeyManager()
    km.initialize()
    key, _ = km.derive_key_from_password(password)
    key_id = f"pwd-{hashlib.sha256(password.encode()).hexdigest()[:8]}"
    km.store_key_securely(key, key_id)
    service = DecryptionService(key_mgr=km)
    return service.decrypt_data(encrypted_data, key=key)


__all__ = [
    "DecryptionService",
    "DecryptionResult",
    "quick_decrypt_file",
    "quick_decrypt_data",
]
