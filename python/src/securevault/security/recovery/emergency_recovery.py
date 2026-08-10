"""SecureVault - Экстренное восстановление доступа.

Однократные коды экстренного восстановления (override/breakglass),
хранящиеся в виде хешей, плюс восстановление мастер-секрета по
Shamir-долям (n-of-m).
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)


class EmergencyRecoveryError(Exception):
    """Ошибка экстренного восстановления."""


class EmergencyRecovery:
    """Выдача и применение кодов экстренного восстановления."""

    def __init__(self):
        self._stored_hashes: Dict[str, dict] = {}

    # ------------------------------------------------------------------
    # Коды экстренного доступа
    # ------------------------------------------------------------------
    def issue_codes(self, count: int = 3, expiry_seconds: int = 3600) -> List[str]:
        """Сгенерировать однократные коды доступа.

        Returns:
            Список кодов (пользователю отдаются только один раз).
        """
        codes = [secrets.token_hex(6) for _ in range(max(1, count))]
        for code in codes:
            self._stored_hashes[self._hash(code)] = {
                "expires_at": datetime.utcnow().timestamp() + expiry_seconds,
                "used": False,
            }
        logger.info(f"Issued {len(codes)} emergency codes")
        return codes

    def redeem(self, code: str) -> bool:
        """Использовать код. Возвращает True при успехе."""
        digest = self._hash(code)
        record = self._stored_hashes.get(digest)
        if record is None:
            return False
        if record.get("used"):
            return False
        if record.get("expires_at", 0) < datetime.utcnow().timestamp():
            del self._stored_hashes[digest]
            return False
        record["used"] = True
        logger.warning("Emergency code redeemed")
        return True

    @staticmethod
    def _hash(code: str) -> str:
        return hashlib.sha256(code.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Восстановление мастер-секрета (Shamir)
    # ------------------------------------------------------------------
    def split_secret(
        self, secret: bytes, total: int = 5, threshold: int = 3
    ) -> List[bytes]:
        """Разделить секрет на n-of-m Shamir-долей."""
        from securevault.security.shamir import split_secret as _split

        return _split(secret, total=total, threshold=threshold)

    def combine_secret(self, shares: List[bytes], threshold: int = 3) -> bytes:
        """Восстановить секрет из долей."""
        from securevault.security.shamir import join_shares

        if len(shares) < threshold:
            raise EmergencyRecoveryError(
                f"Need at least {threshold} shares, got {len(shares)}"
            )
        return join_shares(shares[:threshold])


__all__ = ["EmergencyRecovery", "EmergencyRecoveryError"]
