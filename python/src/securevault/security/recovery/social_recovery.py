"""SecureVault - Социальное восстановление.

Распределение ключа среди доверенных лиц (guardians) по схеме
Shamir Secret Sharing: для восстановления достаточно threshold долей.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SocialRecoveryError(Exception):
    """Ошибка социального восстановления."""


class SocialRecovery:
    """Раздача и сбор долей ключа через доверенных лиц."""

    def __init__(self):
        from securevault.security.shamir import split_secret as _split

        self._split = _split
        self._shares: Dict[str, bytes] = {}

    def split(
        self, secret: bytes, guardians: List[str], threshold: Optional[int] = None
    ) -> Dict[str, bytes]:
        """Разделить секрет между guardians.

        Args:
            secret: Секрет для распределения.
            guardians: Идентификаторы доверенных лиц.
            threshold: Минимальное число долей для восстановления.

        Returns:
            Словарь {guardian_id: share_bytes}.
        """
        if not guardians:
            raise SocialRecoveryError("At least one guardian required")
        if threshold is None:
            threshold = max(2, len(guardians) // 2 + 1)
        if threshold > len(guardians):
            raise SocialRecoveryError(
                f"Threshold {threshold} exceeds guardian count {len(guardians)}"
            )
        shares = self._split(secret, total=len(guardians), threshold=threshold)
        self._shares = dict(zip(guardians, shares))
        logger.info(f"Secret split among {len(guardians)} guardians (t={threshold})")
        return dict(self._shares)

    def provide_share(self, guardian_id: str, share: bytes) -> None:
        """Получить долю от доверенного лица."""
        self._shares[guardian_id] = share

    def available_sources(self) -> List[str]:
        return list(self._shares.keys())

    def combine(self, threshold: Optional[int] = None) -> bytes:
        """Собрать секрет из собранных долей."""
        from securevault.security.shamir import join_shares

        if threshold is None:
            threshold = max(2, len(self._shares) // 2 + 1)
        shares = list(self._shares.values())
        if len(shares) < threshold:
            raise SocialRecoveryError(
                f"Need at least {threshold} shares, have {len(shares)}"
            )
        return join_shares(shares[:threshold])

    def reset(self) -> None:
        self._shares.clear()


__all__ = ["SocialRecovery", "SocialRecoveryError"]
