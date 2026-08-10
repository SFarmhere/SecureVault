"""SecureVault - Восстановление доступа через CLI.

Оркестрация процессов экстренного и социального восстановления.
"""

from __future__ import annotations

import getpass
import logging
from typing import List, Optional

from securevault.security.recovery.emergency_recovery import EmergencyRecovery
from securevault.security.recovery.social_recovery import SocialRecovery

logger = logging.getLogger(__name__)


class CliRecovery:
    """Интерактивные сценарии восстановления для CLI."""

    def __init__(self, force_noninteractive: bool = True):
        self.force_noninteractive = force_noninteractive

    # ------------------------------------------------------------------
    # Экстренное восстановление
    # ------------------------------------------------------------------
    def issue_codes(self, count: int = 3) -> List[str]:
        """Выдать экстренные коды и показать их."""
        return EmergencyRecovery().issue_codes(count)

    def redeem_code(self, code: str) -> bool:
        """Проверить экстренный код."""
        return EmergencyRecovery().redeem(code)

    # ------------------------------------------------------------------
    # Социальное восстановление
    # ------------------------------------------------------------------
    def run_social_recovery(
        self, initial_shares: List[bytes], threshold: Optional[int] = None
    ) -> bytes:
        """Собрать секрет из предоставленных долей."""
        recovery = SocialRecovery()
        for i, share in enumerate(initial_shares):
            recovery.provide_share(f"source-{i}", share)
        return recovery.combine(threshold)

    # ------------------------------------------------------------------
    # Полный запрос паролей (интерактив)
    # ------------------------------------------------------------------
    def prompt_master_password(self, confirm: bool = True) -> str:
        """Запросить мастер-пароль (подавляется в неинтерактивном режиме)."""
        if self.force_noninteractive:
            raise RuntimeError(
                "Interactive prompt disabled " "(set force_noninteractive=False)"
            )
        password = getpass.getpass("Введите мастер-пароль: ")
        if confirm:
            again = getpass.getpass("Повторите мастер-пароль: ")
            if password != again:
                raise ValueError("Passwords do not match")
        return password


__all__ = ["CliRecovery"]
