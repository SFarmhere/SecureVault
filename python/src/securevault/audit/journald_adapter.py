"""SecureVault - Journald адаптер для аудит-записей.

Обеспечивает интеграцию с systemd-journald для логирования
аудит-записей на Linux системах.
"""

import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class JournaldAdapterError(Exception):
    """Ошибка Journald адаптера."""
    pass


class JournaldAdapter:
    """Адаптер для записи аудит-записей в systemd-journald."""

    def __init__(self, facility: str = "securevault"):
        self.facility = facility
        self._client = None
        self._initialized = False

    def initialize(self) -> None:
        """Инициализировать подключение к journald."""
        try:
            import systemd.journal as journal
            self._client = journal
            self._initialized = True
            logger.info("Journald adapter initialized")
        except ImportError:
            self._initialized = False
            logger.warning(
                "systemd not available. Install with: pip install systemd"
            )

    def write(self, entry: Dict[str, Any]) -> None:
        """Записать запись в journald."""
        if not self._initialized:
            self.initialize()
        if not self._initialized:
            return

        self._client.send(
            entry.get("action", "audit"),
            PRIORITY=self._severity_to_priority(entry.get("severity", "info")),
            SYSLOG_IDENTIFIER=self.facility,
            USER_ID=entry.get("user_id", ""),
            RESULT=entry.get("result", ""),
            ENTRY_ID=entry.get("entry_id", ""),
            MESSAGE=f"Audit: {entry.get('user_id', '')} -> {entry.get('action', '')}",
        )

    def close(self) -> None:
        """Закрыть адаптер."""
        self._initialized = False

    @staticmethod
    def _severity_to_priority(severity: str) -> str:
        """Преобразовать severity в journald priority."""
        priorities = {
            "debug": "7",
            "info": "6",
            "warning": "4",
            "error": "3",
            "critical": "2",
        }
        return priorities.get(severity, "6")


__all__ = ["JournaldAdapter", "JournaldAdapterError"]