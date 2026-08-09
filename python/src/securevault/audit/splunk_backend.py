"""SecureVault - Splunk бэкенд для аудит-записей.

Обеспечивает интеграцию с Splunk HEC (HTTP Event Collector).
"""

import json
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class SplunkBackendError(Exception):
    """Ошибка Splunk бэкенда."""


class SplunkBackend:
    """Бэкенд хранения аудит-записей в Splunk."""

    def __init__(
        self,
        host: str = "localhost",
        token: str = "",
        index: str = "securevault",
        port: int = 8088,
        scheme: str = "https",
    ):
        self.host = host
        self.token = token
        self.index = index
        self.port = port
        self.scheme = scheme
        self._initialized = False

    def initialize(self) -> None:
        """Инициализировать подключение к Splunk."""
        if not self.token:
            raise SplunkBackendError("Splunk HEC token is required")
        try:
            import requests

            self._requests = requests
            self._initialized = True
            logger.info(f"Splunk backend initialized: {self.host}:{self.port}")
        except ImportError:
            raise SplunkBackendError(
                "requests not installed. Install with: pip install requests"
            )

    def write(self, entry: Dict[str, Any]) -> None:
        """Записать запись в Splunk."""
        if not self._initialized:
            self.initialize()

        payload = {
            "event": entry,
            "index": self.index,
            "sourcetype": "securevault:audit",
            "source": entry.get("source", "securevault-core"),
        }

        url = f"{self.scheme}://{self.host}:{self.port}/services/collector"
        headers = {
            "Authorization": f"Splunk {self.token}",
            "Content-Type": "application/json",
        }

        try:
            resp = self._requests.post(url, headers=headers, data=json.dumps(payload))
            resp.raise_for_status()
        except Exception as e:
            raise SplunkBackendError(f"Splunk write failed: {e}")

    def close(self) -> None:
        """Закрыть подключение."""
        self._initialized = False


__all__ = ["SplunkBackend", "SplunkBackendError"]
