"""SecureVault - Технология AMD SEV/SEV-SNP.

Программная модель создания и проверки отчётов аттестации SEV.
Реальное оборудование подключается аппаратным модулем.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class SevError(Exception):
    """Ошибка SEV-аттестации."""


class SevAttestation:
    """Формирование и проверка отчётов аттестации SEV."""

    def __init__(self, measurement_key: Optional[bytes] = None):
        self._measurement_key = measurement_key or secrets.token_bytes(32)

    # ------------------------------------------------------------------
    # Измерения
    # ------------------------------------------------------------------
    def measure(self, payload: bytes, launch_measurement: bytes) -> bytes:
        """Вычислить измерение гостевой среды (H(launch || payload))."""
        return hashlib.sha256(launch_measurement + payload).digest()

    def attestation_report(
        self, measurement: bytes, platform: str = "sev"
    ) -> Dict[str, Any]:
        """Создать отчёт аттестации с подписью."""
        report = {
            "algorithm": "sev-attestation",
            "platform": platform,
            "measurement": measurement.hex(),
            "nonce": secrets.token_hex(16),
        }
        signed = self.sign(report)
        return {"report": report, "signature": signed.hex()}

    def sign(self, report: Dict[str, Any]) -> bytes:
        """Подписать отчёт HMAC-SHA256."""
        data = _canonical(report).encode("utf-8")
        return hmac.new(self._measurement_key, data, hashlib.sha256).digest()

    def verify(self, report: Dict[str, Any], signature: bytes) -> bool:
        """Проверить подпись отчёта."""
        expected = self.sign(report)
        return hmac.compare_digest(expected, signature)

    def verify_measurement(
        self, report: Dict[str, Any], signature: bytes, expected_measurement: bytes
    ) -> bool:
        """Проверить подпись и совпадение измерения ожидаемому."""
        ok = self.verify(report, signature)
        if not ok:
            return False
        return bytes.fromhex(report["measurement"]) == expected_measurement


def _canonical(data: Dict[str, Any]) -> str:
    """Каноническое представление словаря для подписи."""
    import json

    return json.dumps(data, sort_keys=True, separators=(",", ":"))


__all__ = ["SevAttestation", "SevError"]
