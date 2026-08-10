"""SecureVault - Сканер безопасности.

Проверка конфигурации, путей и окружения на предмет ослаблений
безопасности: слабые пароли, устаревшие сертификаты, рискованные пути.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """Результат одной проверки безопасности."""

    severity: str  # low | medium | high | critical
    check: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {"severity": self.severity, "check": self.check, "detail": self.detail}


class SecurityScanner:
    """Набор проверок безопасности окружения и конфигурации."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.findings: List[Finding] = field(default_factory=list)  # type: ignore[assignment]

    def scan(self) -> List[Finding]:
        """Выполнить все проверки и вернуть найденные проблемы."""
        self.findings = []
        self._check_anti_debug()
        self._check_config()
        self._check_paths()
        self._check_password_policy()
        return list(self.findings)

    # ------------------------------------------------------------------
    # Проверки
    # ------------------------------------------------------------------
    def _check_anti_debug(self) -> None:
        try:
            from securevault.security.anti_debug import AntiDebug

            detector = AntiDebug()
            detector.check()
            for item in detector.get_checks():
                if item.get("detected"):
                    self.findings.append(
                        Finding(
                            "critical",
                            "anti_debug",
                            f"Debugger detected: {item['name']}",
                        )
                    )
        except Exception as e:  # noqa: BLE001
            self.findings.append(Finding("medium", "anti_debug", f"Check failed: {e}"))

    def _check_config(self) -> None:
        audit = self.config.get("audit", {})
        if self.config.get("audit", {}).get("enabled") is False:
            self.findings.append(
                Finding("high", "audit_disabled", "Audit logging is disabled")
            )
        if audit.get("sign_entries") is False:
            self.findings.append(
                Finding("high", "audit_no_signature", "Audit entries are not signed")
            )
        anti_debug = self.config.get("security", {}).get("anti_debug", True)
        if anti_debug is False:
            self.findings.append(
                Finding("medium", "anti_debug_disabled", "Anti-debug is disabled")
            )

    def _check_paths(self) -> None:
        data_dir = self.config.get("app", {}).get("data_dir")
        if data_dir:
            from securevault.utils import path_utils

            if not path_utils.is_writable(data_dir):
                self.findings.append(
                    Finding("high", "data_dir", f"Data dir not writable: {data_dir}")
                )

    def _check_password_policy(self) -> None:
        min_len = self.config.get("password_policy", {}).get("min_length", 8)
        if min_len < 12:
            self.findings.append(
                Finding(
                    "medium",
                    "password_policy",
                    f"Minimum password length {min_len} < recommended 12",
                )
            )


__all__ = ["SecurityScanner", "Finding"]
