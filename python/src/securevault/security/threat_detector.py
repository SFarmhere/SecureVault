"""SecureVault - Детектор угроз.

Объединяет сигналы из разных источников (anti-debug, файловый монитор,
политики) и вычисляет уровень угрозы по эвристикам.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Dict, List

logger = logging.getLogger(__name__)

# Тяжесть сигналов
SEVERITY_WEIGHT = {"low": 1, "medium": 3, "high": 8, "critical": 20}


@dataclass
class ThreatSignal:
    """Отдельный сигнал угрозы."""

    source: str
    severity: str
    detail: str
    timestamp: float = 0.0


class ThreatLevel:
    """Уровни угрозы."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatDetector:
    """Эвристический анализ сигналов и вычисление уровня угрозы."""

    def __init__(self, threshold_high: int = 10, threshold_critical: int = 25):
        self.threshold_high = threshold_high
        self.threshold_critical = threshold_critical
        self._signals: List[ThreatSignal] = []
        self._lock = threading.RLock()
        self._history: Dict[str, float] = {}

    def report(self, source: str, severity: str, detail: str = "") -> None:
        """Зарегистрировать новый сигнал угрозы."""
        with self._lock:
            now = time.time()
            self._signals.append(ThreatSignal(source, severity, detail, now))
            self._history[source] = now
            logger.warning(f"Threat signal [{severity}] {source}: {detail}")

    def _score(self, window: float = 300.0) -> int:
        """Суммарный вес сигналов в пределах окна времени."""
        now = time.time()
        score = 0
        for s in self._signals:
            if now - s.timestamp <= window:
                score += SEVERITY_WEIGHT.get(s.severity, 1)
        return score

    def assess(self, window: float = 300.0) -> str:
        """Оценить текущий уровень угрозы."""
        score = self._score(window)
        if score >= self.threshold_critical:
            return ThreatLevel.CRITICAL
        if score >= self.threshold_high:
            return ThreatLevel.HIGH
        if score > 0:
            return ThreatLevel.MEDIUM
        return ThreatLevel.NONE

    def recent_signals(self, window: float = 300.0) -> List[ThreatSignal]:
        now = time.time()
        return [s for s in self._signals if now - s.timestamp <= window]

    def integrate_anti_debug(self) -> None:
        """Интеграция с anti-debug: при обнаружении отладчика — сигнал."""
        try:
            from securevault.security.anti_debug import AntiDebug

            detector = AntiDebug()
            detector.check()
            if detector.is_debugger_detected():
                self.report("anti_debug", "critical", "Debugger detected")
        except Exception as e:  # noqa: BLE001
            logger.debug(f"Anti-debug integration failed: {e}")

    def reset(self) -> None:
        with self._lock:
            self._signals.clear()
            self._history.clear()


__all__ = ["ThreatDetector", "ThreatSignal", "ThreatLevel"]
