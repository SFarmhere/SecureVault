"""SecureVault - Индикатор прогресса для CLI."""

from __future__ import annotations

import sys
import time


class ProgressBar:
    """Простой прогресс-индикатор, выводимый в stderr."""

    WIDTH = 40

    def __init__(self, total: int, description: str = "Progress"):
        self.total = max(1, total)
        self.description = description
        self.current = 0
        self._start = time.time()

    def update(self, increment: int = 1, force: bool = False) -> None:
        """Обновить текущее значение."""
        self.current = min(self.current + increment, self.total)
        if force or self.current == self.total:
            self.render(final=True)

    def set(self, value: int) -> None:
        self.current = min(value, self.total)

    def render(self, final: bool = False) -> None:
        ratio = self.current / self.total
        filled = int(ratio * self.WIDTH)
        bar = "#" * filled + "-" * (self.WIDTH - filled)
        percent = ratio * 100
        line = f"\r{self.description}: [{bar}] {percent:5.1f}%"
        if not final:
            sys.stderr.write(line)
            sys.stderr.flush()
        else:
            elapsed = time.time() - self._start
            sys.stderr.write(f"{line} ({elapsed:.2f}s)\n")
            sys.stderr.flush()

    def finish(self) -> None:
        self.current = self.total
        self.render(final=True)


__all__ = ["ProgressBar"]
