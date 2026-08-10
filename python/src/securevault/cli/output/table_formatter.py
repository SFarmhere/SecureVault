"""SecureVault - Табличное форматирование вывода CLI."""

from __future__ import annotations

from typing import Iterable, List, Optional, Sequence


class TableFormatter:
    """Отрисовка простых ASCII-таблиц."""

    def __init__(
        self,
        headers: Sequence[str],
        rows: Optional[Iterable[Sequence]] = None,
        title: Optional[str] = None,
    ):
        self.headers = [str(h) for h in headers]
        self.rows: List[List[str]] = [
            ["" if cell is None else str(cell) for cell in row] for row in (rows or [])
        ]
        self.title = title

    def add_row(self, row: Sequence) -> "TableFormatter":
        self.rows.append(["" if cell is None else str(cell) for cell in row])
        return self

    def _widths(self) -> List[int]:
        widths = [len(h) for h in self.headers]
        for row in self.rows:
            for i, cell in enumerate(row):
                if i < len(widths):
                    widths[i] = max(widths[i], len(cell))
                else:
                    widths.append(len(cell))
        return widths

    def render(self) -> str:
        if not self.headers and not self.rows:
            return "(пусто)"
        widths = self._widths()
        lines: List[str] = []
        if self.title:
            lines.append(self.title)
        sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"

        def fmt(row: Sequence[str]) -> str:
            out = []
            for i in range(len(widths)):
                cell = row[i] if i < len(row) else ""
                out.append(f" {cell:<{widths[i]}} ")
            return "|" + "|".join(out) + "|"

        lines.append(sep)
        lines.append(fmt(self.headers))
        lines.append(sep)
        for row in self.rows:
            lines.append(fmt(row))
        lines.append(sep)
        return "\n".join(lines)

    def __str__(self) -> str:
        return self.render()


__all__ = ["TableFormatter"]
