"""SecureVault - Обработка ошибок нативных модулей.

Отображение кодов возврата нативных библиотек в исключения проекта.
"""

from __future__ import annotations

import logging
from typing import Dict

from securevault import exceptions

logger = logging.getLogger(__name__)

# Типовые коды возврата нативных модулей (0 - успех)
KNOWN_CODES: Dict[int, str] = {
    0: "OK",
    1: "FAILED",
    2: "INVALID_ARGUMENT",
    3: "NOT_INITIALIZED",
    4: "BUFFER_TOO_SMALL",
    5: "AUTH_FAILED",
    6: "KEY_NOT_FOUND",
    7: "OUT_OF_MEMORY",
    8: "NOT_SUPPORTED",
}


class NativeErrorHandler:
    """Проверка кодов возврата и генерация исключений."""

    def __init__(self, module_name: str = "native"):
        self.module_name = module_name

    def check(self, code: int, context: str = "") -> None:
        """Проверить код возврата; при ошибке поднять исключение."""
        if code == 0:
            return
        message = KNOWN_CODES.get(code, f"code {code}")
        detail = (
            f"{self.module_name}: {context} -> {message}"
            if context
            else f"{self.module_name}: {message}"
        )
        exc = self._map(code, detail)
        logger.error(detail)
        raise exc

    def _map(self, code: int, message: str):
        if code == 5:
            return exceptions.IntegrityError(message)
        if code == 6:
            return exceptions.KeyNotFoundError(message)
        if code == 8:
            return exceptions.NativeModuleError(f"Not supported: {message}")
        return exceptions.NativeModuleError(message)

    def result(self, code: int, context: str = "") -> int:
        """Аналогично check, но возвращает код (для удобных цепочек)."""
        self.check(code, context)
        return code


__all__ = ["NativeErrorHandler", "KNOWN_CODES"]
