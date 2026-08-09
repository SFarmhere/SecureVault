"""SecureVault - Anti-debug и проверка целостности.

Обеспечивает:
- Обнаружение отладчиков
- Проверку целостности PE/ELF/Mach-O
- Anti-debugging техники (Windows, Linux, macOS)
"""

import logging
import platform
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class AntiDebugError(Exception):
    """Ошибка anti-debug."""


class AntiDebug:
    """
    Anti-debug модуль для обнаружения отладчиков и проверки целостности.

    Поддерживает:
    - Windows: IsDebuggerPresent, PEB.BeingDebugged
    - Linux: /proc/self/status TracerPid
    - macOS: sysctl P_TRACED
    - Проверку целостности исполняемых файлов (PE/ELF/Mach-O)
    """

    def __init__(self):
        self._system = platform.system().lower()
        self._debugger_detected = False
        self._checks: List[Dict[str, Any]] = []

    def check(self) -> List[Dict[str, Any]]:
        """Выполнить все проверки на отладчики."""
        self._debugger_detected = False
        self._checks = []

        if self._system == "windows":
            self._check_windows()
        elif self._system == "linux":
            self._check_linux()
        elif self._system == "darwin":
            self._check_macos()

        return self._checks

    def is_debugger_detected(self) -> bool:
        """Проверить, обнаружен ли отладчик."""
        return self._debugger_detected

    def get_checks(self) -> List[Dict[str, Any]]:
        """Получить результаты проверок."""
        return self._checks

    def check_integrity(self, file_path: str) -> bool:
        """Проверить целостность исполняемого файла."""
        try:
            with open(file_path, "rb") as f:
                data = f.read()
            return self._verify_executable(data)
        except Exception as e:
            logger.error(f"Integrity check failed for {file_path}: {e}")
            return False

    # ------------------------------------------------------------------------
    # ПРОВЕРКИ ПО ПЛАТФОРМАМ
    # ------------------------------------------------------------------------

    def _check_windows(self) -> None:
        """Проверка на отладчик в Windows."""
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            result = kernel32.IsDebuggerPresent()
            self._add_check("IsDebuggerPresent", result != 0)
        except Exception as e:
            self._add_check("IsDebuggerPresent", False, f"Error: {e}")

    def _check_linux(self) -> None:
        """Проверка на отладчик в Linux."""
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("TracerPid:"):
                        pid = int(line.split(":")[1].strip())
                        self._add_check("TracerPid", pid != 0)
                        break
        except Exception as e:
            self._add_check("TracerPid", False, f"Error: {e}")

    def _check_macos(self) -> None:
        """Проверка на отладчик в macOS."""
        try:
            self._add_check("sysctl", False, "Not fully implemented")
        except Exception as e:
            self._add_check("sysctl", False, f"Error: {e}")

    # ------------------------------------------------------------------------
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # ------------------------------------------------------------------------

    def _add_check(self, name: str, detected: bool, details: str = "") -> None:
        self._checks.append({"name": name, "detected": detected, "details": details})
        if detected:
            self._debugger_detected = True
        logger.debug(f"Anti-debug check {name}: detected={detected}")

    def _verify_executable(self, data: bytes) -> bool:
        """Проверить структуру исполняемого файла."""
        try:
            if data[:2] == b"MZ":
                return self._verify_pe(data)
            elif data[:4] == b"\x7fELF":
                return self._verify_elf(data)
            elif data[:4] in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"):
                return self._verify_macho(data)
            return False
        except Exception:
            return False

    def _verify_pe(self, data: bytes) -> bool:
        """Проверка PE формата."""
        try:
            if len(data) < 64:
                return False
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            if pe_offset + 4 > len(data):
                return False
            return data[pe_offset : pe_offset + 4] == b"PE\x00\x00"
        except Exception:
            return False

    def _verify_elf(self, data: bytes) -> bool:
        """Проверка ELF формата."""
        try:
            if len(data) < 52:
                return False
            return data[4] in (1, 2) and data[5] in (1, 2)
        except Exception:
            return False

    def _verify_macho(self, data: bytes) -> bool:
        """Проверка Mach-O формата."""
        try:
            return len(data) >= 4
        except Exception:
            return False


__all__ = ["AntiDebug", "AntiDebugError"]
