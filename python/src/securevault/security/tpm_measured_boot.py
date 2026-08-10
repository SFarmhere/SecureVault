"""SecureVault - Измерение целостности загрузки (TPM PCR).

Программная модель TPM-измерений: ведение регистров PCR, их расширение
(extend) и проверка ожидаемых значений. Реальный TPM добавляется
аппаратным модулем; здесь реализована логика цепочки измерений.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class PcrValue:
    """Значение регистра PCR."""

    index: int
    value: str
    measured_by: str = ""


class PcrError(Exception):
    """Ошибка работы с PCR."""


class TpmMeasuredBoot:
    """Управление регистрами PCR в программном режиме."""

    SHA256_LEN = 32  # байт

    def __init__(self, banks: Optional[List[int]] = None):
        self._pcrs: Dict[int, str] = {}
        self._banks = banks or list(range(0, 24))

    def _digest(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def extend(self, index: int, data: bytes, measured_by: str = "") -> str:
        """Расширить регистр PCR: new = H(old || data).

        Args:
            index: Номер регистра PCR.
            data: Данные для измерения.
            measured_by: Источник измерения (модуль).

        Returns:
            Новое значение регистра (hex).
        """
        if index not in self._banks:
            raise PcrError(f"PCR bank {index} not supported")
        if index < 0:
            raise PcrError(f"Invalid PCR index: {index}")

        old = self._pcrs.get(index)
        if old is None:
            old = "00" * self.SHA256_LEN
        old_bytes = bytes.fromhex(old)
        new_value = self._digest(old_bytes + data)
        self._pcrs[index] = new_value
        logger.debug(f"PCR[{index}] extended by {measured_by or 'unknown'}")
        return new_value

    def reset(self, index: int) -> None:
        """Сбросить регистр PCR в исходное состояние."""
        if index in self._pcrs:
            del self._pcrs[index]

    def reset_all(self) -> None:
        self._pcrs.clear()

    def get(self, index: int) -> Optional[str]:
        """Текущее значение регистра PCR (None, если не измерялся)."""
        return self._pcrs.get(index)

    def values(self) -> List[PcrValue]:
        return [PcrValue(k, v) for k, v in sorted(self._pcrs.items())]

    def verify(self, index: int, expected: str) -> bool:
        """Проверить соответствие регистра ожидаемому значению."""
        if index not in self._pcrs:
            return False
        return self._pcrs[index].lower() == expected.lower()

    def integrity_match(self, expected_manifest: Dict[int, str]) -> bool:
        """Проверить целостность против манифеста ожидаемых PCR."""
        for idx, expected in expected_manifest.items():
            if int(idx) in self._pcrs and self._pcrs[int(idx)] != expected:
                return False
        return True


__all__ = ["TpmMeasuredBoot", "PcrValue", "PcrError"]
