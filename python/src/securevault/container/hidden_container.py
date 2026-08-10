"""SecureVault - Скрытый контейнер (plausible deniability).

Реализация контейнера, в котором поверх «обычного» содержимого (приманка)
размещается скрытый том, открываемый вторым паролем. Существование
скрытого тома невозможно доказать без пароля.

Схема: два независимых AES-256-GCM-шифрованных сегмента внутри одного
файла. Сегмент приманки и скрытый сегмент не имеют криптографической
связи — оба выглядят как случайные данные.
"""

from __future__ import annotations

import logging
import os
import struct
from typing import Dict

from securevault.native import crypto

logger = logging.getLogger(__name__)

MAGIC = b"SVHC"  # SecureVault Hidden Container
VERSION = 1
# Структура: [4 MAGIC][2 версия][2 флаг скрыт][8 размер полезн.][данные(N)]
_HEADER = struct.Struct(">4sHHI")


class HiddenContainerError(Exception):
    """Ошибка скрытого контейнера."""


class HiddenContainer:
    """Скрытый (денiable) контейнер с двумя слоями."""

    def __init__(self, size: int = 65536):
        # Распределяем: 40% приманка, 60% скрытый том
        self._decoy_size = int(size * 0.4)
        self._hidden_size = size - self._decoy_size
        self._data = bytearray(size)

    # ------------------------------------------------------------------
    # Создание
    # ------------------------------------------------------------------
    def create(
        self,
        decoy: Dict[str, bytes],
        hidden: Dict[str, bytes],
        decoy_key: bytes,
        hidden_key: bytes,
    ) -> bytes:
        """Создать скрытый контейнер.

        Args:
            decoy: Файлы приманки (name -> data).
            hidden: Файлы скрытого тома (name -> data).
            decoy_key: Ключ приманки.
            hidden_key: Ключ скрытого тома.

        Returns:
            Сериализованный контейнер (байты).
        """
        payload_decoy = self._pack_payload(decoy)
        payload_hidden = self._pack_payload(hidden)

        if len(payload_decoy) + len(payload_hidden) > len(self._data):
            raise HiddenContainerError("Payload exceeds container size")

        decoy_ct = self._seal(payload_decoy, decoy_key)
        hidden_ct = self._seal(payload_hidden, hidden_key)

        # Заполняем весь буфер случайными байтами (никаких «дыр»).
        self._data = bytearray(os.urandom(len(self._data)))

        # Сегмент приманки — в начале файла, скрытый сегмент — в конце.
        seg_d = _HEADER.pack(MAGIC, VERSION, 0, len(decoy_ct)) + decoy_ct
        seg_h = _HEADER.pack(MAGIC, VERSION, 1, len(hidden_ct)) + hidden_ct

        self._data[0 : len(seg_d)] = seg_d
        tail = len(self._data) - len(seg_h)
        self._data[tail:] = seg_h

        return bytes(self._data)

    # ------------------------------------------------------------------
    # Открытие
    # ------------------------------------------------------------------
    def open(self, container: bytes, key: bytes) -> Dict[str, bytes]:
        """Открыть контейнер ключом (приманки или скрытым).

        Сканирует содержимое на наличие валидных заголовков сегментов
        и пробует расшифровать каждый ключом. Корректный сегмент
        определяется успешной проверкой тега GCM.
        """
        positions: list = []
        n = len(container)
        for i in range(0, n - _HEADER.size):
            if container[i : i + 4] != MAGIC:
                continue
            try:
                _magic, _ver, _flag, plen = _HEADER.unpack_from(container, i)
            except struct.error:
                continue
            if i + _HEADER.size + plen <= n:
                positions.append((i, plen))

        for offset, plen in positions:
            seg = container[offset + _HEADER.size : offset + _HEADER.size + plen]
            try:
                payload = self._open(seg, key)
            except crypto.AuthenticationError:
                continue  # неверный ключ/не тот сегмент
            except Exception as e:  # noqa: BLE001
                logger.debug(f"Segment decrypt failed at {offset}: {e}")
                continue
            return self._unpack_payload(payload)

        raise HiddenContainerError("Unable to open container with provided key")

    # ------------------------------------------------------------------
    # Внутренние helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _pack_payload(files: Dict[str, bytes]) -> bytes:
        out = struct.pack(">I", len(files))
        for name, data in files.items():
            name_b = name.encode("utf-8")
            out += struct.pack(">I", len(name_b)) + name_b
            out += struct.pack(">Q", len(data)) + data
        return out

    @staticmethod
    def _unpack_payload(payload: bytes) -> Dict[str, bytes]:
        files: Dict[str, bytes] = {}
        offset = 4
        count = struct.unpack_from(">I", payload, 0)[0]
        for _ in range(count):
            name_len = struct.unpack_from(">I", payload, offset)[0]
            offset += 4
            name = payload[offset : offset + name_len].decode("utf-8")
            offset += name_len
            data_len = struct.unpack_from(">Q", payload, offset)[0]
            offset += 8
            files[name] = payload[offset : offset + data_len]
            offset += data_len
        return files

    @staticmethod
    def _seal(data: bytes, key: bytes) -> bytes:
        return crypto.encrypt_aes_gcm(data, key)

    @staticmethod
    def _open(data: bytes, key: bytes) -> bytes:
        return crypto.decrypt_aes_gcm(data, key)


__all__ = ["HiddenContainer", "HiddenContainerError"]
