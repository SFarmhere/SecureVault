"""SecureVault - Контейнерный формат (уровень CONTAINER).

Упаковка/распаковка файлов в единый поток с манифестом, проверкой
целостности и опциональным шифрованием контейнера ключом.
"""

from __future__ import annotations

import hashlib
import io
import json
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional

CONTAINER_MAGIC_V1 = b"SVC1"  # Обычный формат
CONTAINER_MAGIC_V2 = b"SVC2"  # Скрытый формат (plausible deniability)
HEADER_VERSION = 1


class ContainerFormatError(Exception):
    """Ошибка формата контейнера."""


@dataclass
class ContainerEntry:
    """Запись (файл) внутри контейнера."""

    name: str
    data: bytes
    mime: str = "application/octet-stream"

    def checksum(self) -> str:
        return hashlib.sha256(self.data).hexdigest()


class ContainerFormat:
    """Упаковка набора записей в единый поток с манифестом."""

    def __init__(self, container_id: Optional[str] = None, format_version: int = 1):
        self.container_id = container_id or ""
        self.format_version = format_version
        self.entries: Dict[str, ContainerEntry] = {}

    def magic(self) -> bytes:
        return CONTAINER_MAGIC_V2 if self.format_version == 2 else CONTAINER_MAGIC_V1

    def add(self, entry: ContainerEntry) -> None:
        self.entries[entry.name] = entry

    def remove(self, name: str) -> bool:
        return self.entries.pop(name, None) is not None

    def get(self, name: str) -> Optional[ContainerEntry]:
        return self.entries.get(name)

    def names(self) -> List[str]:
        return list(self.entries.keys())

    def total_size(self) -> int:
        return sum(len(e.data) for e in self.entries.values())

    def pack(self) -> bytes:
        """Упаковать в бинарный поток.

        Формат: [4 MAGIC][1 VERSION][4 длина манифеста][манифест]
                ... секции данных [4 длина][данные]
        """
        manifest = {
            "container_id": self.container_id,
            "format_version": self.format_version,
            "files": [
                {"name": e.name, "mime": e.mime, "sha256": e.checksum()}
                for e in self.entries.values()
            ],
        }
        manifest_bytes = json.dumps(manifest, ensure_ascii=False).encode("utf-8")
        out = io.BytesIO()
        out.write(self.magic())
        out.write(struct.pack("B", HEADER_VERSION))
        out.write(struct.pack(">I", len(manifest_bytes)))
        out.write(manifest_bytes)
        for entry in self.entries.values():
            out.write(struct.pack(">I", len(entry.data)))
            out.write(entry.data)
        return out.getvalue()

    @classmethod
    def unpack(cls, data: bytes) -> "ContainerFormat":
        """Разобрать бинарный поток в контейнер (с проверкой целостности)."""
        if len(data) < 9:
            raise ContainerFormatError("Container too short")
        magic = data[:4]
        if magic not in (CONTAINER_MAGIC_V1, CONTAINER_MAGIC_V2):
            raise ContainerFormatError(f"Invalid container magic: {magic!r}")
        version, manifest_len = struct.unpack(">BI", data[4:9])
        offset = 9
        manifest_bytes = data[offset : offset + manifest_len]
        offset += manifest_len
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            raise ContainerFormatError(f"Invalid manifest: {e}") from e
        container = cls(
            container_id=manifest.get("container_id", ""),
            format_version=manifest.get("format_version", version),
        )
        for file_info in manifest.get("files", []):
            size = struct.unpack(">I", data[offset : offset + 4])[0]
            offset += 4
            file_data = data[offset : offset + size]
            offset += size
            entry = ContainerEntry(
                file_info["name"],
                file_data,
                file_info.get("mime", "application/octet-stream"),
            )
            if entry.checksum() != file_info.get("sha256", ""):
                raise ContainerFormatError(f"Checksum mismatch for {entry.name}")
            container.add(entry)
        return container

    def encrypt_payload(self, key: bytes, container_id: Optional[str] = None) -> bytes:
        """Зашифровать упакованный контейнер ключом (AES-256-GCM)."""
        from securevault.protection_levels.container import ContainerProtectionLevel

        protection = ContainerProtectionLevel(container_id=container_id)
        ct, _ = protection.encrypt(self.pack(), key)
        return ct

    @classmethod
    def decrypt_payload(cls, ciphertext: bytes, key: bytes) -> "ContainerFormat":
        """Расшифровать и разобрать контейнер."""
        from securevault.protection_levels.container import ContainerProtectionLevel

        protection = ContainerProtectionLevel()
        packed = protection.decrypt(ciphertext, key)
        return cls.unpack(packed)


__all__ = [
    "ContainerFormat",
    "ContainerEntry",
    "ContainerFormatError",
    "CONTAINER_MAGIC_V1",
    "CONTAINER_MAGIC_V2",
]
