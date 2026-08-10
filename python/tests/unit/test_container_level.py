"""SecureVault - Модульные тесты контейнерного уровня защиты."""

from fixtures.test_data import random_key
from securevault.protection_levels.container import (
    ContainerEntry,
    ContainerFormat,
    ContainerFormatError,
)
from securevault.protection_levels.container_level import ContainerLevel


def test_container_format_roundtrip():
    c = ContainerFormat(container_id="c1")
    c.add(ContainerEntry("a.txt", b"alpha"))
    c.add(ContainerEntry("b.bin", b"beta"))
    packed = c.pack()
    c2 = ContainerFormat.unpack(packed)
    assert c2.names() == ["a.txt", "b.bin"]
    assert c2.get("a.txt").data == b"alpha"
    assert (
        c2.get("b.bin").checksum()
        == "e89a0b57b4766dc67893a9918a5b09a4717293a5c1d8e22a1f3f8c73f4c1b9ca"
    )  # sha256("beta")


def test_container_format_checksum_violation():
    c = ContainerFormat()
    c.add(ContainerEntry("x", b"data"))
    packed = bytearray(c.pack())
    packed[-1] ^= 0xFF  # портим данные
    try:
        ContainerFormat.unpack(bytes(packed))
        raised = False
    except ContainerFormatError:
        raised = True
    assert raised


def test_container_level_create_open():
    key = random_key()
    level = ContainerLevel(container_id="c1")
    blob = level.create({"a.txt": b"hello", "b.txt": b"world"}, key)
    opened = level.open(blob, key)
    assert opened == {"a.txt": b"hello", "b.txt": b"world"}
    assert sorted(level.list_files(blob, key)) == ["a.txt", "b.txt"]
    assert level.extract_file(blob, key, "a.txt") == b"hello"


def test_container_level_add_file():
    key = random_key()
    level = ContainerLevel()
    blob = level.create({"a.txt": b"one"}, key)
    updated = level.add_file(blob, key, "b.txt", b"two")
    assert level.open(updated, key) == {"a.txt": b"one", "b.txt": b"two"}
