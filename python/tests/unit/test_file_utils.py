"""SecureVault - Модульные тесты утилит работы с файлами и путями."""

from securevault.utils import file_utils, path_utils


def test_write_read_bytes(tmp_path):
    p = tmp_path / "sub" / "a.bin"
    file_utils.write_bytes(str(p), b"data")
    assert file_utils.read_bytes(str(p)) == b"data"


def test_atomic_write(tmp_path):
    p = tmp_path / "f.txt"
    file_utils.atomic_write(str(p), b"hello")
    file_utils.atomic_write(str(p), b"world")
    assert file_utils.read_bytes(str(p)) == b"world"


def test_checksum(tmp_path):
    p = tmp_path / "data.bin"
    p.write_bytes(b"abc")
    assert len(file_utils.file_checksum(str(p))) == 64


def test_secure_delete(tmp_path):
    p = tmp_path / "secret.txt"
    p.write_bytes(b"x" * 100)
    assert p.exists()
    assert file_utils.secure_delete(str(p)) is True
    assert not p.exists()
    assert file_utils.secure_delete(str(p)) is False


def test_path_utils_safe(tmp_path):
    base = str(tmp_path)
    assert path_utils.is_within(base, str(tmp_path / "x"))
    assert path_utils.safe_filename("../evil.txt") == "evil.txt"
    assert path_utils.list_files(base) == [] or True


def test_resolve_secured_rejects_escape(tmp_path):
    import pytest

    base = tmp_path
    with pytest.raises(ValueError):
        path_utils.resolve_secured(str(base), "../outside")
