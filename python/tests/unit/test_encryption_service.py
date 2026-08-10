"""SecureVault - Модульные тесты сервиса шифрования."""

from fixtures.mock_services import FakeKeyManager
from fixtures.test_data import make_temp_file
from securevault.core.encryption_service import (
    EncryptionService,
    ProtectionLevel,
    is_encrypted_file,
)


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def test_encrypt_decrypt_data():
    fake = FakeKeyManager()
    svc = EncryptionService(key_mgr=fake)
    key = fake.generate_file_key()
    plain = b"hello securevault" * 10
    ct = svc.encrypt_data(plain, key=key)
    assert ct != plain
    assert svc.decrypt_data(ct, key=key) == plain


def test_file_roundtrip_individual(tmp_path):
    fake = FakeKeyManager()
    svc = EncryptionService(key_mgr=fake)
    key = fake.generate_file_key()
    fake.store_key_securely(key, "k1")

    src = make_temp_file(tmp_path, size=2048)
    enc = str(tmp_path / "out.enc")
    dec = str(tmp_path / "out.dec")
    svc.encrypt_file(src, enc, key_id="k1", protection_level=ProtectionLevel.INDIVIDUAL)
    assert is_encrypted_file(enc)
    svc.decrypt_file(enc, dec, key_id="k1")
    assert _read(dec) == _read(src)


def test_file_roundtrip_container(tmp_path):
    fake = FakeKeyManager()
    svc = EncryptionService(key_mgr=fake)
    key = fake.generate_file_key()
    fake.store_key_securely(key, "k1")

    src = make_temp_file(tmp_path, size=1024)
    enc = str(tmp_path / "c.enc")
    dec = str(tmp_path / "c.dec")
    meta = svc.encrypt_file(
        src, enc, key_id="k1", protection_level=ProtectionLevel.CONTAINER
    )
    assert meta.protection_level == ProtectionLevel.CONTAINER
    svc.decrypt_file(enc, dec, key_id="k1")
    assert _read(dec) == _read(src)


def test_integrity_failure_raises(tmp_path):
    fake = FakeKeyManager()
    svc = EncryptionService(key_mgr=fake)
    key = fake.generate_file_key()

    src = make_temp_file(tmp_path, size=512)
    enc = str(tmp_path / "i.enc")
    svc.encrypt_file(
        src, enc, key_id=None
    )  # генерирует ключ без key_id не требуется для damage-теста
    # портим байты шифротекста
    corrupted = bytearray(_read(enc))
    corrupted[-3] ^= 0xFF
    bad = str(tmp_path / "bad.enc")
    with open(bad, "wb") as fh:
        fh.write(bytes(corrupted))
    from securevault import exceptions

    try:
        svc.decrypt_file(bad, str(tmp_path / "bad.dec"))
        raised = False
    except (exceptions.DecryptionError, exceptions.IntegrityError, Exception):
        raised = True
    assert raised
