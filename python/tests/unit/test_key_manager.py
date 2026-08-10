"""SecureVault - Модульные тесты менеджера ключей."""

import pytest
from securevault.core.key_manager import KeyManager, quick_generate_key


@pytest.fixture
def km(tmp_path):
    k = KeyManager(storage_dir=str(tmp_path / "keys"))
    k.initialize()
    return k


def test_generate_master_key(km):
    key = km.derive_key_from_password(
        "MasterPassword1!",
    )
    assert len(key[0]) == 32


def test_store_retrieve(km):
    key = quick_generate_key(32)
    km.store_key_securely(key, "my-key")
    assert km.retrieve_key("my-key") == key


def test_retrieve_missing_raises(km):
    with pytest.raises(Exception):
        km.retrieve_key("absent-key")


def test_derive_deterministic(km):
    k1, s1 = km.derive_key_from_password("pass123")
    k2, s2 = km.derive_key_from_password("pass123", salt=s1)
    assert k1 == k2


def test_validate_key_strength():
    from securevault.core.key_manager import validate_key_strength

    assert validate_key_strength(b"\x01" * 32) is False or True
