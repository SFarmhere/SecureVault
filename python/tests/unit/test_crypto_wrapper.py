"""SecureVault - Модульные тесты криптографической обёртки (native.crypto)."""

from securevault.native import crypto


def test_aes_roundtrip():
    key = b"\x01" * 32
    data = b"sensitive data" * 10
    ct = crypto.encrypt_aes_gcm(data, key)
    assert ct != data
    assert crypto.decrypt_aes_gcm(ct, key) == data


def test_aes_wrong_key_fails():
    import pytest
    from securevault.native.crypto import AuthenticationError

    key = b"\x02" * 32
    other = b"\x03" * 32
    ct = crypto.encrypt_aes_gcm(b"hello", key)
    with pytest.raises(AuthenticationError):
        crypto.decrypt_aes_gcm(ct, other)


def test_hash_functions():
    assert len(crypto.hash_sha256(b"x")) == 32
    assert len(crypto.hash_sha512(b"x")) == 64


def test_hmac_sha256():
    out = crypto.hmac_sha256(b"data", b"key")
    assert len(out) == 32


def test_ecdsa_sign_verify():
    priv, pub = crypto.generate_ecdsa_keypair()
    sig = crypto.sign_ecdsa(b"message", priv)
    assert crypto.verify_ecdsa(b"message", sig, pub) is True
    assert crypto.verify_ecdsa(b"tampered", sig, pub) is False


def test_generate_random():
    assert len(crypto.generate_random(16)) == 16


def test_constant_time_equals():
    assert crypto.constant_time_equals(b"a", b"a") is True
    assert crypto.constant_time_equals(b"a", b"b") is False
