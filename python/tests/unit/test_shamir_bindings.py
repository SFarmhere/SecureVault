"""SecureVault - Модульные тесты Shamir Secret Sharing (Python-реализация)."""

from securevault.security.shamir import (
    InsufficientSharesError,
    ShamirSecretSharing,
    join_shares,
    split_secret,
)


def test_split_join_roundtrip():
    secret = b"master-secret" * 2
    shares = split_secret(secret, total=5, threshold=3)
    assert len(shares) == 5
    recovered = join_shares(shares[:3])
    assert recovered == secret


def test_threshold_required():
    secret = b"important-secret"
    shares = split_secret(secret, total=5, threshold=3)
    # Двух долей недостаточно
    try:
        join_shares(shares[:2])
        raised = False
    except InsufficientSharesError:
        raised = True
    assert raised


def test_class_interface():
    sss = ShamirSecretSharing()
    secret = b"secret"
    shares = sss.split(secret, total=3, threshold=2)
    assert sss.join(shares[:2]) == secret


def test_different_subset_also_works():
    secret = b"multi-subset"
    shares = split_secret(secret, total=5, threshold=3)
    assert join_shares([shares[4], shares[1], shares[3]]) == secret
