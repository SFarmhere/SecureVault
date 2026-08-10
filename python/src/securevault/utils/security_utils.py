"""SecureVault - Криптографические утилиты.

Вспомогательные функции для работы с ключами, паролями, токенами
и безопасным сравнением данных.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

from securevault import constants


def random_token(length: int = 32) -> str:
    """Криптографически стойкий hex-токен заданной длины (в байтах)."""
    return secrets.token_hex(length)


def random_bytes(length: int = 32) -> bytes:
    """Криптографически стойкая последовательность случайных байт."""
    return secrets.token_bytes(length)


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """Константное сравнение двух последовательностей (защита от timing)."""
    return hmac.compare_digest(a, b)


def generate_salt(length: int = constants.ARGON2_SALT_LENGTH) -> bytes:
    """Сгенерировать криптографическую соль."""
    return secrets.token_bytes(length)


def verify_password(password: str, expected_hash: bytes, salt: bytes) -> bool:
    """Проверить пароль по хешу (SHA-256 fallback).

    Примечание: для продакшена использовать специализированный KDF
    (Argon2id через core.key_manager).
    """
    derived = derive_password_hash(password, salt)
    return constant_time_equals(derived, expected_hash)


def derive_password_hash(password: str, salt: bytes) -> bytes:
    """Вычислить хеш пароля с солью (SHA-256 fallback)."""
    return hashlib.sha256(salt + password.encode("utf-8")).digest()


def key_strength_bits(key: bytes) -> int:
    """Оценить энтропию ключа в битах."""
    return len(key) * 8


def secure_zero(data: bytearray) -> None:
    """Затереть данные в памяти нулями."""
    for i in range(len(data)):
        data[i] = 0


def fingerprint(data: bytes, length: int = 16) -> str:
    """Отпечаток данных (SHA-256, hex)."""
    return hashlib.sha256(data).hexdigest()[:length]


def is_strong_password(
    password: str, min_length: int = constants.MIN_PASSWORD_LENGTH
) -> bool:
    """Базовая проверка сложности пароля."""
    if not isinstance(password, str) or len(password) < min_length:
        return False
    checks = [
        any(c.isupper() for c in password),
        any(c.islower() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ]
    return sum(checks) >= 3


__all__ = [
    "random_token",
    "random_bytes",
    "constant_time_equals",
    "generate_salt",
    "verify_password",
    "derive_password_hash",
    "key_strength_bits",
    "secure_zero",
    "fingerprint",
    "is_strong_password",
]
