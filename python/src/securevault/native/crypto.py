"""
SecureVault - Криптографический модуль (Python обертка)

Предоставляет криптографические операции с автоматическим выбором
реализации:
1. Нативный C++ модуль (если доступен)
2. Python cryptography библиотека (fallback)

Функции:
- Шифрование/дешифрование AES-256-GCM
- Хеширование SHA256/SHA512
- HMAC-SHA256
- Генерация случайных чисел
- Подпись и проверка ECDSA (для аудита)

Зависимости:
- native/__init__.py: Менеджер нативных модулей
- exceptions: Исключения проекта
- constants: Константы

Использование:
    from securevault.native import crypto

    # Проверка доступности
    if crypto.is_available():
        encrypted = crypto.encrypt_aes_gcm(data, key)
    else:
        # Используется Python fallback
        encrypted = crypto.encrypt_aes_gcm(data, key)
"""

import os
import hmac
import hashlib
import logging
import secrets
from typing import Optional, Tuple

# Внутренние импорты
from securevault.native import get_native_manager
from securevault import exceptions
from securevault import constants

logger = logging.getLogger(__name__)


# ============================================================================
# КОНСТАНТЫ
# ============================================================================

# Размеры
AES_GCM_NONCE_SIZE = constants.AES_GCM_NONCE_SIZE  # 12 байт
AES_GCM_TAG_SIZE = constants.AES_GCM_TAG_SIZE  # 16 байт
AES_KEY_SIZE = constants.AES_KEY_SIZE  # 32 байта (AES-256)

# ECDSA
ECDSA_P256_KEY_SIZE = constants.ECDSA_P256_KEY_SIZE  # 32 байта
ECDSA_P384_KEY_SIZE = constants.ECDSA_P384_KEY_SIZE  # 48 байт


# ============================================================================
# ИСКЛЮЧЕНИЯ
# ============================================================================


class CryptoError(exceptions.NativeError):
    """Базовое исключение для криптографических операций."""


class CryptoNotAvailableError(CryptoError):
    """Криптографический модуль недоступен."""


class InvalidKeyError(CryptoError):
    """Невалидный ключ."""


class InvalidNonceError(CryptoError):
    """Невалидный nonce."""


class AuthenticationError(CryptoError):
    """Ошибка аутентификации (неверный тег)."""


# ============================================================================
# ВНУТРЕННЕЕ СОСТОЯНИЕ
# ============================================================================
# Кэш доступности нативного модуля
_native_available: Optional[bool] = None

# Кэш Python cryptography доступности
_python_crypto_available: Optional[bool] = None


# ============================================================================
# ПРОВЕРКА ДОСТУПНОСТИ
# ============================================================================


def is_available() -> bool:
    """
    Проверить доступность криптографического модуля.

    Returns:
        True если доступен нативный модуль или Python fallback.
    """
    global _native_available
    if _native_available is None:
        try:
            nm = get_native_manager()
            _native_available = nm.is_crypto_available()
        except Exception:
            _native_available = False

    return _native_available or _is_python_crypto_available()


def is_native_available() -> bool:
    """
    Проверить доступность нативного C++ модуля.

    Returns:
        True если нативный модуль доступен.
    """
    global _native_available
    if _native_available is None:
        try:
            nm = get_native_manager()
            _native_available = nm.is_crypto_available()
        except Exception:
            _native_available = False
    return _native_available


def _is_python_crypto_available() -> bool:
    """Проверить доступность Python cryptography библиотеки."""
    global _python_crypto_available
    if _python_crypto_available is None:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401

            _python_crypto_available = True
        except ImportError:
            _python_crypto_available = False
    return _python_crypto_available


# ============================================================================
# AES-256-GCM ШИФРОВАНИЕ
# ============================================================================


def encrypt_aes_gcm(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Шифрование AES-256-GCM.

    Args:
        plaintext: Открытый текст.
        key: Ключ (32 байта для AES-256).
        associated_data: Дополнительные аутентифицированные данные (AAD).

    Returns:
        nonce + ciphertext + tag (12 + N + 16 байт).

    Raises:
        InvalidKeyError: Если ключ невалидного размера.
        CryptoError: Если шифрование не удалось.
    """
    _validate_key(key)

    # Попытка использовать нативный модуль
    if is_native_available():
        try:
            nm = get_native_manager()
            return nm.crypto.encrypt_aes_gcm(plaintext, key, associated_data)
        except NotImplementedError:
            logger.debug("Native AES-GCM not implemented, using Python fallback")
        except Exception as e:
            logger.warning(f"Native AES-GCM failed: {e}, using Python fallback")

    # Python fallback
    return _encrypt_aes_gcm_python(plaintext, key, associated_data)


def decrypt_aes_gcm(
    ciphertext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Дешифрование AES-256-GCM.

    Args:
        ciphertext: Зашифрованные данные (nonce + ciphertext + tag).
        key: Ключ (32 байта для AES-256).
        associated_data: Дополнительные аутентифицированные данные (AAD).

    Returns:
        Открытый текст.

    Raises:
        InvalidKeyError: Если ключ невалидного размера.
        AuthenticationError: Если проверка тега не прошла.
        CryptoError: Если дешифрование не удалось.
    """
    _validate_key(key)

    if len(ciphertext) < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE:
        raise CryptoError(
            f"Ciphertext too short: {len(ciphertext)} bytes "
            f"(need at least {AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE})"
        )

    # Попытка использовать нативный модуль
    if is_native_available():
        try:
            nm = get_native_manager()
            return nm.crypto.decrypt_aes_gcm(ciphertext, key, associated_data)
        except NotImplementedError:
            logger.debug("Native AES-GCM not implemented, using Python fallback")
        except Exception as e:
            logger.warning(f"Native AES-GCM decrypt failed: {e}, using Python fallback")

    # Python fallback
    return _decrypt_aes_gcm_python(ciphertext, key, associated_data)


def _encrypt_aes_gcm_python(
    plaintext: bytes,
    key: bytes,
    associated_data: Optional[bytes],
) -> bytes:
    """Python реализация AES-256-GCM через cryptography."""
    if not _is_python_crypto_available():
        raise CryptoNotAvailableError(
            "No crypto backend available. Install 'cryptography' package "
            "or build native crypto module."
        )

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        aesgcm = AESGCM(key)
        nonce = os.urandom(AES_GCM_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        # Формат: nonce + ciphertext (включая tag)
        return nonce + ciphertext

    except ImportError:
        raise CryptoNotAvailableError("cryptography library not installed")
    except Exception as e:
        raise CryptoError(f"AES-GCM encryption failed: {e}")


def _decrypt_aes_gcm_python(
    ciphertext: bytes,
    key: bytes,
    associated_data: Optional[bytes],
) -> bytes:
    """Python реализация AES-256-GCM через cryptography."""
    if not _is_python_crypto_available():
        raise CryptoNotAvailableError(
            "No crypto backend available. Install 'cryptography' package "
            "or build native crypto module."
        )

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.exceptions import InvalidTag

        aesgcm = AESGCM(key)
        nonce = ciphertext[:AES_GCM_NONCE_SIZE]
        encrypted = ciphertext[AES_GCM_NONCE_SIZE:]

        try:
            return aesgcm.decrypt(nonce, encrypted, associated_data)
        except InvalidTag:
            raise AuthenticationError("AES-GCM authentication failed (invalid tag)")

    except ImportError:
        raise CryptoNotAvailableError("cryptography library not installed")
    except AuthenticationError:
        raise
    except Exception as e:
        raise CryptoError(f"AES-GCM decryption failed: {e}")


# ============================================================================
# ХЕШИРОВАНИЕ
# ============================================================================


def hash_sha256(data: bytes) -> bytes:
    """
    SHA256 хеш.

    Args:
        data: Данные для хеширования.

    Returns:
        32-байтовый хеш.
    """
    # Попытка использовать нативный модуль
    if is_native_available():
        try:
            nm = get_native_manager()
            return nm.crypto.hash_sha256(data)
        except NotImplementedError:
            pass
        except Exception as e:
            logger.warning(f"Native SHA256 failed: {e}")

    return hashlib.sha256(data).digest()


def hash_sha512(data: bytes) -> bytes:
    """
    SHA512 хеш.

    Args:
        data: Данные для хеширования.

    Returns:
        64-байтовый хеш.
    """
    # Попытка использовать нативный модуль
    if is_native_available():
        try:
            nm = get_native_manager()
            return nm.crypto.hash_sha512(data)
        except NotImplementedError:
            pass
        except Exception as e:
            logger.warning(f"Native SHA512 failed: {e}")

    return hashlib.sha512(data).digest()


def hmac_sha256(data: bytes, key: bytes) -> bytes:
    """
    HMAC-SHA256.

    Args:
        data: Данные.
        key: Ключ.

    Returns:
        32-байтовый HMAC.
    """
    # Попытка использовать нативный модуль
    if is_native_available():
        try:
            nm = get_native_manager()
            return nm.crypto.hmac_sha256(data, key)
        except NotImplementedError:
            pass
        except Exception as e:
            logger.warning(f"Native HMAC-SHA256 failed: {e}")

    return hmac.new(key, data, hashlib.sha256).digest()


# ============================================================================
# ГЕНЕРАЦИЯ СЛУЧАЙНЫХ ЧИСЕЛ
# ============================================================================


def generate_random(size: int) -> bytes:
    """
    Генерация криптостойких случайных байтов.

    Args:
        size: Количество байтов.

    Returns:
        Случайные байты.

    Raises:
        CryptoError: Если size <= 0.
    """
    if size <= 0:
        raise CryptoError(f"Size must be positive, got {size}")

    # Попытка использовать нативный модуль
    if is_native_available():
        try:
            nm = get_native_manager()
            return nm.crypto.generate_random(size)
        except NotImplementedError:
            pass
        except Exception as e:
            logger.warning(f"Native random failed: {e}")

    return secrets.token_bytes(size)


# ============================================================================
# ECDSA ПОДПИСЬ (ДЛЯ АУДИТА)
# ============================================================================


def generate_ecdsa_keypair(curve: str = "p256") -> Tuple[bytes, bytes]:
    """
    Сгенерировать ECDSA ключевую пару.

    Args:
        curve: Кривая ("p256" или "p384").

    Returns:
        Кортеж (private_key_pem, public_key_pem).

    Raises:
        CryptoError: Если генерация не удалась.
    """
    if not _is_python_crypto_available():
        raise CryptoNotAvailableError("ECDSA requires 'cryptography' package")

    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import serialization

        if curve == "p256":
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif curve == "p384":
            private_key = ec.generate_private_key(ec.SECP384R1())
        else:
            raise CryptoError(f"Unsupported curve: {curve}")

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        return private_pem, public_pem

    except ImportError:
        raise CryptoNotAvailableError("cryptography library not installed")
    except Exception as e:
        raise CryptoError(f"ECDSA keypair generation failed: {e}")


def sign_ecdsa(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Подписать данные ECDSA.

    Args:
        data: Данные для подписи.
        private_key_pem: Приватный ключ в PEM формате.

    Returns:
        Подпись (DER формат).

    Raises:
        CryptoError: Если подпись не удалась.
    """
    if not _is_python_crypto_available():
        raise CryptoNotAvailableError("ECDSA requires 'cryptography' package")

    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, serialization

        private_key = serialization.load_pem_private_key(private_key_pem, password=None)

        signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        return signature

    except ImportError:
        raise CryptoNotAvailableError("cryptography library not installed")
    except Exception as e:
        raise CryptoError(f"ECDSA signing failed: {e}")


def verify_ecdsa(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Проверить ECDSA подпись.

    Args:
        data: Данные.
        signature: Подпись (DER формат).
        public_key_pem: Публичный ключ в PEM формате.

    Returns:
        True если подпись валидна.

    Raises:
        CryptoError: Если проверка не удалась.
    """
    if not _is_python_crypto_available():
        raise CryptoNotAvailableError("ECDSA requires 'cryptography' package")

    try:
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.exceptions import InvalidSignature

        public_key = serialization.load_pem_public_key(public_key_pem)

        try:
            public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            return False

    except ImportError:
        raise CryptoNotAvailableError("cryptography library not installed")
    except Exception as e:
        raise CryptoError(f"ECDSA verification failed: {e}")


# ============================================================================
# УТИЛИТЫ
# ============================================================================


def _validate_key(key: bytes) -> None:
    """Проверить размер ключа."""
    if not key:
        raise InvalidKeyError("Key cannot be empty")
    if len(key) not in (16, 24, 32):
        raise InvalidKeyError(
            f"Key must be 16, 24, or 32 bytes (AES-128/192/256), got {len(key)}"
        )


def secure_erase(data: bytearray) -> None:
    """
    Криптографическое затирание данных в памяти.

    Args:
        data: Данные для затирания (изменяются на месте).
    """
    if data:
        for i in range(len(data)):
            data[i] = 0


def constant_time_equals(a: bytes, b: bytes) -> bool:
    """
    Константное сравнение (защита от timing attacks).

    Args:
        a: Первые данные.
        b: Вторые данные.

    Returns:
        True если равны.
    """
    return hmac.compare_digest(a, b)


# ============================================================================
# ЭКСПОРТ
# ============================================================================

__all__ = [
    # Проверка доступности
    "is_available",
    "is_native_available",
    # AES-GCM
    "encrypt_aes_gcm",
    "decrypt_aes_gcm",
    # Хеширование
    "hash_sha256",
    "hash_sha512",
    "hmac_sha256",
    # Случайные числа
    "generate_random",
    # ECDSA
    "generate_ecdsa_keypair",
    "sign_ecdsa",
    "verify_ecdsa",
    # Утилиты
    "secure_erase",
    "constant_time_equals",
    # Исключения
    "CryptoError",
    "CryptoNotAvailableError",
    "InvalidKeyError",
    "InvalidNonceError",
    "AuthenticationError",
]
