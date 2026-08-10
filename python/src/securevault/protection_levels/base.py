"""SecureVault - Базовый класс уровней защиты данных.

Определяет контракт для реализаций уровней защиты (ORIGINAL, INDIVIDUAL,
CONTAINER, HYPER). Каждый уровень обязан реализовать методы encrypt/decrypt.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple


class AbstractProtectionLevel(ABC):
    """Абстрактный уровень защиты.

    Контракт: ``encrypt`` возвращает кортеж ``(ciphertext, metadata)``,
    ``decrypt`` возвращает открытый текст.
    """

    #: Человекочитаемое имя уровня
    name: str = "abstract"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r}>"

    @abstractmethod
    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        algorithm: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[bytes, Dict[str, Any]]:
        """Зашифровать открытый текст.

        Args:
            plaintext: Открытые данные.
            key: Криптографический ключ.
            algorithm: Идентификатор алгоритма (опционально).

        Returns:
            Кортеж ``(ciphertext, metadata)``.
        """
        raise NotImplementedError

    @abstractmethod
    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        algorithm: Optional[str] = None,
        **kwargs: Any,
    ) -> bytes:
        """Расшифровать данные.

        Args:
            ciphertext: Зашифрованные данные.
            key: Криптографический ключ.
            algorithm: Идентификатор алгоритма (опционально).

        Returns:
            Открытый текст.
        """
        raise NotImplementedError


__all__ = ["AbstractProtectionLevel"]
