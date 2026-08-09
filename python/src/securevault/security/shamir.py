"""
SecureVault - Shamir Secret Sharing (3-of-5)

Реализация схемы разделения секрета Шамира (Shamir's Secret Sharing).
Позволяет разделить мастер-ключ на N частей (shares), из которых
достаточно K частей для восстановления (K-of-N).

В SecureVault используется схема 3-of-5:
- 5 shares распределяются между доверенными лицами/устройствами
- Любые 3 shares позволяют восстановить мастер-ключ
- Потеря 2 shares не компрометирует безопасность

Использование:
    from securevault.security.shamir import ShamirSecretSharing

    sss = ShamirSecretSharing()

    # Разделение секрета
    master_key = b"my-secret-key-32-bytes-long!!"
    shares = sss.split(master_key, total=5, threshold=3)

    # Восстановление
    recovered = sss.join(shares[:3])
    assert recovered == master_key
"""

import hashlib
import hmac
import os
from typing import List, Optional, Tuple

# Размер поля GF(256) - используем простой модуль 257
# (простое число, ближайшее к 256)
_PRIME = 257


class ShamirError(Exception):
    """Базовое исключение для Shamir Secret Sharing."""


class InvalidShareError(ShamirError):
    """Невалидная часть секрета."""


class InsufficientSharesError(ShamirError):
    """Недостаточно частей для восстановления."""


class Share:
    """
    Одна часть разделенного секрета (share).

    Содержит:
    - index: номер части (1..N)
    - value: значение части (байты той же длины, что и секрет)
    - checksum: контрольная сумма для проверки целостности
    """

    HEADER = b"SVSS"  # SecureVault Shamir Secret
    VERSION = 1

    def __init__(self, index: int, value: bytes, checksum: Optional[bytes] = None):
        if index < 1 or index > 255:
            raise InvalidShareError(f"Share index must be 1..255, got {index}")
        self.index = index
        self.value = value
        self.checksum = checksum or self._compute_checksum()

    def _compute_checksum(self) -> bytes:
        """Вычислить контрольную сумму для проверки целостности."""
        data = bytes([self.index]) + self.value
        return hashlib.sha256(data).digest()[:4]

    def verify(self) -> bool:
        """Проверить целостность части."""
        return self.checksum == self._compute_checksum()

    def serialize(self) -> bytes:
        """
        Сериализовать часть в бинарный формат.

        Формат:
        [4 байта] HEADER "SVSS"
        [1 байт]  VERSION
        [1 байт]  INDEX (1..255)
        [2 байта] VALUE_LENGTH (big-endian)
        [N байт]  VALUE
        [4 байта] CHECKSUM (SHA256 первых 4 байт)
        """
        value_len = len(self.value)
        data = (
            self.HEADER
            + bytes([self.VERSION])
            + bytes([self.index])
            + value_len.to_bytes(2, "big")
            + self.value
            + self.checksum
        )
        return data

    @staticmethod
    def deserialize(data: bytes) -> "Share":
        """
        Десериализовать часть из бинарного формата.

        Args:
            data: Бинарные данные части.

        Returns:
            Объект Share.

        Raises:
            InvalidShareError: Если формат невалиден.
        """
        if len(data) < 12:
            raise InvalidShareError(f"Share data too short: {len(data)} bytes")

        if data[:4] != Share.HEADER:
            raise InvalidShareError(f"Invalid header: {data[:4]!r}")

        version = data[4]
        if version != Share.VERSION:
            raise InvalidShareError(f"Unsupported version: {version}")

        index = data[5]
        value_len = int.from_bytes(data[6:8], "big")

        if len(data) < 8 + value_len + 4:
            raise InvalidShareError(
                f"Share data too short for value length {value_len}"
            )

        value = data[8 : 8 + value_len]
        checksum = data[8 + value_len : 8 + value_len + 4]

        share = Share(index, value, checksum)
        if not share.verify():
            raise InvalidShareError("Checksum mismatch - share data corrupted")

        return share

    def __repr__(self) -> str:
        return f"Share(index={self.index}, value_len={len(self.value)}, valid={self.verify()})"


class ShamirSecretSharing:
    """
    Реализация схемы разделения секрета Шамира над GF(256).

    Использует полином степени K-1 (где K = threshold) над полем GF(257).
    Коэффициенты полинома выбираются случайно, свободный член = секрет.

    Пример:
        sss = ShamirSecretSharing()

        # Разделить секрет на 5 частей, нужно 3 для восстановления
        shares = sss.split(b"secret-key-here", total=5, threshold=3)

        # Восстановить из любых 3 частей
        recovered = sss.join(shares[:3])
    """

    # ------------------------------------------------------------------------
    # ПОЛЕ GF(257) - АРИФМЕТИКА НАД ПРОСТЫМ ПОЛЕМ
    # ------------------------------------------------------------------------

    @staticmethod
    def _mod(x: int) -> int:
        """Привести число к полю GF(257)."""
        return x % _PRIME

    @staticmethod
    def _add(a: int, b: int) -> int:
        """Сложение в GF(257)."""
        return (a + b) % _PRIME

    @staticmethod
    def _sub(a: int, b: int) -> int:
        """Вычитание в GF(257)."""
        return (a - b) % _PRIME

    @staticmethod
    def _mul(a: int, b: int) -> int:
        """Умножение в GF(257)."""
        return (a * b) % _PRIME

    @staticmethod
    def _inv(a: int) -> int:
        """
        Обратный элемент в GF(257) через расширенный алгоритм Евклида.

        Args:
            a: Число в поле GF(257), a != 0.

        Returns:
            a^(-1) mod 257.
        """
        if a == 0:
            raise ZeroDivisionError("Cannot invert zero in GF(257)")

        # extended Euclidean algorithm
        t, new_t = 0, 1
        r, new_r = _PRIME, a

        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t - quotient * new_t
            r, new_r = new_r, r - quotient * new_r

        if r > 1:
            raise ValueError(f"{a} is not invertible in GF(257)")

        return t % _PRIME

    @staticmethod
    def _eval_poly(coefficients: List[int], x: int) -> int:
        """
        Вычислить значение полинома в точке x по схеме Горнера.

        poly(x) = c0 + c1*x + c2*x^2 + ... + ck*x^k

        Args:
            coefficients: Коэффициенты полинома [c0, c1, ..., ck].
            x: Точка, в которой вычисляем.

        Returns:
            Значение полинома в точке x.
        """
        result = 0
        for coeff in reversed(coefficients):
            result = ShamirSecretSharing._add(
                ShamirSecretSharing._mul(result, x), coeff
            )
        return result

    @staticmethod
    def _lagrange_interpolate(points: List[Tuple[int, int]], x: int) -> int:
        """
        Интерполяция Лагранжа для восстановления значения полинома в точке x.

        L(x) = sum(y_j * product((x - x_m) / (x_j - x_m) for m != j))

        Args:
            points: Список точек [(x1, y1), (x2, y2), ...].
            x: Точка, в которой восстанавливаем значение.

        Returns:
            Значение полинома в точке x.
        """
        result = 0
        n = len(points)

        for i in range(n):
            xi, yi = points[i]

            numerator = 1
            denominator = 1

            for j in range(n):
                if i == j:
                    continue
                xj = points[j][0]

                numerator = ShamirSecretSharing._mul(
                    numerator, ShamirSecretSharing._sub(x, xj)
                )
                denominator = ShamirSecretSharing._mul(
                    denominator, ShamirSecretSharing._sub(xi, xj)
                )

            # Li(x) = numerator / denominator
            li = ShamirSecretSharing._mul(
                numerator, ShamirSecretSharing._inv(denominator)
            )

            result = ShamirSecretSharing._add(result, ShamirSecretSharing._mul(yi, li))

        return result

    # ------------------------------------------------------------------------
    # ПУБЛИЧНЫЕ МЕТОДЫ
    # ------------------------------------------------------------------------

    def split(self, secret: bytes, total: int = 5, threshold: int = 3) -> List[Share]:
        """
        Разделить секрет на N частей, K из которых нужны для восстановления.

        Алгоритм:
        1. Для каждого байта секрета создаем полином степени K-1
        2. Свободный член полинома = байт секрета
        3. Остальные K-1 коэффициентов - случайные числа в GF(257)
        4. Вычисляем значение полинома в N точках (x = 1..N)
        5. Каждая часть = набор значений для всех байтов секрета

        Args:
            secret: Секрет для разделения (любые байты).
            total: Общее количество частей (N). По умолчанию 5.
            threshold: Минимальное количество частей для восстановления (K).
                       По умолчанию 3.

        Returns:
            Список из N объектов Share.

        Raises:
            ValueError: Если threshold > total или threshold < 2.
        """
        if threshold > total:
            raise ValueError(f"Threshold ({threshold}) cannot exceed total ({total})")
        if threshold < 2:
            raise ValueError(f"Threshold must be at least 2, got {threshold}")
        if total > 255:
            raise ValueError(f"Total cannot exceed 255, got {total}")
        if not secret:
            raise ValueError("Secret cannot be empty")

        secret_len = len(secret)
        shares: List[List[int]] = [[] for _ in range(total)]

        # Для каждого байта секрета создаем полином
        for byte_idx in range(secret_len):
            secret_byte = secret[byte_idx]

            # Генерируем случайные коэффициенты для полинома степени K-1
            # coeffs[0] = секретный байт (свободный член)
            coeffs = [secret_byte] + [os.urandom(1)[0] for _ in range(threshold - 1)]

            # Вычисляем значение полинома в точках x = 1..total
            for share_idx in range(total):
                x = share_idx + 1  # x = 1, 2, ..., total
                y = self._eval_poly(coeffs, x)
                shares[share_idx].append(y)

        # Создаем объекты Share
        result = []
        for i in range(total):
            value = bytes(shares[i])
            result.append(Share(i + 1, value))

        return result

    def join(self, shares: List[Share]) -> bytes:
        """
        Восстановить секрет из K (или более) частей.

        Алгоритм:
        1. Для каждой позиции байта применяем интерполяцию Лагранжа
        2. Восстанавливаем свободный член полинома (секретный байт)
        3. Собираем все байты в исходный секрет

        Args:
            shares: Список объектов Share (минимум threshold штук).

        Returns:
            Восстановленный секрет.

        Raises:
            InsufficientSharesError: Если shares меньше 2.
            InvalidShareError: Если какая-то часть повреждена.
        """
        if len(shares) < 2:
            raise InsufficientSharesError(
                f"Need at least 2 shares to recover, got {len(shares)}"
            )

        # Проверяем целостность всех частей
        for share in shares:
            if not share.verify():
                raise InvalidShareError(
                    f"Share {share.index} failed checksum verification"
                )

        # Проверяем, что все части одной длины
        value_lengths = {len(s.value) for s in shares}
        if len(value_lengths) != 1:
            raise InvalidShareError("All shares must have the same value length")

        secret_len = len(shares[0].value)

        # Восстанавливаем секрет побайтово через интерполяцию Лагранжа
        recovered = bytearray()
        for byte_idx in range(secret_len):
            # Собираем точки (x, y) для текущего байта
            points = []
            for share in shares:
                x = share.index
                y = share.value[byte_idx]
                points.append((x, y))

            # Восстанавливаем значение в точке x=0 (свободный член)
            secret_byte = self._lagrange_interpolate(points, 0)
            recovered.append(secret_byte)

        return bytes(recovered)

    # ------------------------------------------------------------------------
    # УТИЛИТЫ
    # ------------------------------------------------------------------------

    @staticmethod
    def generate_master_key(size: int = 32) -> bytes:
        """
        Сгенерировать криптостойкий мастер-ключ.

        Args:
            size: Размер ключа в байтах. По умолчанию 32 (AES-256).

        Returns:
            Случайный ключ.
        """
        return os.urandom(size)

    @staticmethod
    def verify_recovery(shares: List[Share], original_secret: bytes) -> bool:
        """
        Проверить, что из shares восстанавливается исходный секрет.

        Args:
            shares: Список частей.
            original_secret: Исходный секрет для сравнения.

        Returns:
            True если восстановление успешно.
        """
        try:
            sss = ShamirSecretSharing()
            recovered = sss.join(shares)
            return hmac.compare_digest(recovered, original_secret)
        except Exception:
            return False


# ============================================================================
# ФУНКЦИИ ВЫСОКОГО УРОВНЯ
# ============================================================================


def split_secret(secret: bytes, total: int = 5, threshold: int = 3) -> List[bytes]:
    """
    Разделить секрет и вернуть сериализованные части.

    Args:
        secret: Секрет для разделения.
        total: Общее количество частей.
        threshold: Минимальное количество для восстановления.

    Returns:
        Список сериализованных байтовых строк.
    """
    sss = ShamirSecretSharing()
    shares = sss.split(secret, total, threshold)
    return [s.serialize() for s in shares]


def join_shares(serialized_shares: List[bytes]) -> bytes:
    """
    Восстановить секрет из сериализованных частей.

    Args:
        serialized_shares: Список сериализованных частей.

    Returns:
        Восстановленный секрет.
    """
    shares = [Share.deserialize(s) for s in serialized_shares]
    sss = ShamirSecretSharing()
    return sss.join(shares)
