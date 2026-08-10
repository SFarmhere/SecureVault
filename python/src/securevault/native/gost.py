"""SecureVault - Поддержка российских криптоалгоритмов ГОСТ.

Обёртка для ГОСТ 28147-89 (Магма), ГОСТ Р 34.10-2012 (подпись),
ГОСТ Р 34.11-2012 (хеш Streebog) и ГОСТ Р 34.12-2015 (Магма/Кузнечик).

Реализация зависит от нативной библиотеки или стороннего пакета;
при их отсутствии функции выбрасывают NotImplementedError.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Идентификаторы поддерживаемых алгоритмов
ALGORITHMS = {
    "gost28147": "ГОСТ 28147-89 (Магма)",
    "gost3410": "ГОСТ Р 34.10-2012",
    "gost3411": "ГОСТ Р 34.11-2012 (Streebog)",
    "magma": "ГОСТ Р 34.12-2015 Магма",
    "kuznyechik": "ГОСТ Р 34.12-2015 Кузнечик",
}


def is_available() -> bool:
    """Доступна ли реализация ГОСТ (native/сторонний пакет)."""
    try:
        import gostcrypto  # noqa: F401  (сторонний пакет)

        return True
    except ImportError:
        try:
            from securevault.native import get_native_manager

            manager = get_native_manager()
            mode = getattr(manager, "module_info", {}) or {}
            return bool(mode.get("gost", {}).get("available"))
        except Exception:  # noqa: BLE001
            return False


def gost3411_streebog(data: bytes, mode: int = 256) -> bytes:
    """Хеш Streebog (ГОСТ Р 34.11-2012), длина 256/512 бит."""
    if not is_available():
        raise NotImplementedError(
            "GOST R 34.11-2012 requires 'gostcrypto' package or a native module"
        )
    import gostcrypto

    digest = gostcrypto.gosthash.new(f"streebog{mode}", data=data).digest()
    return bytes(digest)


def gost3410_sign(data: bytes, private_key) -> bytes:
    """Подпись ГОСТ Р 34.10-2012."""
    if not is_available():
        raise NotImplementedError(
            "GOST R 34.10-2012 requires 'gostcrypto' package or a native module"
        )
    import gostcrypto

    signer = gostcrypto.gostsignature.new(
        gostcrypto.gostsignature.CURVES_R_1323565281019_2017[
            "id-tc26-gost-3410-12-256"
        ],
        private_key=bytes(private_key),
    )
    return bytes(signer.sign(data))


def supported_algorithms() -> list:
    """Список поддерживаемых алгоритмов."""

    return list(ALGORITHMS.keys())


__all__ = [
    "is_available",
    "gost3411_streebog",
    "gost3410_sign",
    "supported_algorithms",
    "ALGORITHMS",
]
