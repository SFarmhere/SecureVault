"""
SecureVault - многоуровневая система криптографической защиты файлов.

Пакет верхнего уровня. Точка входа для python-бэкенда.

Основные возможности:
- 4 уровня защиты данных (ORIGINAL, INDIVIDUAL, CONTAINER, HYPER)
- Аппаратная поддержка ключей (PKCS#11 / HSM / USB-токен)
- Аудит-инфраструктура (ECDSA-подпись, hash chain, forensic логирование)
- Виртуальные контейнеры с дедупликацией и скрытыми томами
"""

from securevault import constants, exceptions  # noqa: F401
from securevault.version import (  # noqa: F401
    __version__,
    check_python_version,
    get_version,
    version_info,
)

__title__ = "SecureVault"
__author__ = "SecureVault Team"
__license__ = "GPL-3.0-or-later"

# Повторный экспорт базовых типов для удобства пользователей
from securevault.constants import ProtectionLevel  # noqa: E402

__all__ = [
    "constants",
    "exceptions",
    "ProtectionLevel",
    "__version__",
    "get_version",
    "version_info",
    "check_python_version",
]
