"""SecureVault - Информация о версии.

Централизованное место для версионирования проекта.
Значение версии импортируется в пакет securevault/__init__.py
и используется в CLI, API и метаданных.
"""

# Каноническая строка версии (SemVer)
__version__ = "0.1.0"

# Версия в виде кортежа для программного сравнения
VERSION = (0, 1, 0)

# Уровень зрелости: alpha | beta | rc | stable
RELEASE_STATUS = "alpha"

# Минимальная требуемая версия Python
MIN_PYTHON = (3, 9)

# Кодовое имя релиза
CODENAME = "Umbra"

# Отметка сборки (заполняется CI при необходимости)
BUILD = ""


def get_version() -> str:
    """Вернуть строку версии с учётом статуса релиза.

    Returns:
        Строка вида ``0.1.0-alpha``.
    """
    base = __version__
    if RELEASE_STATUS not in ("stable", ""):
        base = f"{base}-{RELEASE_STATUS}"
    return base


def version_info() -> dict:
    """Вернуть полную информацию о версии в виде словаря."""
    return {
        "version": __version__,
        "tuple": VERSION,
        "status": RELEASE_STATUS,
        "codename": CODENAME,
        "build": BUILD,
        "display": get_version(),
    }


def check_python_version() -> bool:
    """Проверить, что текущий интерпретатор соответствует минимальному."""
    import sys

    return sys.version_info >= MIN_PYTHON


__all__ = [
    "__version__",
    "VERSION",
    "RELEASE_STATUS",
    "MIN_PYTHON",
    "CODENAME",
    "BUILD",
    "get_version",
    "version_info",
    "check_python_version",
]
