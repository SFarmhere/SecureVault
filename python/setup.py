"""SecureVault - setup.py для сборки и установки python-пакета."""

from pathlib import Path

from setuptools import find_packages, setup

NAME = "securevault"
VERSION = "0.1.0"
DESCRIPTION = (
    "Многоуровневая система криптографической защиты файлов "
    "с аппаратной поддержкой ключей (HSM / USB Token)."
)
ROOT = Path(__file__).resolve().parent


def read_requirements(name: str) -> list:
    """Прочитать список зависимостей из файла requirements."""
    req_file = ROOT / name
    if not req_file.exists():
        return []
    deps = []
    for line in req_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "-r", "-i ", "--")):
            deps.append(line)
    return deps


setup(
    name=NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=(ROOT / ".." / "README.md").read_text(
        encoding="utf-8", errors="ignore"
    ),
    long_description_content_type="text/markdown",
    author="SecureVault Team",
    license="GPL-3.0-or-later",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.9",
    install_requires=read_requirements("requirements-prod.txt"),
    extras_require={
        "dev": read_requirements("requirements-dev.txt"),
        "test": read_requirements("requirements-test.txt"),
    },
    entry_points={
        "console_scripts": [
            "securevault=securevault.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: End Users/Desktop",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
    ],
)
