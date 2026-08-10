"""SecureVault - Корневая конфигурация pytest.

Настраивает sys.path так, чтобы пакет ``securevault`` (src) и подпакет
``fixtures`` были импортируемы из любых тестов.
"""

from __future__ import annotations

import sys
from pathlib import Path

# python/tests
TESTS_ROOT = Path(__file__).resolve().parent
# python/src
SRC = TESTS_ROOT.parent / "src"

for _path in (str(SRC), str(TESTS_ROOT)):
    if _path not in sys.path:
        sys.path.insert(0, _path)
