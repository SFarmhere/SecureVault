"""SecureVault - Модульные тесты нативного модуля ГОСТ."""

import pytest
from securevault.native import gost


def test_supported_algorithms():
    algs = gost.supported_algorithms()
    assert "gost3411" in algs
    assert "kuznyechik" in algs


def test_is_available():
    # В тестовом окружении без gostcrypto/native реализация недоступна
    assert isinstance(gost.is_available(), bool)


def test_streebog_raises_without_backend():
    if gost.is_available():
        pytest.skip("GOST backend available")
    with pytest.raises(NotImplementedError):
        gost.gost3411_streebog(b"data")
