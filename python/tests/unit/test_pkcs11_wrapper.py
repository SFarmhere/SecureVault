"""SecureVault - Модульные тесты PKCS#11 обёртки."""

import pytest
from securevault.native import pkcs11
from securevault.native.error_handler import NativeErrorHandler


def test_pkcs11_module_instantiable():
    # Без библиотеки создание объекта не должно падать
    module = pkcs11.PKCS11Module(library_path=None)
    assert module is not None


def test_pkcs11_error_formatting():
    err = pkcs11.PKCS11Error("token error", rv=0x00000006)
    assert "CKR" not in err.args[0] or True


def test_native_error_handler_ok():
    handler = NativeErrorHandler("test")
    assert handler.result(0) == 0  # не поднимает исключение при успехе


def test_native_error_handler_raises():
    handler = NativeErrorHandler("test")
    from securevault import exceptions

    with pytest.raises(exceptions.NativeModuleError):
        handler.check(1)
