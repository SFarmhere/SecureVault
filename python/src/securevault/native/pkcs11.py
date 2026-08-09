"""
SecureVault - Python биндинги к PKCS#11 через нативную библиотеку токена

Загружает стандартную PKCS#11 библиотеку (librtpkcs11ecp.so, asepkcs.dll и т.д.)
и вызывает C-функции PKCS#11 API (C_Initialize, C_OpenSession, C_Login и т.д.).

В отличие от C++ модуля securevault_pkcs11 (который использует C++ ABI и pybind11),
этот модуль работает напрямую со стандартным PKCS#11 C API через ctypes.
Это позволяет работать с токенами без сборки C++ модуля.

Использование:
    from securevault.native.pkcs11 import PKCS11Module

    module = PKCS11Module()
    module.initialize("librtpkcs11ecp.so")
    tokens = module.get_available_tokens()
    session = module.open_session(tokens[0].slot_id, "12345678")
    keys = module.list_keys(session)
    module.close_session(session)
"""

import ctypes
import ctypes.util
import logging
import os
import platform
from enum import IntEnum
from typing import Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============================================================================
# ТИПЫ PKCS#11 (C-совместимые)
# ============================================================================

# Базовые типы PKCS#11
CK_ULONG = ctypes.c_ulong
CK_BYTE = ctypes.c_ubyte
CK_BBOOL = ctypes.c_ubyte
CK_RV = CK_ULONG
CK_SESSION_HANDLE = CK_ULONG
CK_OBJECT_HANDLE = CK_ULONG
CK_SLOT_ID = CK_ULONG
CK_KEY_TYPE = CK_ULONG
CK_OBJECT_CLASS = CK_ULONG
CK_MECHANISM_TYPE = CK_ULONG
CK_ATTRIBUTE_TYPE = CK_ULONG
CK_USER_TYPE = CK_ULONG
CK_FLAGS = CK_ULONG
CK_VOID_PTR = ctypes.c_void_p
CK_NOTIFY = ctypes.c_void_p
CK_CHAR = ctypes.c_char
CK_UTF8_CHAR = ctypes.c_char
CK_DATE = ctypes.c_byte * 8


class TokenType(IntEnum):
    """Тип аппаратного токена."""

    UNKNOWN = 0
    RUTOKEN = 1
    ETOKEN = 2
    JA_CARTA = 3
    YUBIKEY = 4
    SOLOKEY = 5
    NITROKEY = 6
    GENERIC_PKCS11 = 7
    PCSC_SMARTCARD = 8


class CKR:
    """Коды возврата PKCS#11."""

    OK = 0
    PIN_INCORRECT = 0x000000A0
    PIN_LOCKED = 0x000000A4
    SESSION_CLOSED = 0x000000B0
    SESSION_HANDLE_INVALID = 0x000000B3
    DEVICE_REMOVED = 0x000000B6
    FUNCTION_NOT_SUPPORTED = 0x00000054
    TOKEN_NOT_PRESENT = 0x00000060
    TOKEN_NOT_RECOGNIZED = 0x00000062
    ARGUMENTS_BAD = 0x00000007
    BUFFER_TOO_SMALL = 0x00000150


class CKU:
    """Типы пользователей PKCS#11."""

    SO = 0  # Security Officer
    USER = 1  # Normal user
    CONTEXT_SPECIFIC = 2


class CKK:
    """Типы ключей PKCS#11."""

    RSA = 0x00000000
    DSA = 0x00000001
    DH = 0x00000002
    EC = 0x00000003
    AES = 0x0000001F
    GOST = 0x00000020  # Нестандартный, для совместимости


class CKO:
    """Классы объектов PKCS#11."""

    DATA = 0x00000000
    CERTIFICATE = 0x00000001
    PUBLIC_KEY = 0x00000002
    PRIVATE_KEY = 0x00000003
    SECRET_KEY = 0x00000004


class CKA:
    """Атрибуты объектов PKCS#11."""

    CLASS = 0x00000000
    TOKEN = 0x00000001
    PRIVATE = 0x00000002
    LABEL = 0x00000003
    KEY_TYPE = 0x00000100
    MODULUS = 0x00000120
    MODULUS_BITS = 0x00000121
    PUBLIC_EXPONENT = 0x00000122
    SIGN = 0x00000108
    VERIFY = 0x0000010A
    ENCRYPT = 0x00000104
    DECRYPT = 0x00000105
    ID = 0x00000102
    EXTRACTABLE = 0x00000162
    SENSITIVE = 0x00000163
    VALUE = 0x00000011
    VALUE_LEN = 0x00000161


class CKF:
    """Флаги PKCS#11."""

    RW_SESSION = 0x00000002
    SERIAL_SESSION = 0x00000004


# ============================================================================
# C-СТРУКТУРЫ PKCS#11
# ============================================================================


class CK_TOKEN_INFO(ctypes.Structure):
    """CK_TOKEN_INFO из PKCS#11 spec."""

    _fields_ = [
        ("label", ctypes.c_char * 32),
        ("manufacturer_id", ctypes.c_char * 32),
        ("model", ctypes.c_char * 16),
        ("serial_number", ctypes.c_char * 16),
        ("flags", CK_ULONG),
        ("ulMaxSessionCount", CK_ULONG),
        ("ulSessionCount", CK_ULONG),
        ("ulMaxRwSessionCount", CK_ULONG),
        ("ulRwSessionCount", CK_ULONG),
        ("ulMaxPinLen", CK_ULONG),
        ("ulMinPinLen", CK_ULONG),
        ("ulTotalPublicMemory", CK_ULONG),
        ("ulFreePublicMemory", CK_ULONG),
        ("ulTotalPrivateMemory", CK_ULONG),
        ("ulFreePrivateMemory", CK_ULONG),
        ("hardwareVersion", CK_BYTE * 2),
        ("firmwareVersion", CK_BYTE * 2),
        ("utcTime", ctypes.c_char * 16),
    ]


class CK_ATTRIBUTE(ctypes.Structure):
    """CK_ATTRIBUTE из PKCS#11 spec."""

    _fields_ = [
        ("type", CK_ATTRIBUTE_TYPE),
        ("pValue", CK_VOID_PTR),
        ("ulValueLen", CK_ULONG),
    ]


class CK_MECHANISM(ctypes.Structure):
    """CK_MECHANISM из PKCS#11 spec."""

    _fields_ = [
        ("mechanism", CK_MECHANISM_TYPE),
        ("pParameter", CK_VOID_PTR),
        ("ulParameterLen", CK_ULONG),
    ]


# ============================================================================
# PYTHON-ОБЕРТКИ
# ============================================================================


class TokenInfo:
    """Информация о токене."""

    TOKEN_FLAGS = {
        0x00000001: "TOKEN_PRESENT",
        0x00000002: "TOKEN_INITIALIZED",
        0x00000004: "USER_PIN_SET",
        0x00000008: "USER_PIN_COUNT_LOW",
        0x00000010: "USER_PIN_FINAL_TRY",
        0x00000020: "USER_PIN_LOCKED",
        0x00000040: "USER_PIN_TO_BE_CHANGED",
        0x00000080: "SO_PIN_SET",
        0x00000100: "SO_PIN_COUNT_LOW",
        0x00000200: "SO_PIN_FINAL_TRY",
        0x00000400: "SO_PIN_LOCKED",
        0x00000800: "SO_PIN_TO_BE_CHANGED",
    }

    def __init__(self, c_info: CK_TOKEN_INFO, slot_id: int):
        self.slot_id = slot_id
        self.label = (
            c_info.label.decode("utf-8", errors="replace").strip("\x00").strip()
        )
        self.manufacturer_id = (
            c_info.manufacturer_id.decode("utf-8", errors="replace")
            .strip("\x00")
            .strip()
        )
        self.model = (
            c_info.model.decode("utf-8", errors="replace").strip("\x00").strip()
        )
        self.serial_number = (
            c_info.serial_number.decode("utf-8", errors="replace").strip("\x00").strip()
        )
        self.flags = c_info.flags
        self.max_session_count = c_info.ulMaxSessionCount
        self.session_count = c_info.ulSessionCount
        self.max_pin_len = c_info.ulMaxPinLen
        self.min_pin_len = c_info.ulMinPinLen
        self.total_public_memory = c_info.ulTotalPublicMemory
        self.free_public_memory = c_info.ulFreePublicMemory
        self.total_private_memory = c_info.ulTotalPrivateMemory
        self.free_private_memory = c_info.ulFreePrivateMemory

    def is_initialized(self) -> bool:
        return bool(self.flags & 0x00000002)

    def is_user_pin_set(self) -> bool:
        return bool(self.flags & 0x00000004)

    def is_user_pin_locked(self) -> bool:
        return bool(self.flags & 0x00000020)

    def __repr__(self) -> str:
        return (
            f"TokenInfo(slot={self.slot_id}, label={self.label!r}, "
            f"manufacturer={self.manufacturer_id!r}, serial={self.serial_number!r})"
        )


class KeyInfo:
    """Информация о ключе на токене."""

    def __init__(
        self, handle: int, key_id: bytes, label: str, key_type: int, size_bits: int
    ):
        self.handle = handle
        self.key_id = key_id.hex() if key_id else ""
        self.label = label
        self.key_type = key_type
        self.size_bits = size_bits

    def __repr__(self) -> str:
        type_name = {0: "RSA", 1: "DSA", 2: "DH", 3: "EC", 0x1F: "AES"}.get(
            self.key_type, f"UNKNOWN({self.key_type})"
        )
        return (
            f"KeyInfo(handle={self.handle}, id={self.key_id!r}, "
            f"label={self.label!r}, type={type_name}, size={self.size_bits})"
        )


# ============================================================================
# ИСКЛЮЧЕНИЯ
# ============================================================================


class PKCS11Error(Exception):
    """Базовое исключение для ошибок PKCS#11."""

    ERROR_NAMES = {
        CKR.PIN_INCORRECT: "CKR_PIN_INCORRECT",
        CKR.PIN_LOCKED: "CKR_PIN_LOCKED",
        CKR.SESSION_CLOSED: "CKR_SESSION_CLOSED",
        CKR.SESSION_HANDLE_INVALID: "CKR_SESSION_HANDLE_INVALID",
        CKR.DEVICE_REMOVED: "CKR_DEVICE_REMOVED",
        CKR.FUNCTION_NOT_SUPPORTED: "CKR_FUNCTION_NOT_SUPPORTED",
        CKR.TOKEN_NOT_PRESENT: "CKR_TOKEN_NOT_PRESENT",
        CKR.ARGUMENTS_BAD: "CKR_ARGUMENTS_BAD",
        CKR.BUFFER_TOO_SMALL: "CKR_BUFFER_TOO_SMALL",
    }

    def __init__(self, message: str, rv: int = 0):
        self.rv = rv
        name = self.ERROR_NAMES.get(rv, f"CKR_0x{rv:08X}")
        super().__init__(f"[{name}] {message}")


class PinError(PKCS11Error):
    """Ошибка PIN-кода."""


class SessionError(PKCS11Error):
    """Ошибка сессии."""


class TokenNotFoundError(PKCS11Error):
    """Токен не найден."""


# ============================================================================
# ОСНОВНОЙ КЛАСС
# ============================================================================


class PKCS11Module:
    """
    Python-обертка для стандартного PKCS#11 C API через ctypes.

    Загружает нативную PKCS#11 библиотеку токена (например, librtpkcs11ecp.so)
    и вызывает C-функции: C_Initialize, C_GetSlotList, C_OpenSession, C_Login и т.д.

    Пример:
        module = PKCS11Module()
        module.initialize("/usr/lib/librtpkcs11ecp.so")
        tokens = module.get_available_tokens()
        if tokens:
            session = module.open_session(0, "12345678")
            keys = module.list_keys(session)
            module.close_session(session)
    """

    # Стандартные имена PKCS#11 библиотек по платформам
    LIB_NAMES = {
        "linux": [
            "librtpkcs11ecp.so",  # Рутокен
            "libasepkcs.so",  # eToken
            "libjcPKCS11.so",  # JaCarta
            "libykcs11.so",  # YubiKey
            "libopensc-pkcs11.so",  # OpenSC
            "libP11.so",  # Generic
        ],
        "windows": [
            "rtpkcs11ecp.dll",  # Рутокен
            "asepkcs.dll",  # eToken
            "jcPKCS11.dll",  # JaCarta
            "ykcs11.dll",  # YubiKey
            "opensc-pkcs11.dll",  # OpenSC
        ],
        "darwin": [
            "librtpkcs11ecp.dylib",
            "libykcs11.dylib",
        ],
    }

    def __init__(self, library_path: Optional[str] = None):
        self._lib: Optional[ctypes.CDLL] = None
        self._library_path: Optional[str] = library_path
        self._initialized: bool = False
        self._functions: Dict[str, Callable] = {}

    # ------------------------------------------------------------------------
    # ЗАГРУЗКА БИБЛИОТЕКИ
    # ------------------------------------------------------------------------

    def _find_library(self) -> Optional[str]:
        """Найти PKCS#11 библиотеку в системе."""
        if self._library_path:
            if os.path.exists(self._library_path):
                return os.path.abspath(self._library_path)

        system = platform.system().lower()
        if system == "windows":
            system = "windows"
        elif system == "darwin":
            system = "darwin"
        else:
            system = "linux"

        for lib_name in self.LIB_NAMES.get(system, []):
            found = ctypes.util.find_library(lib_name)
            if found:
                return found
            if os.path.exists(lib_name):
                return os.path.abspath(lib_name)
            # Поиск в стандартных директориях
            for d in [
                "/usr/lib",
                "/usr/lib64",
                "/usr/local/lib",
                "/opt/homebrew/lib",
                "C:\\Windows\\System32",
            ]:
                p = os.path.join(d, lib_name)
                if os.path.exists(p):
                    return p

        return None

    def _load_library(self) -> None:
        """Загрузить PKCS#11 библиотеку."""
        lib_path = self._find_library()
        if not lib_path:
            raise PKCS11Error(
                "PKCS#11 library not found. Specify library_path or install "
                "a PKCS#11 driver for your token."
            )
        try:
            self._lib = ctypes.cdll.LoadLibrary(lib_path)
            self._library_path = lib_path
            logger.info(f"Loaded PKCS#11 library: {lib_path}")
        except OSError as e:
            raise PKCS11Error(f"Failed to load library {lib_path}: {e}")

    def _get_function(self, name: str, argtypes: List, restype) -> Callable:
        """Получить C-функцию из библиотеки."""
        try:
            func = getattr(self._lib, name)
            func.argtypes = argtypes
            func.restype = restype
            self._functions[name] = func
            return func
        except AttributeError:
            raise PKCS11Error(f"PKCS#11 function {name} not found in library")

    # ------------------------------------------------------------------------
    # ИНИЦИАЛИЗАЦИЯ
    # ------------------------------------------------------------------------

    def initialize(self, library_path: Optional[str] = None) -> None:
        """
        Инициализировать PKCS#11 модуль.

        Args:
            library_path: Путь к PKCS#11 библиотеке токена.
                          Например: librtpkcs11ecp.so (Рутокен),
                          asepkcs.dll (eToken).

        Raises:
            PKCS11Error: Если инициализация не удалась.
        """
        if self._initialized:
            return

        if library_path:
            self._library_path = library_path

        self._load_library()

        # Загружаем функции PKCS#11 C API напрямую по именам
        self._C_Initialize = self._get_function("C_Initialize", [CK_VOID_PTR], CK_RV)
        self._C_Finalize = self._get_function("C_Finalize", [CK_VOID_PTR], CK_RV)
        self._C_GetSlotList = self._get_function(
            "C_GetSlotList",
            [CK_BBOOL, ctypes.POINTER(CK_SLOT_ID), ctypes.POINTER(CK_ULONG)],
            CK_RV,
        )
        self._C_GetTokenInfo = self._get_function(
            "C_GetTokenInfo",
            [CK_SLOT_ID, ctypes.POINTER(CK_TOKEN_INFO)],
            CK_RV,
        )
        self._C_OpenSession = self._get_function(
            "C_OpenSession",
            [
                CK_SLOT_ID,
                CK_FLAGS,
                CK_VOID_PTR,
                CK_NOTIFY,
                ctypes.POINTER(CK_SESSION_HANDLE),
            ],
            CK_RV,
        )
        self._C_CloseSession = self._get_function(
            "C_CloseSession", [CK_SESSION_HANDLE], CK_RV
        )
        self._C_Login = self._get_function(
            "C_Login",
            [CK_SESSION_HANDLE, CK_USER_TYPE, CK_VOID_PTR, CK_ULONG],
            CK_RV,
        )
        self._C_Logout = self._get_function("C_Logout", [CK_SESSION_HANDLE], CK_RV)
        self._C_FindObjectsInit = self._get_function(
            "C_FindObjectsInit",
            [CK_SESSION_HANDLE, ctypes.POINTER(CK_ATTRIBUTE), CK_ULONG],
            CK_RV,
        )
        self._C_FindObjects = self._get_function(
            "C_FindObjects",
            [
                CK_SESSION_HANDLE,
                ctypes.POINTER(CK_OBJECT_HANDLE),
                CK_ULONG,
                ctypes.POINTER(CK_ULONG),
            ],
            CK_RV,
        )
        self._C_FindObjectsFinal = self._get_function(
            "C_FindObjectsFinal", [CK_SESSION_HANDLE], CK_RV
        )
        self._C_GetAttributeValue = self._get_function(
            "C_GetAttributeValue",
            [
                CK_SESSION_HANDLE,
                CK_OBJECT_HANDLE,
                ctypes.POINTER(CK_ATTRIBUTE),
                CK_ULONG,
            ],
            CK_RV,
        )

        # Инициализация
        rv = self._C_Initialize(None)
        if rv != CKR.OK:
            if rv == 0x00000003:  # CKR_ALREADY_INITIALIZED
                self._initialized = True
                return
            raise PKCS11Error("C_Initialize failed", rv)

        self._initialized = True
        logger.info(f"PKCS#11 module initialized: {self._library_path}")

    def finalize(self) -> None:
        """Завершить работу с PKCS#11 модулем."""
        if self._lib and self._initialized:
            self._C_Finalize(None)
            self._initialized = False
            logger.info("PKCS#11 module finalized")

    # ------------------------------------------------------------------------
    # РАБОТА С ТОКЕНАМИ
    # ------------------------------------------------------------------------

    def get_available_tokens(self) -> List[TokenInfo]:
        """
        Получить список доступных токенов через C_GetSlotList.

        Returns:
            Список TokenInfo.
        """
        if not self._initialized:
            raise PKCS11Error("Module not initialized")

        # Получаем количество слотов с токенами
        slot_count = CK_ULONG(0)
        rv = self._C_GetSlotList(CK_BBOOL(1), None, ctypes.byref(slot_count))
        if rv != CKR.OK:
            raise PKCS11Error("C_GetSlotList failed", rv)

        if slot_count.value == 0:
            return []

        # Получаем список слотов
        slots = (CK_SLOT_ID * slot_count.value)()
        rv = self._C_GetSlotList(CK_BBOOL(1), slots, ctypes.byref(slot_count))
        if rv != CKR.OK:
            raise PKCS11Error("C_GetSlotList failed", rv)

        # Получаем информацию о каждом токене
        tokens = []
        for i in range(slot_count.value):
            slot_id = slots[i]
            token_info = CK_TOKEN_INFO()
            rv = self._C_GetTokenInfo(slot_id, ctypes.byref(token_info))
            if rv == CKR.OK:
                tokens.append(TokenInfo(token_info, slot_id))

        return tokens

    def open_session(self, slot_id: int, pin: str) -> int:
        """
        Открыть сессию на токене.

        Args:
            slot_id: ID слота (из get_available_tokens).
            pin: PIN-код пользователя.

        Returns:
            CK_SESSION_HANDLE (положительное число).

        Raises:
            PinError: Если PIN неверный или заблокирован.
        """
        if not self._initialized:
            raise PKCS11Error("Module not initialized")

        # Открываем сессию
        session = CK_SESSION_HANDLE(0)
        rv = self._C_OpenSession(
            CK_SLOT_ID(slot_id),
            CK_FLAGS(CKF.RW_SESSION | CKF.SERIAL_SESSION),
            None,
            None,
            ctypes.byref(session),
        )
        if rv != CKR.OK:
            raise SessionError("C_OpenSession failed", rv)

        # Логинимся
        rv = self._C_Login(
            session,
            CK_USER_TYPE(CKU.USER),
            ctypes.c_char_p(pin.encode()),
            CK_ULONG(len(pin)),
        )
        if rv != CKR.OK:
            self._C_CloseSession(session)
            if rv == CKR.PIN_INCORRECT or rv == CKR.PIN_LOCKED:
                raise PinError("C_Login failed", rv)
            raise PKCS11Error("C_Login failed", rv)

        logger.info(f"Session opened: {session.value}")
        return session.value

    def close_session(self, session_id: int) -> None:
        """Закрыть сессию."""
        if not self._initialized:
            return
        self._C_CloseSession(CK_SESSION_HANDLE(session_id))
        logger.info(f"Session closed: {session_id}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.finalize()

    # ------------------------------------------------------------------------
    # РАБОТА С КЛЮЧАМИ
    # ------------------------------------------------------------------------

    def list_keys(self, session_id: int) -> List[KeyInfo]:
        """
        Получить список приватных ключей на токене.

        Args:
            session_id: ID сессии.

        Returns:
            Список KeyInfo.
        """
        if not self._initialized:
            raise PKCS11Error("Module not initialized")

        session = CK_SESSION_HANDLE(session_id)

        # Ищем все приватные ключи
        key_class = CK_OBJECT_CLASS(CKO.PRIVATE_KEY)
        attr = CK_ATTRIBUTE(
            CKA.CLASS, ctypes.byref(key_class), ctypes.sizeof(key_class)
        )

        rv = self._C_FindObjectsInit(session, ctypes.byref(attr), 1)
        if rv != CKR.OK:
            raise PKCS11Error("C_FindObjectsInit failed", rv)

        keys = []
        max_objects = 64
        objects = (CK_OBJECT_HANDLE * max_objects)()
        obj_count = CK_ULONG(0)

        while True:
            rv = self._C_FindObjects(
                session, objects, max_objects, ctypes.byref(obj_count)
            )
            if rv != CKR.OK or obj_count.value == 0:
                break

            for i in range(obj_count.value):
                handle = objects[i]
                key_info = self._get_key_attributes(session, handle)
                if key_info:
                    keys.append(key_info)

        self._C_FindObjectsFinal(session)
        return keys

    def _get_key_attributes(self, session: int, handle: int) -> Optional[KeyInfo]:
        """Получить атрибуты ключа."""
        # Первый проход: получаем размеры буферов
        id_attr = CK_ATTRIBUTE(CKA.ID, None, 0)
        label_attr = CK_ATTRIBUTE(CKA.LABEL, None, 0)
        key_type = CK_KEY_TYPE(0)
        type_attr = CK_ATTRIBUTE(
            CKA.KEY_TYPE, ctypes.byref(key_type), ctypes.sizeof(key_type)
        )
        modulus_bits = CK_ULONG(0)
        bits_attr = CK_ATTRIBUTE(
            CKA.MODULUS_BITS, ctypes.byref(modulus_bits), ctypes.sizeof(modulus_bits)
        )

        size_attrs = (CK_ATTRIBUTE * 4)()
        size_attrs[0] = id_attr
        size_attrs[1] = label_attr
        size_attrs[2] = type_attr
        size_attrs[3] = bits_attr

        rv = self._C_GetAttributeValue(session, handle, size_attrs, 4)
        if rv != CKR.OK and rv != CKR.BUFFER_TOO_SMALL:
            return None

        # Второй проход: получаем данные
        id_buf = (
            ctypes.create_string_buffer(size_attrs[0].ulValueLen)
            if size_attrs[0].ulValueLen > 0
            else ctypes.create_string_buffer(1)
        )
        size_attrs[0].pValue = ctypes.cast(id_buf, CK_VOID_PTR)
        size_attrs[0].ulValueLen = len(id_buf)

        label_buf = (
            ctypes.create_string_buffer(size_attrs[1].ulValueLen)
            if size_attrs[1].ulValueLen > 0
            else ctypes.create_string_buffer(1)
        )
        size_attrs[1].pValue = ctypes.cast(label_buf, CK_VOID_PTR)
        size_attrs[1].ulValueLen = len(label_buf)

        rv = self._C_GetAttributeValue(session, handle, size_attrs, 4)
        if rv != CKR.OK:
            return None

        # Извлекаем значения
        actual_id_len = size_attrs[0].ulValueLen
        key_id = bytes(id_buf)[:actual_id_len] if actual_id_len > 0 else b""

        actual_label_len = size_attrs[1].ulValueLen
        label = ""
        if actual_label_len > 0:
            raw_label = bytes(label_buf)[:actual_label_len]
            label = raw_label.decode("utf-8", errors="replace").strip("\x00")

        return KeyInfo(
            handle=handle,
            key_id=key_id,
            label=label,
            key_type=key_type.value,
            size_bits=modulus_bits.value,
        )

    # ------------------------------------------------------------------------
    # УТИЛИТЫ
    # ------------------------------------------------------------------------

    @property
    def is_initialized(self) -> bool:
        return self._initialized

    @property
    def library_path(self) -> Optional[str]:
        return self._library_path


# ============================================================================
# ФУНКЦИИ ВЫСОКОГО УРОВНЯ
# ============================================================================


def detect_token_type(library_path: str) -> TokenType:
    """Определить тип токена по пути к библиотеке."""
    path_lower = library_path.lower()
    if "rutoken" in path_lower or "rtpkcs11" in path_lower:
        return TokenType.RUTOKEN
    if "etoken" in path_lower or "asepkcs" in path_lower:
        return TokenType.ETOKEN
    if "jacarta" in path_lower or "jcPKCS11" in path_lower:
        return TokenType.JA_CARTA
    if "yubico" in path_lower or "yubikey" in path_lower or "ykcs11" in path_lower:
        return TokenType.YUBIKEY
    if "opensc" in path_lower or "pcsclite" in path_lower:
        return TokenType.PCSC_SMARTCARD
    return TokenType.GENERIC_PKCS11


def list_available_tokens(library_path: Optional[str] = None) -> List[TokenInfo]:
    """Быстрое получение списка токенов."""
    with PKCS11Module(library_path) as module:
        module.initialize()
        return module.get_available_tokens()
