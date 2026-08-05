"""
SecureVault - Нативные модули

Централизованная инициализация и управление нативными C++ модулями:
- crypto: Криптографические операции (AES-GCM, SHA256, etc.)
- container: Операции с контейнерами
- pkcs11: Взаимодействие с HSM/USB токенами

Этот модуль предоставляет единый интерфейс для доступа ко всем
нативным модулям с автоматической загрузкой и обработкой ошибок.

Архитектура:
1. Ленивая загрузка модулей (только при первом обращении)
2. Автоматическое определение доступности библиотек
3. Единая обработка ошибок нативного кода
4. Fallback на Python реализации если нативный модуль недоступен

Использование:
    from securevault.native import get_native_manager
    
    nm = get_native_manager()
    
    # Проверка доступности
    if nm.is_available():
        # Использование нативных функций
        encrypted = nm.crypto.encrypt_aes_gcm(data, key)
    
    # Или прямой импорт
    from securevault.native import crypto
    if crypto.is_available():
        encrypted = crypto.encrypt_aes_gcm(data, key)
"""

import os
import sys
import logging
import ctypes
from typing import Optional, Dict, Any, List
from pathlib import Path
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ============================================================================
# КОНСТАНТЫ
# ============================================================================

# Имена библиотек по платформам
CRYPTO_LIB_NAMES = {
    "linux": ["libsecurevault_crypto.so", "libcrypto.so"],
    "windows": ["securevault_crypto.dll", "libcrypto.dll"],
    "darwin": ["libsecurevault_crypto.dylib", "libcrypto.dylib"],
}

CONTAINER_LIB_NAMES = {
    "linux": ["libsecurevault_container.so"],
    "windows": ["securevault_container.dll"],
    "darwin": ["libsecurevault_container.dylib"],
}

PKCS11_LIB_NAMES = {
    "linux": ["libsecurevault_pkcs11.so"],
    "windows": ["securevault_pkcs11.dll"],
    "darwin": ["libsecurevault_pkcs11.dylib"],
}

# Пути поиска библиотек
LIB_SEARCH_PATHS = [
    # Текущая директория
    Path(__file__).parent,
    # Родительская директория
    Path(__file__).parent.parent,
    # Системные пути
    Path("/usr/lib"),
    Path("/usr/lib64"),
    Path("/usr/local/lib"),
    Path("/opt/homebrew/lib"),  # macOS Homebrew
    Path("C:\\Windows\\System32"),  # Windows
]


# ============================================================================
# ИСКЛЮЧЕНИЯ
# ============================================================================

class NativeError(Exception):
    """Базовое исключение для нативных модулей."""
    pass


class LibraryNotFoundError(NativeError):
    """Библиотека не найдена."""
    pass


class LibraryLoadError(NativeError):
    """Ошибка загрузки библиотеки."""
    pass


class FunctionNotFoundError(NativeError):
    """Функция не найдена в библиотеке."""
    pass


class NativeModuleError(NativeError):
    """Ошибка нативного модуля."""
    pass


# ============================================================================
# СТРУКТУРЫ ДАННЫХ
# ============================================================================

@dataclass
class NativeModuleInfo:
    """Информация о нативном модуле."""
    name: str
    loaded: bool
    library_path: Optional[str]
    error: Optional[str] = None
    version: Optional[str] = None


# ============================================================================
# ЗАГРУЗЧИК БИБЛИОТЕК
# ============================================================================

class LibraryLoader:
    """
    Загрузчик нативных библиотек.
    
    Предоставляет функционал для поиска и загрузки C++ библиотек
    с поддержкой разных платформ и путей поиска.
    """
    
    def __init__(self):
        self._loaded_libs: Dict[str, ctypes.CDLL] = {}
    
    def find_library(self, lib_names: List[str]) -> Optional[str]:
        """
        Найти библиотеку в системе.
        
        Args:
            lib_names: Список возможных имен библиотеки.
        
        Returns:
            Путь к библиотеке или None.
        """
        # 1. Проверка через ctypes.util
        for name in lib_names:
            found = ctypes.util.find_library(name)
            if found:
                return found
        
        # 2. Проверка в стандартных путях
        for search_path in LIB_SEARCH_PATHS:
            for name in lib_names:
                lib_path = search_path / name
                if lib_path.exists():
                    return str(lib_path)
        
        # 3. Проверка в PATH
        for name in lib_names:
            if os.path.exists(name):
                return os.path.abspath(name)
        
        return None
    
    def load_library(self, lib_name: str, search_names: List[str]) -> ctypes.CDLL:
        """
        Загрузить библиотеку.
        
        Args:
            lib_name: Логическое имя библиотеки.
            search_names: Список возможных имен файла.
        
        Returns:
            Загруженная библиотека.
        
        Raises:
            LibraryNotFoundError: Если библиотека не найдена.
            LibraryLoadError: Если не удалось загрузить.
        """
        # Проверка кэша
        if lib_name in self._loaded_libs:
            return self._loaded_libs[lib_name]
        
        # Поиск библиотеки
        lib_path = self.find_library(search_names)
        if not lib_path:
            raise LibraryNotFoundError(
                f"Library {lib_name} not found. Searched: {search_names}"
            )
        
        # Загрузка
        try:
            lib = ctypes.cdll.LoadLibrary(lib_path)
            self._loaded_libs[lib_name] = lib
            logger.info(f"Loaded native library: {lib_name} from {lib_path}")
            return lib
            
        except OSError as e:
            raise LibraryLoadError(f"Failed to load {lib_name} from {lib_path}: {e}")
    
    def unload_library(self, lib_name: str) -> None:
        """Выгрузить библиотеку."""
        if lib_name in self._loaded_libs:
            del self._loaded_libs[lib_name]
            logger.debug(f"Unloaded native library: {lib_name}")


# ============================================================================
# ОБЕРТКИ НАД НАТИВНЫМИ МОДУЛЯМИ
# ============================================================================

class CryptoModule:
    """
    Обертка над нативным crypto модулем.
    
    Предоставляет доступ к криптографическим функциям:
    - Шифрование/дешифрование (AES-GCM, AES-CBC)
    - Хеширование (SHA256, SHA512)
    - HMAC
    - Генерация случайных чисел
    """
    
    def __init__(self, loader: LibraryLoader):
        self._loader = loader
        self._lib: Optional[ctypes.CDLL] = None
        self._available = False
        self._error: Optional[str] = None
    
    def initialize(self) -> bool:
        """
        Инициализировать модуль.
        
        Returns:
            True если модуль доступен.
        """
        try:
            # Загрузка библиотеки
            self._lib = self._loader.load_library("crypto", CRYPTO_LIB_NAMES[sys.platform])
            
            # TODO: Загрузка функций из библиотеки
            # self._encrypt_aes_gcm = self._lib.encrypt_aes_gcm
            # self._encrypt_aes_gcm.argtypes = [...]
            # self._encrypt_aes_gcm.restype = ...
            
            self._available = True
            logger.info("Native crypto module initialized")
            return True
            
        except (LibraryNotFoundError, LibraryLoadError) as e:
            self._error = str(e)
            logger.warning(f"Native crypto module not available: {e}")
            return False
    
    def is_available(self) -> bool:
        """Проверить доступность модуля."""
        return self._available
    
    def get_error(self) -> Optional[str]:
        """Получить ошибку инициализации."""
        return self._error
    
    # ------------------------------------------------------------------------
    # КРИПТОГРАФИЧЕСКИЕ ОПЕРАЦИИ
    # ------------------------------------------------------------------------
    
    def encrypt_aes_gcm(
        self,
        plaintext: bytes,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Шифрование AES-256-GCM.
        
        Args:
            plaintext: Открытый текст.
            key: Ключ (32 байта для AES-256).
            associated_data: Дополнительные аутентифицированные данные.
        
        Returns:
            nonce + ciphertext + tag.
        """
        if not self._available:
            raise NativeModuleError("Crypto module not available")
        
        # TODO: Реализовать вызов нативной функции
        # Пока заглушка
        raise NotImplementedError("Native AES-GCM not implemented yet")
    
    def decrypt_aes_gcm(
        self,
        ciphertext: bytes,
        key: bytes,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Дешифрование AES-256-GCM.
        
        Args:
            ciphertext: Зашифрованные данные (nonce + ciphertext + tag).
            key: Ключ.
            associated_data: Дополнительные аутентифицированные данные.
        
        Returns:
            Открытый текст.
        """
        if not self._available:
            raise NativeModuleError("Crypto module not available")
        
        raise NotImplementedError("Native AES-GCM not implemented yet")
    
    def hash_sha256(self, data: bytes) -> bytes:
        """
        SHA256 хеш.
        
        Args:
            data: Данные для хеширования.
        
        Returns:
            32-байтовый хеш.
        """
        if not self._available:
            raise NativeModuleError("Crypto module not available")
        
        raise NotImplementedError("Native SHA256 not implemented yet")
    
    def hash_sha512(self, data: bytes) -> bytes:
        """
        SHA512 хеш.
        
        Args:
            data: Данные для хеширования.
        
        Returns:
            64-байтовый хеш.
        """
        if not self._available:
            raise NativeModuleError("Crypto module not available")
        
        raise NotImplementedError("Native SHA512 not implemented yet")
    
    def hmac_sha256(self, data: bytes, key: bytes) -> bytes:
        """
        HMAC-SHA256.
        
        Args:
            data: Данные.
            key: Ключ.
        
        Returns:
            32-байтовый HMAC.
        """
        if not self._available:
            raise NativeModuleError("Crypto module not available")
        
        raise NotImplementedError("Native HMAC-SHA256 not implemented yet")
    
    def generate_random(self, size: int) -> bytes:
        """
        Генерация случайных байтов.
        
        Args:
            size: Количество байтов.
        
        Returns:
            Случайные байты.
        """
        if not self._available:
            raise NativeModuleError("Crypto module not available")
        
        raise NotImplementedError("Native random not implemented yet")


class ContainerModule:
    """
    Обертка над нативным container модулем.
    
    Предоставляет доступ к операциям с контейнерами:
    - Создание/удаление контейнеров
    - Чтение/запись блоков
    - Дедупликация
    """
    
    def __init__(self, loader: LibraryLoader):
        self._loader = loader
        self._lib: Optional[ctypes.CDLL] = None
        self._available = False
        self._error: Optional[str] = None
    
    def initialize(self) -> bool:
        """
        Инициализировать модуль.
        
        Returns:
            True если модуль доступен.
        """
        try:
            self._lib = self._loader.load_library(
                "container", CONTAINER_LIB_NAMES[sys.platform]
            )
            self._available = True
            logger.info("Native container module initialized")
            return True
            
        except (LibraryNotFoundError, LibraryLoadError) as e:
            self._error = str(e)
            logger.warning(f"Native container module not available: {e}")
            return False
    
    def is_available(self) -> bool:
        """Проверить доступность модуля."""
        return self._available
    
    def get_error(self) -> Optional[str]:
        """Получить ошибку инициализации."""
        return self._error


class PKCS11ModuleWrapper:
    """
    Обертка над нативным PKCS#11 модулем.
    
    Предоставляет доступ к операциям с HSM/токенами:
    - Управление сессиями
    - Работа с ключами
    - Криптографические операции на токене
    """
    
    def __init__(self, loader: LibraryLoader):
        self._loader = loader
        self._lib: Optional[ctypes.CDLL] = None
        self._available = False
        self._error: Optional[str] = None
    
    def initialize(self) -> bool:
        """
        Инициализировать модуль.
        
        Returns:
            True если модуль доступен.
        """
        try:
            self._lib = self._loader.load_library(
                "pkcs11", PKCS11_LIB_NAMES[sys.platform]
            )
            self._available = True
            logger.info("Native PKCS#11 module initialized")
            return True
            
        except (LibraryNotFoundError, LibraryLoadError) as e:
            self._error = str(e)
            logger.warning(f"Native PKCS#11 module not available: {e}")
            return False
    
    def is_available(self) -> bool:
        """Проверить доступность модуля."""
        return self._available
    
    def get_error(self) -> Optional[str]:
        """Получить ошибку инициализации."""
        return self._error


# ============================================================================
# МЕНЕДЖЕР НАТИВНЫХ МОДУЛЕЙ
# ============================================================================

class NativeManager:
    """
    Менеджер нативных модулей.
    
    Предоставляет централизованный доступ ко всем нативным модулям
    с ленивой инициализацией и кэшированием.
    
    Пример:
        nm = NativeManager()
        
        # Инициализация всех модулей
        nm.initialize()
        
        # Проверка доступности
        if nm.is_crypto_available():
            # Использование crypto
            encrypted = nm.crypto.encrypt_aes_gcm(data, key)
    """
    
    _instance: Optional["NativeManager"] = None
    
    def __new__(cls):
        """Синглтон паттерн."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        """Инициализировать менеджер."""
        if self._initialized:
            return
        
        self._loader = LibraryLoader()
        self._crypto = CryptoModule(self._loader)
        self._container = ContainerModule(self._loader)
        self._pkcs11 = PKCS11ModuleWrapper(self._loader)
        
        self._initialized = True
        logger.debug("NativeManager created")
    
    def initialize(self) -> Dict[str, NativeModuleInfo]:
        """
        Инициализировать все модули.
        
        Returns:
            Словарь с информацией о каждом модуле.
        """
        logger.info("Initializing native modules...")
        
        modules = {
            "crypto": self._crypto.initialize(),
            "container": self._container.initialize(),
            "pkcs11": self._pkcs11.initialize(),
        }
        
        info = {
            "crypto": NativeModuleInfo(
                name="crypto",
                loaded=modules["crypto"],
                library_path=self._get_lib_path("crypto"),
                error=self._crypto.get_error(),
            ),
            "container": NativeModuleInfo(
                name="container",
                loaded=modules["container"],
                library_path=self._get_lib_path("container"),
                error=self._container.get_error(),
            ),
            "pkcs11": NativeModuleInfo(
                name="pkcs11",
                loaded=modules["pkcs11"],
                library_path=self._get_lib_path("pkcs11"),
                error=self._pkcs11.get_error(),
            ),
        }
        
        available_count = sum(1 for m in info.values() if m.loaded)
        logger.info(
            f"Native modules initialized: {available_count}/{len(info)} available"
        )
        
        return info
    
    def _get_lib_path(self, lib_name: str) -> Optional[str]:
        """Получить путь к загруженной библиотеке."""
        # TODO: Реализовать получение пути из loader
        return None
    
    def is_available(self) -> bool:
        """
        Проверить доступность хотя бы одного модуля.
        
        Returns:
            True если хотя бы один модуль доступен.
        """
        return (
            self._crypto.is_available()
            or self._container.is_available()
            or self._pkcs11.is_available()
        )
    
    def is_crypto_available(self) -> bool:
        """Проверить доступность crypto модуля."""
        return self._crypto.is_available()
    
    def is_container_available(self) -> bool:
        """Проверить доступность container модуля."""
        return self._container.is_available()
    
    def is_pkcs11_available(self) -> bool:
        """Проверить доступность PKCS#11 модуля."""
        return self._pkcs11.is_available()
    
    @property
    def crypto(self) -> CryptoModule:
        """Получить crypto модуль."""
        return self._crypto
    
    @property
    def container(self) -> ContainerModule:
        """Получить container модуль."""
        return self._container
    
    @property
    def pkcs11(self) -> PKCS11ModuleWrapper:
        """Получить PKCS#11 модуль."""
        return self._pkcs11
    
    def get_module_info(self) -> Dict[str, NativeModuleInfo]:
        """
        Получить информацию о всех модулях.
        
        Returns:
            Словарь с информацией о модулях.
        """
        return {
            "crypto": NativeModuleInfo(
                name="crypto",
                loaded=self._crypto.is_available(),
                library_path=None,
                error=self._crypto.get_error(),
            ),
            "container": NativeModuleInfo(
                name="container",
                loaded=self._container.is_available(),
                library_path=None,
                error=self._container.get_error(),
            ),
            "pkcs11": NativeModuleInfo(
                name="pkcs11",
                loaded=self._pkcs11.is_available(),
                library_path=None,
                error=self._pkcs11.get_error(),
            ),
        }
    
    def shutdown(self) -> None:
        """Завершить работу и выгрузить все модули."""
        logger.info("Shutting down native modules...")
        # TODO: Выгрузка библиотек
        logger.info("Native modules shutdown complete")


# ============================================================================
# ГЛОБАЛЬНЫЙ ДОСТУП
# ============================================================================

# Глобальный экземпляр менеджера
_native_manager: Optional[NativeManager] = None


def get_native_manager() -> NativeManager:
    """
    Получить глобальный экземпляр менеджера нативных модулей.
    
    Returns:
        Экземпляр NativeManager.
    """
    global _native_manager
    if _native_manager is None:
        _native_manager = NativeManager()
    return _native_manager


def initialize_native_modules() -> Dict[str, NativeModuleInfo]:
    """
    Инициализировать все нативные модули.
    
    Returns:
        Информация о модулях.
    """
    nm = get_native_manager()
    return nm.initialize()


def is_native_available() -> bool:
    """
    Проверить доступность нативных модулей.
    
    Returns:
        True если хотя бы один модуль доступен.
    """
    return get_native_manager().is_available()


# ============================================================================
# УТИЛИТЫ
# ============================================================================

def find_library(lib_name: str, search_names: List[str]) -> Optional[str]:
    """
    Найти библиотеку в системе.
    
    Args:
        lib_name: Логическое имя библиотеки.
        search_names: Список возможных имен файла.
    
    Returns:
        Путь к библиотеке или None.
    """
    loader = LibraryLoader()
    return loader.find_library(search_names)


def get_library_search_paths() -> List[Path]:
    """
    Получить список путей для поиска библиотек.
    
    Returns:
        Список путей.
    """
    return LIB_SEARCH_PATHS.copy()


def add_library_search_path(path: Path) -> None:
    """
    Добавить путь для поиска библиотек.
    
    Args:
        path: Путь к директории с библиотеками.
    """
    if path not in LIB_SEARCH_PATHS:
        LIB_SEARCH_PATHS.append(path)
        logger.debug(f"Added library search path: {path}")


# ============================================================================
# ЭКСПОРТ
# ============================================================================

__all__ = [
    # Основные классы
    "NativeManager",
    "LibraryLoader",
    "NativeModuleInfo",
    
    # Модули
    "CryptoModule",
    "ContainerModule",
    "PKCS11ModuleWrapper",
    
    # Исключения
    "NativeError",
    "LibraryNotFoundError",
    "LibraryLoadError",
    "FunctionNotFoundError",
    "NativeModuleError",
    
    # Функции доступа
    "get_native_manager",
    "initialize_native_modules",
    "is_native_available",
    
    # Утилиты
    "find_library",
    "get_library_search_paths",
    "add_library_search_path",
]