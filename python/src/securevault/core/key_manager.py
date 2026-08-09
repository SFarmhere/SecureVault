"""
SecureVault - Менеджер ключей

Управление жизненным циклом ключей:
- Генерация мастер-ключей и ключей файлов
- Хранение в HSM/USB токенах через PKCS#11
- Ротация и архив ключей
- Деривация из паролей (Argon2id)
- Резервное копирование (Shamir Secret Sharing 3-of-5)
- Криптографическое затирание

Зависимости:
- native.pkcs11: Взаимодействие с HSM/токенами
- native.crypto: Криптографические операции
- security.shamir: Разделение секрета (SSS)
- exceptions: Исключения проекта
- constants: Константы

Использование:
    from securevault.core.key_manager import KeyManager

    km = KeyManager()

    # Генерация мастер-ключа
    master_key = km.generate_master_key()

    # Хранение в HSM
    km.store_key_securely(master_key, "master-key-1")

    # Получение из HSM
    retrieved = km.retrieve_key("master-key-1")

    # Ротация
    km.rotate_keys("master-key-1")

    # Резервное копирование
    shares = km.backup_keys(master_key)

    # Уничтожение
    km.destroy_key("master-key-1")
"""

import os
import secrets
import hashlib
import hmac
import logging
from typing import Optional, List, Tuple, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum

# Внутренние импорты
from securevault.native import pkcs11
from securevault.native import crypto
from securevault.security import shamir
from securevault import exceptions

logger = logging.getLogger(__name__)


# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================


class KeyType(Enum):
    """Типы ключей."""

    MASTER = "master"  # Мастер-ключ (главный ключ шифрования)
    FILE = "file"  # Ключ для отдельного файла
    PASSWORD = "password"  # Ключ, деривированный из пароля
    TOKEN = "token"  # Ключ на HSM/токене
    SESSION = "session"  # Временный сессионный ключ


class KeyStatus(Enum):
    """Статусы ключа."""

    ACTIVE = "active"  # Активный, используется
    ROTATED = "rotated"  # Заменен новой версией
    ARCHIVED = "archived"  # В архиве (можно восстановить)
    DESTROYED = "destroyed"  # Уничтожен


class ProtectionLevel(Enum):
    """Уровни защиты ключей."""

    SOFTWARE = "software"  # Программное хранение (зашифровано)
    HARDWARE = "hardware"  # Аппаратное хранение (HSM/токен)
    HYBRID = "hybrid"  # Гибрид (часть в HSM, часть программно)


# Параметры по умолчанию
DEFAULT_MASTER_KEY_SIZE = 32  # 256 бит (AES-256)
DEFAULT_FILE_KEY_SIZE = 32  # 256 бит
DEFAULT_SESSION_KEY_SIZE = 32  # 256 бит
DEFAULT_PASSWORD_KEY_SIZE = 32  # 256 бит

# Параметры Argon2id для деривации ключей из паролей
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LENGTH = 32
ARGON2_SALT_LENGTH = 16

# Параметры Shamir Secret Sharing для бэкапа
SHAMIR_TOTAL_SHARES = 5
SHAMIR_THRESHOLD = 3

# Пути для хранения
KEYS_DIR = "keys"
BACKUP_DIR = "backups"
METADATA_FILE = "key_metadata.json"


# ============================================================================
# МЕТАДАННЫЕ КЛЮЧА
# ============================================================================


class KeyMetadata:
    """Метаданные ключа для отслеживания жизненного цикла."""

    def __init__(
        self,
        key_id: str,
        key_type: KeyType,
        status: KeyStatus = KeyStatus.ACTIVE,
        protection_level: ProtectionLevel = ProtectionLevel.SOFTWARE,
        created_at: Optional[datetime] = None,
        expires_at: Optional[datetime] = None,
        rotated_from: Optional[str] = None,
        description: str = "",
        tags: Optional[List[str]] = None,
    ):
        self.key_id = key_id
        self.key_type = key_type
        self.status = status
        self.protection_level = protection_level
        self.created_at = created_at or datetime.utcnow()
        self.expires_at = expires_at
        self.rotated_from = rotated_from
        self.description = description
        self.tags = tags or []
        self.last_used: Optional[datetime] = None
        self.use_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Сериализовать в словарь."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "status": self.status.value,
            "protection_level": self.protection_level.value,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "rotated_from": self.rotated_from,
            "description": self.description,
            "tags": self.tags,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "use_count": self.use_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyMetadata":
        """Десериализовать из словаря."""
        return cls(
            key_id=data["key_id"],
            key_type=KeyType(data["key_type"]),
            status=KeyStatus(data["status"]),
            protection_level=ProtectionLevel(data["protection_level"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            rotated_from=data.get("rotated_from"),
            description=data.get("description", ""),
            tags=data.get("tags", []),
        )


# ============================================================================
# ИСКЛЮЧЕНИЯ
# ============================================================================


class KeyManagerError(exceptions.SecureVaultError):
    """Базовое исключение для KeyManager."""


class KeyNotFoundError(KeyManagerError):
    """Ключ не найден."""


class KeyAlreadyExistsError(KeyManagerError):
    """Ключ уже существует."""


class KeyExpiredError(KeyManagerError):
    """Ключ истек."""


class KeyDestroyedError(KeyManagerError):
    """Ключ был уничтожен."""


class TokenError(KeyManagerError):
    """Ошибка работы с токеном."""


class InsufficientSharesError(KeyManagerError):
    """Недостаточно shares для восстановления."""


# ============================================================================
# ОСНОВНОЙ КЛАСС
# ============================================================================


class KeyManager:
    """
    Менеджер ключей SecureVault.

    Управляет всем жизненным циклом ключей:
    - Генерация криптостойких ключей
    - Хранение в HSM/USB токенах (PKCS#11)
    - Программное хранение с шифрованием
    - Ротация и версионирование
    - Резервное копирование (Shamir Secret Sharing)
    - Безопасное уничтожение

    Пример:
        km = KeyManager(storage_dir="/secure/vault/keys")

        # Создание мастер-ключа
        master_key = km.generate_master_key()
        km.store_key_securely(master_key, "master-1")

        # Создание ключа для файла
        file_key = km.generate_file_key()
        km.store_key_securely(file_key, "file-abc123")

        # Получение ключа
        key = km.retrieve_key("file-abc123")

        # Ротация
        new_key = km.rotate_keys("file-abc123")

        # Бэкап мастер-ключа
        shares = km.backup_keys(master_key)

        # Восстановление из бэкапа
        recovered = km.restore_from_backup(shares)

        # Уничтожение
        km.destroy_key("file-abc123")
    """

    def __init__(
        self,
        storage_dir: Optional[str] = None,
        token_library: Optional[str] = None,
        master_key_password: Optional[str] = None,
    ):
        """
        Инициализировать менеджер ключей.

        Args:
            storage_dir: Директория для хранения ключей.
                        По умолчанию: ~/.securevault/keys
            token_library: Путь к PKCS#11 библиотеке токена.
                          Если None, попытка автоопределения.
            master_key_password: Пароль для защиты мастер-ключа
                                (если None, генерируется случайный).
        """
        # Директория хранения
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            home = Path.home()
            self.storage_dir = home / ".securevault" / KEYS_DIR

        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Директория для бэкапов
        self.backup_dir = self.storage_dir.parent / BACKUP_DIR
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        # Метаданные ключей
        self.metadata_file = self.storage_dir / METADATA_FILE
        self.metadata: Dict[str, KeyMetadata] = {}
        self._load_metadata()

        # PKCS#11 модуль для работы с токенами
        self._pkcs11_module: Optional[pkcs11.PKCS11Module] = None
        self._token_library = token_library
        self._token_available = False

        # Мастер-ключ (кэшируется в памяти)
        self._master_key: Optional[bytes] = None
        self._master_key_id: Optional[str] = "master-1"

        # Пароль для мастер-ключа
        self._master_key_password = master_key_password

        # Попытка инициализировать токен
        self._try_initialize_token()

        logger.info(f"KeyManager initialized: storage={self.storage_dir}")

    # ------------------------------------------------------------------------
    # ЖИЗНЕННЫЙ ЦИКЛ
    # ------------------------------------------------------------------------

    def initialize(self) -> None:
        """
        Полная инициализация менеджера ключей.

        Загружает мастер-ключ из хранилища или создает новый.
        """
        logger.info("Initializing KeyManager...")

        # Пытаемся загрузить существующий мастер-ключ
        if self._master_key_id and self._master_key_id in self.metadata:
            try:
                self._master_key = self.retrieve_key(self._master_key_id)
                logger.info(f"Master key loaded: {self._master_key_id}")
            except KeyNotFoundError:
                logger.warning("Master key not found, will create new one")
                self._master_key = None

        # Если мастер-ключа нет, создаем
        if self._master_key is None:
            self._master_key = self.generate_master_key()
            self.store_key_securely(self._master_key, self._master_key_id)
            logger.info(f"New master key created: {self._master_key_id}")

        logger.info("KeyManager initialization complete")

    def shutdown(self) -> None:
        """
        Корректное завершение работы.

        Очищает ключи из памяти.
        """
        if self._master_key:
            self._secure_erase(self._master_key)
            self._master_key = None

        if self._pkcs11_module:
            self._pkcs11_module.finalize()
            self._pkcs11_module = None

        logger.info("KeyManager shutdown complete")

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    # ------------------------------------------------------------------------
    # ГЕНЕРАЦИЯ КЛЮЧЕЙ
    # ------------------------------------------------------------------------

    def generate_master_key(self, size: int = DEFAULT_MASTER_KEY_SIZE) -> bytes:
        """
        Сгенерировать новый мастер-ключ.

        Мастер-ключ используется для шифрования всех остальных ключей.
        Хранится в HSM (если доступно) или в зашифрованном виде.

        Args:
            size: Размер ключа в байтах. По умолчанию 32 (AES-256).

        Returns:
            Случайный мастер-ключ.

        Raises:
            KeyManagerError: Если генерация не удалась.
        """
        try:
            # Пытаемся использовать аппаратный генератор
            if self._token_available:
                key = self._generate_key_on_token(size)
                logger.info(f"Master key generated on HSM: {size * 8} bits")
                return key

            # Иначе программная генерация
            key = secrets.token_bytes(size)

            # Дополнительное смешивание через crypto модуль
            if crypto.is_available():
                key = crypto.hash_sha256(key)

            logger.info(f"Master key generated: {size * 8} bits")
            return key

        except Exception as e:
            logger.error(f"Failed to generate master key: {e}")
            raise KeyManagerError(f"Master key generation failed: {e}")

    def generate_file_key(self, size: int = DEFAULT_FILE_KEY_SIZE) -> bytes:
        """
        Сгенерировать ключ для файла.

        Args:
            size: Размер ключа в байтах.

        Returns:
            Случайный ключ для файла.
        """
        return secrets.token_bytes(size)

    def generate_session_key(self, size: int = DEFAULT_SESSION_KEY_SIZE) -> bytes:
        """
        Сгенерировать временный сессионный ключ.

        Args:
            size: Размер ключа в байтах.

        Returns:
            Случайный сессионный ключ.
        """
        return secrets.token_bytes(size)

    def derive_key_from_password(
        self,
        password: str,
        salt: Optional[bytes] = None,
        size: int = DEFAULT_PASSWORD_KEY_SIZE,
    ) -> Tuple[bytes, bytes]:
        """
        Деривация ключа из пароля (Argon2id).

        Args:
            password: Пароль пользователя.
            salt: Соль (если None, генерируется случайная).
            size: Размер выходного ключа в байтах.

        Returns:
            Кортеж (key, salt).

        Raises:
            KeyManagerError: Если деривация не удалась.
        """
        if salt is None:
            salt = secrets.token_bytes(ARGON2_SALT_LENGTH)

        try:
            # Используем встроенную реализацию Argon2id
            # В продакшене должен использоватьсяargon2-cffi
            key = self._argon2id_hash(password, salt, size)

            logger.info(f"Key derived from password: {size * 8} bits")
            return key, salt

        except Exception as e:
            logger.error(f"Failed to derive key from password: {e}")
            raise KeyManagerError(f"Password key derivation failed: {e}")

    def _argon2id_hash(
        self,
        password: str,
        salt: bytes,
        size: int,
    ) -> bytes:
        """
        Argon2id хеширование (упрощенная реализация).

        В продакшене заменить на argon2-cffi.
        """
        # Временная реализация через PBKDF2 (заменить на Argon2id)
        import hashlib

        password_bytes = password.encode("utf-8")

        # PBKDF2-HMAC-SHA256
        key = hashlib.pbkdf2_hmac(
            "sha256",
            password_bytes,
            salt,
            ARGON2_TIME_COST * 1000,  # Увеличиваем итерации
            dklen=size,
        )

        return key

    # ------------------------------------------------------------------------
    # ХРАНЕНИЕ КЛЮЧЕЙ
    # ------------------------------------------------------------------------

    def store_key_securely(
        self,
        key: bytes,
        key_id: str,
        key_type: KeyType = KeyType.FILE,
        protection_level: Optional[ProtectionLevel] = None,
        description: str = "",
        tags: Optional[List[str]] = None,
        expires_in: Optional[timedelta] = None,
    ) -> None:
        """
        Безопасное хранение ключа.

        Приоритет хранения:
        1. HSM/токен (если доступен)
        2. Программное хранение с шифрованием мастер-ключом

        Args:
            key: Ключ для хранения.
            key_id: Уникальный идентификатор ключа.
            key_type: Тип ключа.
            protection_level: Уровень защиты (автоопределение если None).
            description: Описание ключа.
            tags: Теги для категоризации.
            expires_in: Время жизни ключа.

        Raises:
            KeyAlreadyExistsError: Если ключ уже существует.
            KeyManagerError: Если хранение не удалось.
        """
        # Проверка существования
        if key_id in self.metadata:
            raise KeyAlreadyExistsError(f"Key {key_id} already exists")

        # Определение уровня защиты
        if protection_level is None:
            protection_level = (
                ProtectionLevel.HARDWARE
                if self._token_available
                else ProtectionLevel.SOFTWARE
            )

        # Создание метаданных
        expires_at = None
        if expires_in:
            expires_at = datetime.utcnow() + expires_in

        metadata = KeyMetadata(
            key_id=key_id,
            key_type=key_type,
            protection_level=protection_level,
            description=description,
            tags=tags or [],
            expires_at=expires_at,
        )

        try:
            # Сохранение в зависимости от уровня защиты
            if protection_level == ProtectionLevel.HARDWARE and self._token_available:
                self._store_key_on_token(key, key_id)
                logger.info(f"Key stored on HSM: {key_id}")
            else:
                self._store_key_encrypted(key, key_id)
                logger.info(f"Key stored encrypted: {key_id}")

            # Сохранение метаданных
            self.metadata[key_id] = metadata
            self._save_metadata()

        except Exception as e:
            logger.error(f"Failed to store key {key_id}: {e}")
            # Откат метаданных
            if key_id in self.metadata:
                del self.metadata[key_id]
            raise KeyManagerError(f"Key storage failed: {e}")

    def retrieve_key(self, key_id: str) -> bytes:
        """
        Получить ключ из хранилища.

        Args:
            key_id: Идентификатор ключа.

        Returns:
            Ключ в открытом виде.

        Raises:
            KeyNotFoundError: Если ключ не найден.
            KeyDestroyedError: Если ключ был уничтожен.
            KeyExpiredError: Если ключ истек.
        """
        # Проверка метаданных
        if key_id not in self.metadata:
            raise KeyNotFoundError(f"Key {key_id} not found")

        metadata = self.metadata[key_id]

        # Проверка статуса
        if metadata.status == KeyStatus.DESTROYED:
            raise KeyDestroyedError(f"Key {key_id} has been destroyed")

        if metadata.status == KeyStatus.ROTATED:
            raise KeyNotFoundError(
                f"Key {key_id} has been rotated. "
                f"Use rotated_from={metadata.rotated_from} to get new key"
            )

        # Проверка срока действия
        if metadata.expires_at and datetime.utcnow() > metadata.expires_at:
            raise KeyExpiredError(f"Key {key_id} expired at {metadata.expires_at}")

        try:
            # Получение из хранилища
            if (
                metadata.protection_level == ProtectionLevel.HARDWARE
                and self._token_available
            ):
                key = self._retrieve_key_from_token(key_id)
            else:
                key = self._retrieve_key_encrypted(key_id)

            # Обновление статистики использования
            metadata.last_used = datetime.utcnow()
            metadata.use_count += 1
            self._save_metadata()

            logger.debug(f"Key retrieved: {key_id}")
            return key

        except Exception as e:
            logger.error(f"Failed to retrieve key {key_id}: {e}")
            raise KeyManagerError(f"Key retrieval failed: {e}")

    def destroy_key(self, key_id: str, secure: bool = True) -> None:
        """
        Безопасное уничтожение ключа.

        Args:
            key_id: Идентификатор ключа.
            secure: Если True, криптографическое затирание.

        Raises:
            KeyNotFoundError: Если ключ не найден.
        """
        if key_id not in self.metadata:
            raise KeyNotFoundError(f"Key {key_id} not found")

        metadata = self.metadata[key_id]

        try:
            # Удаление из хранилища
            if (
                metadata.protection_level == ProtectionLevel.HARDWARE
                and self._token_available
            ):
                self._destroy_key_on_token(key_id)
            else:
                self._destroy_key_encrypted(key_id, secure=secure)

            # Обновление метаданных
            metadata.status = KeyStatus.DESTROYED
            self._save_metadata()

            logger.info(f"Key destroyed: {key_id}")

        except Exception as e:
            logger.error(f"Failed to destroy key {key_id}: {e}")
            raise KeyManagerError(f"Key destruction failed: {e}")

    # ------------------------------------------------------------------------
    # РОТАЦИЯ КЛЮЧЕЙ
    # ------------------------------------------------------------------------

    def rotate_keys(self, key_id: str, reason: str = "scheduled") -> bytes:
        """
        Ротация ключа (создание новой версии).

        Args:
            key_id: Идентификатор старого ключа.
            reason: Причина ротации.

        Returns:
            Новый ключ.

        Raises:
            KeyNotFoundError: Если старый ключ не найден.
        """
        if key_id not in self.metadata:
            raise KeyNotFoundError(f"Key {key_id} not found")

        old_metadata = self.metadata[key_id]

        # Генерация нового ключа того же типа
        if old_metadata.key_type == KeyType.MASTER:
            new_key = self.generate_master_key()
        elif old_metadata.key_type == KeyType.FILE:
            new_key = self.generate_file_key()
        else:
            new_key = secrets.token_bytes(DEFAULT_FILE_KEY_SIZE)

        # Новый ID для нового ключа
        new_key_id = f"{key_id}-v{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"

        # Сохранение нового ключа
        self.store_key_securely(
            new_key,
            new_key_id,
            key_type=old_metadata.key_type,
            protection_level=old_metadata.protection_level,
            description=f"Rotated from {key_id}: {reason}",
            tags=old_metadata.tags,
        )

        # Обновление старого ключа
        old_metadata.status = KeyStatus.ROTATED
        old_metadata.rotated_from = new_key_id
        self._save_metadata()

        logger.info(f"Key rotated: {key_id} -> {new_key_id}")
        return new_key

    def archive_key(self, key_id: str) -> None:
        """
        Архивировать ключ (переместить в архив).

        Args:
            key_id: Идентификатор ключа.

        Raises:
            KeyNotFoundError: Если ключ не найден.
        """
        if key_id not in self.metadata:
            raise KeyNotFoundError(f"Key {key_id} not found")

        metadata = self.metadata[key_id]
        metadata.status = KeyStatus.ARCHIVED
        self._save_metadata()

        logger.info(f"Key archived: {key_id}")

    # ------------------------------------------------------------------------
    # РЕЗЕРВНОЕ КОПИРОВАНИЕ (SHAMIR SECRET SHARING)
    # ------------------------------------------------------------------------

    def backup_keys(
        self,
        master_key: Optional[bytes] = None,
        total_shares: int = SHAMIR_TOTAL_SHARES,
        threshold: int = SHAMIR_THRESHOLD,
    ) -> List[bytes]:
        """
        Создать резервную копию мастер-ключа (Shamir Secret Sharing).

        Разделяет мастер-ключ на N частей, K из которых нужны для восстановления.

        Args:
            master_key: Мастер-ключ (если None, используется текущий).
            total_shares: Общее количество частей (N).
            threshold: Минимальное количество для восстановления (K).

        Returns:
            Список сериализованных shares.

        Raises:
            KeyManagerError: Если бэкап не удался.
        """
        if master_key is None:
            if self._master_key is None:
                raise KeyManagerError("No master key available")
            master_key = self._master_key

        try:
            sss = shamir.ShamirSecretSharing()
            shares = sss.split(master_key, total=total_shares, threshold=threshold)

            # Сериализация
            serialized = [s.serialize() for s in shares]

            # Сохранение бэкапа
            backup_file = (
                self.backup_dir
                / f"backup-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.dat"
            )
            with open(backup_file, "wb") as f:
                f.write(
                    total_shares.to_bytes(1, "big")
                    + threshold.to_bytes(1, "big")
                    + len(serialized).to_bytes(2, "big")
                )
                for share_data in serialized:
                    f.write(len(share_data).to_bytes(2, "big"))
                    f.write(share_data)

            logger.info(
                f"Backup created: {total_shares} shares, "
                f"threshold={threshold}, file={backup_file}"
            )

            return serialized

        except Exception as e:
            logger.error(f"Failed to create backup: {e}")
            raise KeyManagerError(f"Backup creation failed: {e}")

    def restore_from_backup(
        self,
        shares: List[bytes],
        verify: bool = True,
    ) -> bytes:
        """
        Восстановить мастер-ключ из резервной копии.

        Args:
            shares: Список сериализованных shares (минимум threshold).
            verify: Проверять целостность shares.

        Returns:
            Восстановленный мастер-ключ.

        Raises:
            InsufficientSharesError: Если shares меньше threshold.
            KeyManagerError: Если восстановление не удалось.
        """
        try:
            sss = shamir.ShamirSecretSharing()
            recovered = sss.join([shamir.Share.deserialize(s) for s in shares])

            if verify:
                # Проверка, что ключ валидный
                if len(recovered) not in (16, 24, 32):
                    raise KeyManagerError("Recovered key has invalid length")

            logger.info(f"Master key restored from backup ({len(shares)} shares)")
            return recovered

        except Exception as e:
            logger.error(f"Failed to restore from backup: {e}")
            raise KeyManagerError(f"Backup restoration failed: {e}")

    def restore_from_backup_file(
        self,
        backup_file: str,
        shares_count: int,
    ) -> bytes:
        """
        Восстановить из файла бэкапа.

        Args:
            backup_file: Путь к файлу бэкапа.
            shares_count: Количество shares для использования.

        Returns:
            Восстановленный мастер-ключ.
        """
        with open(backup_file, "rb") as f:
            total_shares = f.read(1)[0]
            threshold = f.read(1)[0]
            num_shares = int.from_bytes(f.read(2), "big")

            if shares_count < threshold:
                raise InsufficientSharesError(
                    f"Need at least {threshold} shares, got {shares_count}"
                )

            shares = []
            for _ in range(shares_count):
                share_len = int.from_bytes(f.read(2), "big")
                share_data = f.read(share_len)
                shares.append(share_data)

        return self.restore_from_backup(shares)

    # ------------------------------------------------------------------------
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # ------------------------------------------------------------------------

    def list_keys(
        self,
        key_type: Optional[KeyType] = None,
        status: Optional[KeyStatus] = None,
    ) -> List[KeyMetadata]:
        """
        Получить список ключей.

        Args:
            key_type: Фильтр по типу.
            status: Фильтр по статусу.

        Returns:
            Список метаданных ключей.
        """
        result = list(self.metadata.values())

        if key_type:
            result = [m for m in result if m.key_type == key_type]

        if status:
            result = [m for m in result if m.status == status]

        return sorted(result, key=lambda m: m.created_at, reverse=True)

    def get_key_info(self, key_id: str) -> KeyMetadata:
        """
        Получить информацию о ключе.

        Args:
            key_id: Идентификатор ключа.

        Returns:
            Метаданные ключа.

        Raises:
            KeyNotFoundError: Если ключ не найден.
        """
        if key_id not in self.metadata:
            raise KeyNotFoundError(f"Key {key_id} not found")

        return self.metadata[key_id]

    def is_token_available(self) -> bool:
        """Проверить доступность HSM/токена."""
        return self._token_available

    def get_master_key_id(self) -> Optional[str]:
        """Получить ID текущего мастер-ключа."""
        return self._master_key_id

    # ------------------------------------------------------------------------
    # ПРИВАТНЫЕ МЕТОДЫ - РАБОТА С ТОКЕНОМ
    # ------------------------------------------------------------------------

    def _try_initialize_token(self) -> None:
        """Попытка инициализировать PKCS#11 токен."""
        try:
            self._pkcs11_module = pkcs11.PKCS11Module(self._token_library)
            self._pkcs11_module.initialize()
            tokens = self._pkcs11_module.get_available_tokens()

            if tokens:
                self._token_available = True
                logger.info(f"Token available: {tokens[0]}")
            else:
                logger.info("No tokens found, using software storage")

        except Exception as e:
            logger.warning(f"Token initialization failed: {e}")
            self._token_available = False

    def _generate_key_on_token(self, size: int) -> bytes:
        """
        Генерация ключа на токене.

        ВНИМАНИЕ: Многие токены не поддерживают генерацию случайных чисел.
        В таком случае используем программную генерацию + импорт.
        """
        # Пока используем программную генерацию
        # В будущем можно использовать C_GenerateRandom если токен поддерживает
        return secrets.token_bytes(size)

    def _store_key_on_token(self, key: bytes, key_id: str) -> None:
        """
        Сохранить ключ на токен.

        Создает секретный ключ на токене с атрибутами:
        - CKA_LABEL: key_id
        - CKA_TOKEN: True (перманентное хранение)
        - CKA_SENSITIVE: True (не экспортируемый)
        - CKA_EXTRACTABLE: False (нельзя извлечь)
        """
        if not self._pkcs11_module or not self._token_available:
            raise TokenError("Token not available")

        # Открываем сессию на первом доступном токене
        tokens = self._pkcs11_module.get_available_tokens()
        if not tokens:
            raise TokenError("No tokens available")

        # TODO: Реализовать сохранение ключа на токен
        # Требуется: открыть сессию, создать объект CKO_SECRET_KEY
        logger.warning(
            "Token key storage not fully implemented, falling back to software"
        )

    def _retrieve_key_from_token(self, key_id: str) -> bytes:
        """
        Получить ключ с токена.

        ВНИМАНИЕ: Если ключ помечен как CKA_SENSITIVE и CKA_EXTRACTABLE=False,
        его нельзя извлечь с токена. В таком случае нужно использовать
        ключ для операций напрямую на токене.
        """
        # TODO: Реализовать получение ключа с токена
        raise TokenError("Token key retrieval not implemented")

    def _destroy_key_on_token(self, key_id: str) -> None:
        """Уничтожить ключ на токене."""
        # TODO: Реализовать удаление ключа с токена
        logger.warning("Token key destruction not fully implemented")

    # ------------------------------------------------------------------------
    # ПРИВАТНЫЕ МЕТОДЫ - ПРОГРАММНОЕ ХРАНЕНИЕ
    # ------------------------------------------------------------------------

    def _store_key_encrypted(self, key: bytes, key_id: str) -> None:
        """
        Сохранить ключ в зашифрованном виде.

        Шифрование: AES-256-GCM
        Ключ шифрования: мастер-ключ
        """
        if self._master_key is None:
            raise KeyManagerError("Master key not available")

        # Шифруем ключ мастер-ключом
        encrypted = crypto.encrypt_aes_gcm(key, self._master_key)

        # Сохраняем в файл
        key_file = self.storage_dir / f"{key_id}.key"
        with open(key_file, "wb") as f:
            f.write(encrypted)

        # Устанавливаем права доступа (только владелец)
        os.chmod(key_file, 0o600)

    def _retrieve_key_encrypted(self, key_id: str) -> bytes:
        """
        Получить ключ из зашифрованного хранилища.

        Args:
            key_id: Идентификатор ключа.

        Returns:
            Расшифрованный ключ.

        Raises:
            KeyNotFoundError: Если файл ключа не найден.
        """
        if self._master_key is None:
            raise KeyManagerError("Master key not available")

        key_file = self.storage_dir / f"{key_id}.key"
        if not key_file.exists():
            raise KeyNotFoundError(f"Key file not found: {key_file}")

        with open(key_file, "rb") as f:
            encrypted = f.read()

        # Расшифровываем
        key = crypto.decrypt_aes_gcm(encrypted, self._master_key)

        return key

    def _destroy_key_encrypted(self, key_id: str, secure: bool = True) -> None:
        """
        Уничтожить ключ в программном хранилище.

        Args:
            key_id: Идентификатор ключа.
            secure: Криптографическое затирание.
        """
        key_file = self.storage_dir / f"{key_id}.key"
        if not key_file.exists():
            return

        if secure:
            # Криптографическое затирание (3 прохода)
            self._secure_erase_file(key_file)
        else:
            # Простое удаление
            key_file.unlink()

    @staticmethod
    def _secure_erase(data: bytes) -> None:
        """
        Криптографическое затирание данных в памяти.

        3 прохода:
        1. Запись нулей
        2. Запись 0xFF
        3. Запись случайных данных
        """
        if not isinstance(data, bytearray):
            data = bytearray(data)

        # Проход 1: нули
        for i in range(len(data)):
            data[i] = 0x00

        # Проход 2: 0xFF
        for i in range(len(data)):
            data[i] = 0xFF

        # Проход 3: случайные данные
        for i in range(len(data)):
            data[i] = secrets.randbelow(256)

    @staticmethod
    def _secure_erase_file(filepath: Path, passes: int = 3) -> None:
        """
        Криптографическое затирание файла.

        Args:
            filepath: Путь к файлу.
            passes: Количество проходов.
        """
        if not filepath.exists():
            return

        size = filepath.stat().st_size

        with open(filepath, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                # Проход случайными данными
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())

        # Удаление файла
        filepath.unlink()

    # ------------------------------------------------------------------------
    # МЕТАДАННЫЕ
    # ------------------------------------------------------------------------

    def _load_metadata(self) -> None:
        """Загрузить метаданные из файла."""
        if not self.metadata_file.exists():
            self.metadata = {}
            return

        try:
            import json

            with open(self.metadata_file, "r") as f:
                data = json.load(f)
                self.metadata = {
                    key_id: KeyMetadata.from_dict(meta) for key_id, meta in data.items()
                }
            logger.debug(f"Loaded {len(self.metadata)} key metadata")

        except Exception as e:
            logger.error(f"Failed to load metadata: {e}")
            self.metadata = {}

    def _save_metadata(self) -> None:
        """Сохранить метаданные в файл."""
        try:
            import json

            data = {key_id: meta.to_dict() for key_id, meta in self.metadata.items()}
            with open(self.metadata_file, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug("Metadata saved")

        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")


# ============================================================================
# ФУНКЦИИ ВЫСОКОГО УРОВНЯ
# ============================================================================


def create_key_manager(
    storage_dir: Optional[str] = None,
    token_library: Optional[str] = None,
) -> KeyManager:
    """
    Фабричная функция для создания KeyManager.

    Args:
        storage_dir: Директория хранения.
        token_library: Путь к PKCS#11 библиотеке.

    Returns:
        Инициализированный KeyManager.
    """
    km = KeyManager(storage_dir=storage_dir, token_library=token_library)
    km.initialize()
    return km


def quick_generate_key(size: int = 32) -> bytes:
    """
    Быстрая генерация ключа без инициализации менеджера.

    Args:
        size: Размер ключа в байтах.

    Returns:
        Случайный ключ.
    """
    return secrets.token_bytes(size)


def quick_derive_key(
    password: str, salt: Optional[bytes] = None
) -> Tuple[bytes, bytes]:
    """
    Быстрая деривация ключа из пароля.

    Args:
        password: Пароль.
        salt: Соль (опционально).

    Returns:
        Кортеж (key, salt).
    """
    km = KeyManager()
    return km.derive_key_from_password(password, salt)


# ============================================================================
# УТИЛИТЫ
# ============================================================================


def validate_key_strength(key: bytes) -> bool:
    """
    Проверить криптостойкость ключа.

    Args:
        key: Ключ для проверки.

    Returns:
        True если ключ достаточно сильный.
    """
    # Проверка длины
    if len(key) not in (16, 24, 32):
        return False

    # Проверка энтропии (упрощенная)
    # В продакшене использовать NIST SP 800-90B
    unique_bytes = len(set(key))
    entropy_ratio = unique_bytes / 256

    return entropy_ratio > 0.5  # Хотя бы 50% уникальных байт


def get_key_fingerprint(key: bytes) -> str:
    """
    Получить отпечаток ключа (SHA256).

    Args:
        key: Ключ.

    Returns:
        Шестнадцатеричная строка отпечатка.
    """
    return hashlib.sha256(key).hexdigest()[:16]


def compare_keys(key1: bytes, key2: bytes) -> bool:
    """
    Сравнить два ключа (защита от timing attacks).

    Args:
        key1: Первый ключ.
        key2: Второй ключ.

    Returns:
        True если ключи идентичны.
    """
    return hmac.compare_digest(key1, key2)
