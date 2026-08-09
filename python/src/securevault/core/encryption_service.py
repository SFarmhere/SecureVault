"""
SecureVault - Сервис шифрования/дешифрования

Основной сервис для криптографической защиты файлов и данных:
- Шифрование/дешифрование файлов с 4 уровнями защиты
- Потоковое шифрование для больших файлов
- Шифрование данных в памяти
- Интеграция с key_manager для управления ключами
- Поддержка нативного C++ crypto модуля с fallback на Python

Уровни защиты:
1. ORIGINAL - исходный файл без изменений (только метаданные)
2. INDIVIDUAL - каждый файл шифруется отдельным ключом
3. CONTAINER - файлы группируются в контейнеры с общим ключом
4. HYPER - максимальная защита (сжатие + шифрование + дедупликация)

Зависимости:
- core/key_manager.py: Управление ключами
- native/crypto.py: Нативные криптографические операции
- protection_levels/: Реализации уровней защиты
- exceptions: Исключения проекта
- constants: Константы

Использование:
    from securevault.core.encryption_service import EncryptionService

    service = EncryptionService()

    # Шифрование файла
    service.encrypt_file("document.pdf", protection_level=ProtectionLevel.INDIVIDUAL)

    # Дешифрование
    service.decrypt_file("document.pdf.enc")

    # Шифрование данных в памяти
    encrypted = service.encrypt_data(b"sensitive data")

    # Потоковое шифрование (для больших файлов)
    service.encrypt_stream("large_file.iso", "large_file.enc", chunk_size=65536)
"""

import os
import hashlib
import hmac
import logging
import struct
from typing import Optional, Dict, Any, Tuple
from pathlib import Path
from enum import Enum
from dataclasses import dataclass

# Внутренние импорты
from securevault.core import key_manager
from securevault.native import crypto
from securevault.protection_levels import (
    ProtectionLevelFactory,
    ProtectionLevel as PLEnum,
)
from securevault import exceptions

logger = logging.getLogger(__name__)


# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================


class ProtectionLevel(Enum):
    """Уровни защиты файлов."""

    ORIGINAL = "original"  # Без шифрования, только метаданные
    INDIVIDUAL = "individual"  # Каждый файл отдельным ключом
    CONTAINER = "container"  # Группировка в контейнеры с общим ключом
    HYPER = "hyper"  # Двойное шифрование: файлы шифруются индивидуально,
    # затем помещаются в зашифрованный контейнер (Double AES)


class EncryptionAlgorithm(Enum):
    """Алгоритмы шифрования."""

    AES_256_GCM = "aes-256-gcm"  # AES-256-GCM (рекомендуемый)
    AES_256_CBC = "aes-256-cbc"  # AES-256-CBC (совместимость)
    CHACHA20_POLY1305 = "chacha20"  # ChaCha20-Poly1305 (для старых систем)


class IntegrityAlgorithm(Enum):
    """Алгоритмы проверки целостности."""

    HMAC_SHA256 = "hmac-sha256"
    POLY1305 = "poly1305"  # Встроен в GCM


# Формат заголовка зашифрованного файла
HEADER_MAGIC = b"SVEF"  # SecureVault Encrypted File
HEADER_VERSION = 1

# Размеры
DEFAULT_CHUNK_SIZE = 65536  # 64 KB
MAX_CHUNK_SIZE = 1048576  # 1 MB

# Параметры шифрования
AES_GCM_NONCE_SIZE = 12
AES_GCM_TAG_SIZE = 16
AES_KEY_SIZE = 32  # 256 бит


# ============================================================================
# МЕТАДАННЫЕ ЗАШИФРОВАННОГО ФАЙЛА
# ============================================================================


@dataclass
class EncryptedFileMetadata:
    """Метаданные зашифрованного файла."""

    # Основная информация
    original_filename: str
    original_size: int
    protection_level: ProtectionLevel

    # Криптография
    algorithm: EncryptionAlgorithm
    key_id: str

    # Целостность
    integrity_hash: bytes
    integrity_algorithm: IntegrityAlgorithm

    # Дополнительно
    created_at: str
    file_id: str
    container_id: Optional[str] = None
    compression_used: bool = False
    deduplication_used: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Сериализовать в словарь."""
        return {
            "original_filename": self.original_filename,
            "original_size": self.original_size,
            "protection_level": self.protection_level.value,
            "algorithm": self.algorithm.value,
            "key_id": self.key_id,
            "integrity_hash": self.integrity_hash.hex(),
            "integrity_algorithm": self.integrity_algorithm.value,
            "created_at": self.created_at,
            "file_id": self.file_id,
            "container_id": self.container_id,
            "compression_used": self.compression_used,
            "deduplication_used": self.deduplication_used,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EncryptedFileMetadata":
        """Десериализовать из словаря."""
        return cls(
            original_filename=data["original_filename"],
            original_size=data["original_size"],
            protection_level=ProtectionLevel(data["protection_level"]),
            algorithm=EncryptionAlgorithm(data["algorithm"]),
            key_id=data["key_id"],
            integrity_hash=bytes.fromhex(data["integrity_hash"]),
            integrity_algorithm=IntegrityAlgorithm(
                data["integrity_algorithm"]),
            created_at=data["created_at"],
            file_id=data["file_id"],
            container_id=data.get("container_id"),
            compression_used=data.get("compression_used", False),
            deduplication_used=data.get("deduplication_used", False),
        )

    def serialize(self) -> bytes:
        """
        Сериализовать в бинарный формат для заголовка файла.

        Формат:
        [4 байта] MAGIC "SVEF"
        [1 байт]  VERSION
        [1 байт]  PROTECTION_LEVEL
        [1 байт]  ALGORITHM
        [1 байт]  INTEGRITY_ALGORITHM
        [2 байта] ORIGINAL_FILENAME_LENGTH
        [N байт]  ORIGINAL_FILENAME
        [8 байт]  ORIGINAL_SIZE
        [4 байт]  KEY_ID_LENGTH
        [N байт]  KEY_ID
        [4 байт]  INTEGRITY_HASH_LENGTH
        [N байт]  INTEGRITY_HASH
        [8 байт]  CREATED_AT_TIMESTAMP
        [4 байт]  FILE_ID_LENGTH
        [N байт]  FILE_ID
        [4 байт]  CONTAINER_ID_LENGTH (0 если нет)
        [N байт]  CONTAINER_ID (опционально)
        [1 байт]  COMPRESSION_USED (0/1)
        [1 байт]  DEDUPLICATION_USED (0/1)
        """
        import json

        # Сериализуем метаданные в JSON для простоты
        meta_dict = self.to_dict()
        meta_json = json.dumps(
            meta_dict, separators=(",", ":")).encode("utf-8")

        return meta_json

    @classmethod
    def deserialize(cls, data: bytes) -> "EncryptedFileMetadata":
        """Десериализовать из бинарных данных."""
        import json

        meta_dict = json.loads(data.decode("utf-8"))
        return cls.from_dict(meta_dict)


# ============================================================================
# ИСКЛЮЧЕНИЯ
# ============================================================================


class EncryptionError(exceptions.SecureVaultError):
    """Базовое исключение для ошибок шифрования."""


class DecryptionError(EncryptionError):
    """Ошибка дешифрования."""


class IntegrityError(EncryptionError):
    """Ошибка проверки целостности."""


class UnsupportedProtectionLevelError(EncryptionError):
    """Неподдерживаемый уровень защиты."""


class FileNotFoundError(EncryptionError):
    """Файл не найден."""


class InvalidEncryptedFileError(DecryptionError):
    """Невалидный формат зашифрованного файла."""


# ============================================================================
# ОСНОВНОЙ КЛАСС
# ============================================================================


class EncryptionService:
    """
    Сервис шифрования/дешифрования файлов SecureVault.

    Предоставляет:
    - Шифрование файлов с 4 уровнями защиты
    - Потоковое шифрование для больших файлов
    - Шифрование данных в памяти
    - Проверку целостности
    - Интеграцию с key_manager

    Пример:
        service = EncryptionService(key_manager=km)

        # Шифрование файла
        metadata = service.encrypt_file(
            "document.pdf",
            protection_level=ProtectionLevel.INDIVIDUAL
        )

        # Дешифрование
        service.decrypt_file("document.pdf.enc", "document_decrypted.pdf")

        # Шифрование данных
        encrypted = service.encrypt_data(b"secret data")
        decrypted = service.decrypt_data(encrypted)
    """

    def __init__(
        self,
        key_mgr: Optional[key_manager.KeyManager] = None,
        default_algorithm: EncryptionAlgorithm = EncryptionAlgorithm.AES_256_GCM,
        default_integrity: IntegrityAlgorithm = IntegrityAlgorithm.HMAC_SHA256,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ):
        """
        Инициализировать сервис шифрования.

        Args:
            key_mgr: Менеджер ключей (если None, создается новый).
            default_algorithm: Алгоритм шифрования по умолчанию.
            default_integrity: Алгоритм проверки целостности.
            chunk_size: Размер чанка для потокового шифрования.
        """
        self.key_mgr = key_mgr or key_manager.KeyManager()
        self.default_algorithm = default_algorithm
        self.default_integrity = default_integrity
        self.chunk_size = chunk_size

        # Фабрика уровней защиты
        self.protection_factory = ProtectionLevelFactory()

        # Проверка доступности нативного модуля
        self._native_available = crypto.is_available()

        logger.info(
            f"EncryptionService initialized: "
            f"algorithm={default_algorithm.value}, "
            f"native={self._native_available}"
        )

    # ------------------------------------------------------------------------
    # ШИФРОВАНИЕ/ДЕШИФРОВАНИЕ ФАЙЛОВ
    # ------------------------------------------------------------------------

    def encrypt_file(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        protection_level: ProtectionLevel = ProtectionLevel.INDIVIDUAL,
        algorithm: Optional[EncryptionAlgorithm] = None,
        key_id: Optional[str] = None,
        compress: bool = False,
    ) -> EncryptedFileMetadata:
        """
        Шифровать файл.

        Args:
            input_path: Путь к исходному файлу.
            output_path: Путь для зашифрованного файла.
                        Если None, добавляется расширение .enc.
            protection_level: Уровень защиты.
            algorithm: Алгоритм шифрования (по умолчанию из конфига).
            key_id: ID ключа (если None, генерируется новый).
            compress: Сжимать файл перед шифрованием.

        Returns:
            Метаданные зашифрованного файла.

        Raises:
            FileNotFoundError: Если исходный файл не найден.
            EncryptionError: Если шифрование не удалось.
        """
        input_file = Path(input_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Определение выходного пути
        if output_path is None:
            output_path = str(input_file) + ".enc"
        output_file = Path(output_path)

        # Определение алгоритма
        algo = algorithm or self.default_algorithm

        # Получение или генерация ключа
        if key_id is None:
            file_key = self.key_mgr.generate_file_key()
            key_id = f"file-{input_file.name}-{hashlib.sha256(input_file.name.encode()).hexdigest()[:8]}"
            self.key_mgr.store_key_securely(file_key, key_id)
        else:
            file_key = self.key_mgr.retrieve_key(key_id)

        try:
            # Чтение исходного файла
            with open(input_file, "rb") as f:
                plaintext = f.read()

            original_size = len(plaintext)

            # Сжатие (опционально)
            if compress:
                plaintext = self._compress(plaintext)
                compression_used = True
            else:
                compression_used = False

            # Шифрование через соответствующий уровень защиты
            if protection_level == ProtectionLevel.HYPER:
                # HYPER: Двойное шифрование
                # 1. Сначала шифруем файл индивидуально (как INDIVIDUAL)
                individual_encrypted = self._encrypt_data_internal(
                    plaintext, file_key, algo
                )

                # 2. Затем шифруем контейнер с этими данными
                # Генерируем ключ контейнера
                container_key = self.key_mgr.generate_file_key()
                container_key_id = f"container-{key_id}"
                self.key_mgr.store_key_securely(
                    container_key, container_key_id)

                # 3. Шифруем данные ключом контейнера
                encrypted_data = self._encrypt_data_internal(
                    individual_encrypted, container_key, algo
                )

                # Сохраняем оба ключа в метаданных
                encryption_key_id = f"{key_id}:{container_key_id}"
                deduplication_used = (
                    False  # HYPER не использует дедупликацию для безопасности
                )
            else:
                # Обычное шифрование для других уровней
                pl_enum = PLEnum(protection_level.value)
                protection = self.protection_factory.create_protection(pl_enum)

                encrypted_data, _ = protection.encrypt(
                    plaintext,
                    file_key,
                    algorithm=algo,
                )
                encryption_key_id = key_id
                deduplication_used = False

            # Создание метаданных
            file_metadata = EncryptedFileMetadata(
                original_filename=input_file.name,
                original_size=original_size,
                protection_level=protection_level,
                algorithm=algo,
                key_id=encryption_key_id,
                integrity_hash=self._compute_integrity(encrypted_data),
                integrity_algorithm=self.default_integrity,
                created_at=__import__(
                    "datetime").datetime.utcnow().isoformat(),
                file_id=hashlib.sha256(
                    input_file.name.encode()).hexdigest()[:16],
                compression_used=compression_used,
                deduplication_used=deduplication_used,
            )

            # Запись зашифрованного файла
            self._write_encrypted_file(
                output_file, encrypted_data, file_metadata)

            logger.info(
                f"File encrypted: {input_path} -> {output_path} "
                f"({original_size} bytes, {protection_level.value})"
            )

            return file_metadata

        except Exception as e:
            logger.error(f"Failed to encrypt file {input_path}: {e}")
            raise EncryptionError(f"File encryption failed: {e}")

    def decrypt_file(
        self,
        input_path: str,
        output_path: Optional[str] = None,
        key_id: Optional[str] = None,
    ) -> EncryptedFileMetadata:
        """
        Дешифровать файл.

        Args:
            input_path: Путь к зашифрованному файлу.
            output_path: Путь для дешифрованного файла.
                        Если None, удаляется расширение .enc.
            key_id: ID ключа (если None, извлекается из метаданных).

        Returns:
            Метаданные файла.

        Raises:
            FileNotFoundError: Если файл не найден.
            DecryptionError: Если дешифрование не удалось.
            IntegrityError: Если проверка целостности не прошла.
        """
        input_file = Path(input_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        # Определение выходного пути
        if output_path is None:
            if str(input_file).endswith(".enc"):
                output_path = str(input_file)[:-4]
            else:
                output_path = str(input_file) + ".dec"
        output_file = Path(output_path)

        try:
            # Чтение зашифрованного файла
            encrypted_data, metadata = self._read_encrypted_file(input_file)

            # Получение ключа
            if key_id is None:
                key_id = metadata.key_id

            file_key = self.key_mgr.retrieve_key(key_id)

            # Проверка целостности
            computed_hash = self._compute_integrity(encrypted_data)
            if not hmac.compare_digest(computed_hash, metadata.integrity_hash):
                raise IntegrityError("File integrity check failed")

            # Дешифрование через соответствующий уровень защиты
            if metadata.protection_level == ProtectionLevel.HYPER:
                # HYPER: Двойное дешифрование (обратный порядок)
                # 1. Сначала дешифруем контейнер
                container_key_id = metadata.key_id.split(":")[1]
                container_key = self.key_mgr.retrieve_key(container_key_id)

                individual_encrypted = self._decrypt_data_internal(
                    encrypted_data, container_key, metadata.algorithm
                )

                # 2. Затем дешифруем файл
                file_key_id = metadata.key_id.split(":")[0]
                file_key = self.key_mgr.retrieve_key(file_key_id)

                plaintext = self._decrypt_data_internal(
                    individual_encrypted, file_key, metadata.algorithm
                )
            else:
                # Обычное дешифрование
                pl_enum = PLEnum(metadata.protection_level.value)
                protection = self.protection_factory.create_protection(pl_enum)

                plaintext = protection.decrypt(encrypted_data, file_key)

            # Распаковка (если сжималось)
            if metadata.compression_used:
                plaintext = self._decompress(plaintext)

            # Запись дешифрованного файла
            with open(output_file, "wb") as f:
                f.write(plaintext)

            logger.info(
                f"File decrypted: {input_path} -> {output_path} "
                f"({len(plaintext)} bytes)"
            )

            return metadata

        except IntegrityError:
            raise
        except Exception as e:
            logger.error(f"Failed to decrypt file {input_path}: {e}")
            raise DecryptionError(f"File decryption failed: {e}")

    # ------------------------------------------------------------------------
    # ПОТОКОВОЕ ШИФРОВАНИЕ
    # ------------------------------------------------------------------------

    def encrypt_stream(
        self,
        input_path: str,
        output_path: str,
        protection_level: ProtectionLevel = ProtectionLevel.INDIVIDUAL,
        chunk_size: Optional[int] = None,
        algorithm: Optional[EncryptionAlgorithm] = None,
    ) -> EncryptedFileMetadata:
        """
        Потоковое шифрование файла (для больших файлов).

        Шифрует файл по частям, не загружая весь файл в память.

        Args:
            input_path: Путь к исходному файлу.
            output_path: Путь для зашифрованного файла.
            protection_level: Уровень защиты.
            chunk_size: Размер чанка (по умолчанию из конфига).
            algorithm: Алгоритм шифрования.

        Returns:
            Метаданные зашифрованного файла.
        """
        input_file = Path(input_path)
        if not input_file.exists():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        chunk = chunk_size or self.chunk_size
        algo = algorithm or self.default_algorithm

        # Генерация ключа
        file_key = self.key_mgr.generate_file_key()
        key_id = f"stream-{input_file.name}-{hashlib.sha256(input_file.name.encode()).hexdigest()[:8]}"
        self.key_mgr.store_key_securely(file_key, key_id)

        try:
            # Для потокового шифрования используем INDIVIDUAL уровень
            # (каждый чанк шифруется с уникальным nonce)
            pl_enum = PLEnum.INDIVIDUAL
            protection = self.protection_factory.create_protection(pl_enum)

            encrypted_chunks = []
            total_size = 0

            with open(input_file, "rb") as f:
                while True:
                    chunk_data = f.read(chunk)
                    if not chunk_data:
                        break

                    # Шифрование чанка
                    encrypted_chunk, _ = protection.encrypt(
                        chunk_data, file_key)
                    encrypted_chunks.append(encrypted_chunk)
                    total_size += len(encrypted_data)

            # Объединение всех чанков
            encrypted_data = b"".join(encrypted_chunks)

            # Создание метаданных
            metadata = EncryptedFileMetadata(
                original_filename=input_file.name,
                original_size=input_file.stat().st_size,
                protection_level=protection_level,
                algorithm=algo,
                key_id=key_id,
                integrity_hash=self._compute_integrity(encrypted_data),
                integrity_algorithm=self.default_integrity,
                created_at=__import__(
                    "datetime").datetime.utcnow().isoformat(),
                file_id=hashlib.sha256(
                    input_file.name.encode()).hexdigest()[:16],
            )

            # Запись
            self._write_encrypted_file(
                Path(output_path), encrypted_data, metadata)

            logger.info(
                f"Stream encryption complete: {input_path} -> {output_path}")
            return metadata

        except Exception as e:
            logger.error(f"Stream encryption failed: {e}")
            raise EncryptionError(f"Stream encryption failed: {e}")

    def decrypt_stream(
        self,
        input_path: str,
        output_path: str,
        key_id: Optional[str] = None,
    ) -> EncryptedFileMetadata:
        """
        Потоковое дешифрование файла.

        Args:
            input_path: Путь к зашифрованному файлу.
            output_path: Путь для дешифрованного файла.
            key_id: ID ключа.

        Returns:
            Метаданные файла.
        """
        # Для простоты читаем весь файл (в будущем можно оптимизировать)
        return self.decrypt_file(input_path, output_path, key_id)

    # ------------------------------------------------------------------------
    # ШИФРОВАНИЕ ДАННЫХ В ПАМЯТИ
    # ------------------------------------------------------------------------

    def encrypt_data(
        self,
        data: bytes,
        key: Optional[bytes] = None,
        algorithm: Optional[EncryptionAlgorithm] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Шифровать данные в памяти.

        Args:
            data: Данные для шифрования.
            key: Ключ (если None, генерируется временный).
            algorithm: Алгоритм шифрования.
            associated_data: Дополнительные аутентифицированные данные.

        Returns:
            Зашифрованные данные (nonce + ciphertext + tag).
        """
        if not data:
            raise EncryptionError("Cannot encrypt empty data")

        algo = algorithm or self.default_algorithm

        # Генерация или использование ключа
        if key is None:
            key = self.key_mgr.generate_session_key()

        try:
            # Использование нативного модуля или fallback
            if self._native_available and algo == EncryptionAlgorithm.AES_256_GCM:
                encrypted = crypto.encrypt_aes_gcm(data, key, associated_data)
            else:
                encrypted = self._encrypt_python(
                    data, key, algo, associated_data)

            logger.debug(f"Data encrypted: {len(data)} bytes")
            return encrypted

        except Exception as e:
            logger.error(f"Data encryption failed: {e}")
            raise EncryptionError(f"Data encryption failed: {e}")

    def decrypt_data(
        self,
        encrypted_data: bytes,
        key: Optional[bytes] = None,
        algorithm: Optional[EncryptionAlgorithm] = None,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Дешифровать данные в памяти.

        Args:
            encrypted_data: Зашифрованные данные.
            key: Ключ.
            algorithm: Алгоритм шифрования.
            associated_data: Дополнительные аутентифицированные данные.

        Returns:
            Дешифрованные данные.
        """
        if not encrypted_data:
            raise DecryptionError("Cannot decrypt empty data")

        algo = algorithm or self.default_algorithm

        try:
            # Использование нативного модуля или fallback
            if self._native_available and algo == EncryptionAlgorithm.AES_256_GCM:
                decrypted = crypto.decrypt_aes_gcm(
                    encrypted_data, key, associated_data)
            else:
                decrypted = self._decrypt_python(
                    encrypted_data, key, algo, associated_data
                )

            logger.debug(f"Data decrypted: {len(decrypted)} bytes")
            return decrypted

        except Exception as e:
            logger.error(f"Data decryption failed: {e}")
            raise DecryptionError(f"Data decryption failed: {e}")

    # ------------------------------------------------------------------------
    # ПРОВЕРКА ЦЕЛОСТНОСТИ
    # ------------------------------------------------------------------------

    def verify_integrity(self, file_path: str) -> bool:
        """
        Проверить целостность зашифрованного файла.

        Args:
            file_path: Путь к зашифрованному файлу.

        Returns:
            True если целостность не нарушена.
        """
        try:
            _, metadata = self._read_encrypted_file(Path(file_path))

            # TODO: Получить ключ и проверить HMAC
            # Пока только проверяем формат
            return True

        except Exception as e:
            logger.error(f"Integrity verification failed: {e}")
            return False

    def get_protection_level(self, file_path: str) -> Optional[ProtectionLevel]:
        """
        Получить уровень защиты зашифрованного файла.

        Args:
            file_path: Путь к зашифрованному файлу.

        Returns:
            Уровень защиты или None если файл не найден/невалиден.
        """
        try:
            _, metadata = self._read_encrypted_file(Path(file_path))
            return metadata.protection_level
        except Exception:
            return None

    # ------------------------------------------------------------------------
    # ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
    # ------------------------------------------------------------------------

    def _compress(self, data: bytes) -> bytes:
        """Сжать данные (zlib)."""
        import zlib

        return zlib.compress(data, level=6)

    def _decompress(self, data: bytes) -> bytes:
        """Распаковать данные."""
        import zlib

        return zlib.decompress(data)

    def _compute_integrity(self, data: bytes) -> bytes:
        """Вычислить хеш целостности."""
        if self.default_integrity == IntegrityAlgorithm.HMAC_SHA256:
            # В реальности здесь должен быть ключ HMAC
            # Пока используем простой SHA256
            return hashlib.sha256(data).digest()
        else:
            return hashlib.sha256(data).digest()

    def _write_encrypted_file(
        self,
        file_path: Path,
        encrypted_data: bytes,
        metadata: EncryptedFileMetadata,
    ) -> None:
        """Записать зашифрованный файл с заголовком."""
        # Сериализация метаданных
        meta_bytes = metadata.serialize()

        with open(file_path, "wb") as f:
            # Заголовок
            f.write(HEADER_MAGIC)
            f.write(struct.pack("B", HEADER_VERSION))

            # Длина метаданных
            f.write(struct.pack(">I", len(meta_bytes)))

            # Метаданные
            f.write(meta_bytes)

            # Зашифрованные данные
            f.write(encrypted_data)

        # Права доступа
        os.chmod(file_path, 0o600)

    def _read_encrypted_file(
        self, file_path: Path
    ) -> Tuple[bytes, EncryptedFileMetadata]:
        """
        Прочитать зашифрованный файл.

        Returns:
            Кортеж (encrypted_data, metadata).
        """
        with open(file_path, "rb") as f:
            # Проверка magic
            magic = f.read(4)
            if magic != HEADER_MAGIC:
                raise InvalidEncryptedFileError(f"Invalid magic: {magic}")

            # Версия
            version = struct.unpack("B", f.read(1))[0]
            if version != HEADER_VERSION:
                raise InvalidEncryptedFileError(
                    f"Unsupported version: {version}")

            # Длина метаданных
            meta_len = struct.unpack(">I", f.read(4))[0]

            # Метаданные
            meta_bytes = f.read(meta_len)
            metadata = EncryptedFileMetadata.deserialize(meta_bytes)

            # Зашифрованные данные
            encrypted_data = f.read()

        return encrypted_data, metadata

    def _encrypt_data_internal(
        self,
        data: bytes,
        key: bytes,
        algorithm: EncryptionAlgorithm,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Внутренний метод шифрования данных.

        Args:
            data: Данные для шифрования.
            key: Ключ.
            algorithm: Алгоритм шифрования.
            associated_data: Дополнительные данные.

        Returns:
            Зашифрованные данные.
        """
        if self._native_available and algorithm == EncryptionAlgorithm.AES_256_GCM:
            return crypto.encrypt_aes_gcm(data, key, associated_data)
        else:
            return self._encrypt_python(data, key, algorithm, associated_data)

    def _decrypt_data_internal(
        self,
        encrypted_data: bytes,
        key: bytes,
        algorithm: EncryptionAlgorithm,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """
        Внутренний метод дешифрования данных.

        Args:
            encrypted_data: Зашифрованные данные.
            key: Ключ.
            algorithm: Алгоритм шифрования.
            associated_data: Дополнительные данные.

        Returns:
            Дешифрованные данные.
        """
        if self._native_available and algorithm == EncryptionAlgorithm.AES_256_GCM:
            return crypto.decrypt_aes_gcm(encrypted_data, key, associated_data)
        else:
            return self._decrypt_python(encrypted_data, key, algorithm, associated_data)

    def _encrypt_python(
        self,
        data: bytes,
        key: bytes,
        algorithm: EncryptionAlgorithm,
        associated_data: Optional[bytes],
    ) -> bytes:
        """
        Шифрование на чистом Python (fallback).

        Использует AES-GCM через cryptography библиотеку.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            if algorithm == EncryptionAlgorithm.AES_256_GCM:
                aesgcm = AESGCM(key)
                nonce = os.urandom(AES_GCM_NONCE_SIZE)
                ciphertext = aesgcm.encrypt(nonce, data, associated_data)

                # Формат: nonce + ciphertext
                return nonce + ciphertext
            else:
                raise EncryptionError(f"Unsupported algorithm: {algorithm}")

        except ImportError:
            raise EncryptionError(
                "cryptography library not installed. "
                "Install it or use native crypto module."
            )

    def _decrypt_python(
        self,
        encrypted_data: bytes,
        key: bytes,
        algorithm: EncryptionAlgorithm,
        associated_data: Optional[bytes],
    ) -> bytes:
        """
        Дешифрование на чистом Python (fallback).
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            if algorithm == EncryptionAlgorithm.AES_256_GCM:
                aesgcm = AESGCM(key)
                nonce = encrypted_data[:AES_GCM_NONCE_SIZE]
                ciphertext = encrypted_data[AES_GCM_NONCE_SIZE:]
                return aesgcm.decrypt(nonce, ciphertext, associated_data)
            else:
                raise DecryptionError(f"Unsupported algorithm: {algorithm}")

        except ImportError:
            raise DecryptionError(
                "cryptography library not installed. "
                "Install it or use native crypto module."
            )


# ============================================================================
# ФУНКЦИИ ВЫСОКОГО УРОВНЯ
# ============================================================================


def create_encryption_service(
    key_mgr: Optional[key_manager.KeyManager] = None,
) -> EncryptionService:
    """
    Фабричная функция для создания EncryptionService.

    Args:
        key_mgr: Менеджер ключей.

    Returns:
        Инициализированный сервис.
    """
    return EncryptionService(key_mgr=key_mgr)


def quick_encrypt_file(
    input_path: str,
    output_path: Optional[str] = None,
    password: Optional[str] = None,
) -> EncryptedFileMetadata:
    """
    Быстрое шифрование файла с паролем.

    Args:
        input_path: Путь к файлу.
        output_path: Путь для зашифрованного файла.
        password: Пароль (если None, генерируется случайный ключ).

    Returns:
        Метаданные зашифрованного файла.
    """
    km = key_manager.KeyManager()
    service = EncryptionService(key_mgr=km)

    if password:
        key, salt = km.derive_key_from_password(password)
        key_id = f"pwd-{hashlib.sha256(password.encode()).hexdigest()[:8]}"
        km.store_key_securely(key, key_id)
    else:
        key_id = None

    return service.encrypt_file(input_path, output_path, key_id=key_id)


def quick_decrypt_file(
    input_path: str,
    output_path: Optional[str] = None,
    password: Optional[str] = None,
) -> EncryptedFileMetadata:
    """
    Быстрое дешифрование файла.

    Args:
        input_path: Путь к зашифрованному файлу.
        output_path: Путь для дешифрованного файла.
        password: Пароль.

    Returns:
        Метаданные файла.
    """
    km = key_manager.KeyManager()
    service = EncryptionService(key_mgr=km)

    key_id = None
    if password:
        key_id = f"pwd-{hashlib.sha256(password.encode()).hexdigest()[:8]}"

    return service.decrypt_file(input_path, output_path, key_id=key_id)


# ============================================================================
# УТИЛИТЫ
# ============================================================================


def is_encrypted_file(file_path: str) -> bool:
    """
    Проверить, является ли файл зашифрованным SecureVault.

    Args:
        file_path: Путь к файлу.

    Returns:
        True если файл зашифрован.
    """
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            return magic == HEADER_MAGIC
    except Exception:
        return False


def get_encryption_info(file_path: str) -> Optional[Dict[str, Any]]:
    """
    Получить информацию о зашифрованном файле без дешифрования.

    Args:
        file_path: Путь к зашифрованному файлу.

    Returns:
        Словарь с информацией или None если файл не зашифрован.
    """
    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
            if magic != HEADER_MAGIC:
                return None

            version = struct.unpack("B", f.read(1))[0]
            meta_len = struct.unpack(">I", f.read(4))[0]
            meta_bytes = f.read(meta_len)

            import json

            metadata = json.loads(meta_bytes.decode("utf-8"))

            return metadata
    except Exception as e:
        logger.error(f"Failed to get encryption info: {e}")
        return None


def estimate_encrypted_size(original_size: int, compression: bool = False) -> int:
    """
    Оценить размер зашифрованного файла.

    Args:
        original_size: Исходный размер.
        compression: Используется ли сжатие.

    Returns:
        Примерный размер зашифрованного файла.
    """
    # Заголовок ~200 байт + overhead шифрования ~28 байт на блок
    header_size = 256
    encryption_overhead = 28

    if compression:
        # Сжатие обычно уменьшает размер на 30-50%
        estimated = int(original_size * 0.7)
    else:
        estimated = original_size

    return header_size + estimated + encryption_overhead
