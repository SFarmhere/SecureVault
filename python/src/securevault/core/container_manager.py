"""
SecureVault - Менеджер контейнеров

Управление виртуальными контейнерами для группировки файлов:
- Создание, монтирование, размонтирование контейнеров
- Добавление и извлечение файлов
- Дедупликация блоков (CDC - Content-Defined Chunking)
- Интеграция с encryption_service для шифрования
- Поддержка нативного C++ container модуля

Контейнеры позволяют:
1. Группировать связанные файлы под одним ключом
2. Экономить место за счет дедупликации
3. Упрощать управление большими объемами данных
4. Реализовывать HYPER уровень защиты

Зависимости:
- core/key_manager.py: Управление ключами
- core/encryption_service.py: Шифрование файлов
- native/container.py: Нативные операции с контейнерами
- storage/deduplication_chunking.py: Дедупликация
- exceptions: Исключения проекта
- constants: Константы

Использование:
    from securevault.core.container_manager import ContainerManager

    cm = ContainerManager()

    # Создание контейнера
    container = cm.create_container("my-docs", size_limit=1073741824)  # 1GB

    # Добавление файлов
    cm.add_file(container.id, "document.pdf")
    cm.add_file(container.id, "image.jpg")

    # Просмотр содержимого
    files = cm.list_files(container.id)

    # Извлечение файла
    cm.extract_file(container.id, "document.pdf", "./extracted/")

    # Удаление файла
    cm.delete_file(container.id, "image.jpg")

    # Размонтирование
    cm.unmount_container(container.id)
"""

import os
import json
import hashlib
import logging
import shutil
from typing import Optional, List, Dict, Any, BinaryIO
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

# Внутренние импорты
from securevault.core import key_manager
from securevault.core import encryption_service
from securevault.native import container as native_container
from securevault.storage import deduplication_chunking
from securevault import exceptions
from securevault import constants

logger = logging.getLogger(__name__)


# ============================================================================
# КОНСТАНТЫ И КОНФИГУРАЦИЯ
# ============================================================================

class ContainerStatus(Enum):
    """Статусы контейнера."""
    CREATED = "created"           # Создан, но не смонтирован
    MOUNTED = "mounted"           # Смонтирован и готов к использованию
    SEALED = "sealed"             # Запечатан (только для чтения)
    CORRUPTED = "corrupted"       # Поврежден
    DELETED = "deleted"           # Удален


class ContainerType(Enum):
    """Типы контейнеров."""
    FILESYSTEM = "filesystem"     # Файловая система (директория)
    ARCHIVE = "archive"           # Один архивный файл
    CLOUD = "cloud"               # Облачный контейнер


# Параметры по умолчанию
DEFAULT_CONTAINER_SIZE = 10737418240  # 10 GB
DEFAULT_CHUNK_SIZE = 65536  # 64 KB
DEFAULT_BLOCK_SIZE = 1048576  # 1 MB

# Пути
CONTAINERS_DIR = "containers"
METADATA_FILE = "container_metadata.json"


# ============================================================================
# МЕТАДАННЫЕ КОНТЕЙНЕРА
# ============================================================================

@dataclass
class ContainerMetadata:
    """Метаданные контейнера."""
    
    # Основная информация
    container_id: str
    name: str
    container_type: ContainerType
    status: ContainerStatus
    
    # Размеры и лимиты
    size_limit: int  # Максимальный размер в байтах
    current_size: int  # Текущий размер в байтах
    file_count: int  # Количество файлов
    
    # Криптография
    encryption_key_id: str
    protection_level: encryption_service.ProtectionLevel
    
    # Дедупликация
    deduplication_enabled: bool
    deduplication_ratio: float  # 0.0 - 1.0
    
    # Временные метки
    created_at: str
    mounted_at: Optional[str] = None
    sealed_at: Optional[str] = None
    last_accessed: Optional[str] = None
    
    # Дополнительно
    description: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализовать в словарь."""
        return {
            "container_id": self.container_id,
            "name": self.name,
            "container_type": self.container_type.value,
            "status": self.status.value,
            "size_limit": self.size_limit,
            "current_size": self.current_size,
            "file_count": self.file_count,
            "encryption_key_id": self.encryption_key_id,
            "protection_level": self.protection_level.value,
            "deduplication_enabled": self.deduplication_enabled,
            "deduplication_ratio": self.deduplication_ratio,
            "created_at": self.created_at,
            "mounted_at": self.mounted_at,
            "sealed_at": self.sealed_at,
            "last_accessed": self.last_accessed,
            "description": self.description,
            "tags": self.tags,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContainerMetadata":
        """Десериализовать из словаря."""
        return cls(
            container_id=data["container_id"],
            name=data["name"],
            container_type=ContainerType(data["container_type"]),
            status=ContainerStatus(data["status"]),
            size_limit=data["size_limit"],
            current_size=data["current_size"],
            file_count=data["file_count"],
            encryption_key_id=data["encryption_key_id"],
            protection_level=encryption_service.ProtectionLevel(data["protection_level"]),
            deduplication_enabled=data.get("deduplication_enabled", False),
            deduplication_ratio=data.get("deduplication_ratio", 0.0),
            created_at=data["created_at"],
            mounted_at=data.get("mounted_at"),
            sealed_at=data.get("sealed_at"),
            last_accessed=data.get("last_accessed"),
            description=data.get("description", ""),
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
        )


@dataclass
class FileEntry:
    """Запись о файле в контейнере."""
    
    file_id: str
    filename: str
    original_path: str
    size: int
    encrypted_size: int
    chunk_count: int
    deduplication_ratio: float
    created_at: str
    modified_at: str
    protection_level: encryption_service.ProtectionLevel
    encryption_key_id: str
    integrity_hash: str
    chunks: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Сериализовать в словарь."""
        return {
            "file_id": self.file_id,
            "filename": self.filename,
            "original_path": self.original_path,
            "size": self.size,
            "encrypted_size": self.encrypted_size,
            "chunk_count": self.chunk_count,
            "deduplication_ratio": self.deduplication_ratio,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "protection_level": self.protection_level.value,
            "encryption_key_id": self.encryption_key_id,
            "integrity_hash": self.integrity_hash,
            "chunks": self.chunks,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileEntry":
        """Десериализовать из словаря."""
        return cls(
            file_id=data["file_id"],
            filename=data["filename"],
            original_path=data["original_path"],
            size=data["size"],
            encrypted_size=data["encrypted_size"],
            chunk_count=data["chunk_count"],
            deduplication_ratio=data["deduplication_ratio"],
            created_at=data["created_at"],
            modified_at=data["modified_at"],
            protection_level=encryption_service.ProtectionLevel(data["protection_level"]),
            encryption_key_id=data["encryption_key_id"],
            integrity_hash=data["integrity_hash"],
            chunks=data.get("chunks", []),
        )


# ============================================================================
# ИСКЛЮЧЕНИЯ
# ============================================================================

class ContainerError(exceptions.SecureVaultError):
    """Базовое исключение для ошибок контейнеров."""
    pass


class ContainerNotFoundError(ContainerError):
    """Контейнер не найден."""
    pass


class ContainerAlreadyExistsError(ContainerError):
    """Контейнер уже существует."""
    pass


class ContainerFullError(ContainerError):
    """Контейнер заполнен."""
    pass


class ContainerNotMountedError(ContainerError):
    """Контейнер не смонтирован."""
    pass


class ContainerSealedError(ContainerError):
    """Контейнер запечатан (только для чтения)."""
    pass


class FileNotFoundInContainerError(ContainerError):
    """Файл не найден в контейнере."""
    pass


class FileAlreadyExistsInContainerError(ContainerError):
    """Файл уже существует в контейнере."""
    pass


# ============================================================================
# ОСНОВНОЙ КЛАСС
# ============================================================================

class ContainerManager:
    """
    Менеджер виртуальных контейнеров SecureVault.
    
    Предоставляет:
    - Создание и управление контейнерами
    - Монтирование/размонтирование
    - Добавление и извлечение файлов
    - Дедупликацию блоков (CDC)
    - Интеграцию с encryption_service
    
    Пример:
        cm = ContainerManager(storage_dir="/secure/vault/containers")
        
        # Создание контейнера
        container = cm.create_container(
            name="my-documents",
            size_limit=10 * 1024 * 1024 * 1024,  # 10GB
            enable_deduplication=True
        )
        
        # Монтирование
        cm.mount_container(container.container_id)
        
        # Добавление файлов
        cm.add_file(container.container_id, "/path/to/document.pdf")
        cm.add_file(container.container_id, "/path/to/image.jpg")
        
        # Просмотр содержимого
        files = cm.list_files(container.container_id)
        
        # Извлечение
        cm.extract_file(container.container_id, "document.pdf", "./output/")
        
        # Размонтирование
        cm.unmount_container(container.container_id)
    """
    
    def __init__(
        self,
        storage_dir: Optional[str] = None,
        key_mgr: Optional[key_manager.KeyManager] = None,
        encryption_svc: Optional[encryption_service.EncryptionService] = None,
        default_container_type: ContainerType = ContainerType.FILESYSTEM,
        enable_deduplication: bool = True,
    ):
        """
        Инициализировать менеджер контейнеров.
        
        Args:
            storage_dir: Директория для хранения контейнеров.
                        По умолчанию: ~/.securevault/containers
            key_mgr: Менеджер ключей.
            encryption_svc: Сервис шифрования.
            default_container_type: Тип контейнера по умолчанию.
            enable_deduplication: Включить дедупликацию по умолчанию.
        """
        # Директория хранения
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            home = Path.home()
            self.storage_dir = home / ".securevault" / CONTAINERS_DIR
        
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Менеджер ключей и сервис шифрования
        self.key_mgr = key_mgr or key_manager.KeyManager()
        self.encryption_svc = encryption_svc or encryption_service.EncryptionService(
            key_mgr=self.key_mgr
        )
        
        # Настройки по умолчанию
        self.default_container_type = default_container_type
        self.enable_deduplication = enable_deduplication
        
        # Метаданные контейнеров
        self.metadata_file = self.storage_dir / METADATA_FILE
        self.containers: Dict[str, ContainerMetadata] = {}
        self.files: Dict[str, Dict[str, FileEntry]] = {}  # container_id -> {filename -> FileEntry}
        
        # Загрузка метаданных
        self._load_metadata()
        
        # Нативный модуль
        self._native_available = native_container.is_available() if hasattr(native_container, 'is_available') else False
        
        logger.info(f"ContainerManager initialized: storage={self.storage_dir}")
    
    # ------------------------------------------------------------------------
    # ЖИЗНЕННЫЙ ЦИКЛ КОНТЕЙНЕРА
    # ------------------------------------------------------------------------
    
    def create_container(
        self,
        name: str,
        size_limit: int = DEFAULT_CONTAINER_SIZE,
        container_type: Optional[ContainerType] = None,
        enable_deduplication: Optional[bool] = None,
        protection_level: Optional[encryption_service.ProtectionLevel] = None,
        description: str = "",
        tags: Optional[List[str]] = None,
    ) -> ContainerMetadata:
        """
        Создать новый контейнер.
        
        Args:
            name: Имя контейнера.
            size_limit: Максимальный размер в байтах.
            container_type: Тип контейнера.
            enable_deduplication: Включить дедупликацию.
            protection_level: Уровень защиты.
            description: Описание.
            tags: Теги.
        
        Returns:
            Метаданные созданного контейнера.
        
        Raises:
            ContainerAlreadyExistsError: Если контейнер уже существует.
        """
        # Генерация ID
        container_id = self._generate_container_id(name)
        
        # Проверка существования
        if container_id in self.containers:
            raise ContainerAlreadyExistsError(f"Container {container_id} already exists")
        
        # Определение параметров
        ctype = container_type or self.default_container_type
        dedup = enable_deduplication if enable_deduplication is not None else self.enable_deduplication
        prot_level = protection_level or encryption_service.ProtectionLevel.CONTAINER
        
        # Генерация ключа для контейнера
        container_key = self.key_mgr.generate_file_key()
        key_id = f"container-{container_id}"
        self.key_mgr.store_key_securely(container_key, key_id)
        
        # Создание метаданных
        metadata = ContainerMetadata(
            container_id=container_id,
            name=name,
            container_type=ctype,
            status=ContainerStatus.CREATED,
            size_limit=size_limit,
            current_size=0,
            file_count=0,
            encryption_key_id=key_id,
            protection_level=prot_level,
            deduplication_enabled=dedup,
            deduplication_ratio=0.0,
            created_at=datetime.utcnow().isoformat(),
            description=description,
            tags=tags or [],
        )
        
        try:
            # Создание физической структуры
            self._create_container_structure(container_id, ctype)
            
            # Сохранение метаданных
            self.containers[container_id] = metadata
            self.files[container_id] = {}
            self._save_metadata()
            
            logger.info(f"Container created: {container_id} ({name})")
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to create container {container_id}: {e}")
            # Откат
            if container_id in self.containers:
                del self.containers[container_id]
            raise ContainerError(f"Container creation failed: {e}")
    
    def mount_container(self, container_id: str) -> ContainerMetadata:
        """
        Смонтировать контейнер.
        
        Args:
            container_id: ID контейнера.
        
        Returns:
            Метаданные контейнера.
        
        Raises:
            ContainerNotFoundError: Если контейнер не найден.
            ContainerError: Если монтирование не удалось.
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        metadata = self.containers[container_id]
        
        if metadata.status == ContainerStatus.MOUNTED:
            logger.warning(f"Container {container_id} already mounted")
            return metadata
        
        if metadata.status == ContainerStatus.DELETED:
            raise ContainerError(f"Container {container_id} has been deleted")
        
        try:
            # Монтирование в зависимости от типа
            if metadata.container_type == ContainerType.FILESYSTEM:
                self._mount_filesystem(container_id)
            elif metadata.container_type == ContainerType.ARCHIVE:
                self._mount_archive(container_id)
            
            # Обновление статуса
            metadata.status = ContainerStatus.MOUNTED
            metadata.mounted_at = datetime.utcnow().isoformat()
            metadata.last_accessed = metadata.mounted_at
            self._save_metadata()
            
            logger.info(f"Container mounted: {container_id}")
            return metadata
            
        except Exception as e:
            logger.error(f"Failed to mount container {container_id}: {e}")
            raise ContainerError(f"Container mount failed: {e}")
    
    def unmount_container(self, container_id: str) -> None:
        """
        Размонтировать контейнер.
        
        Args:
            container_id: ID контейнера.
        
        Raises:
            ContainerNotFoundError: Если контейнер не найден.
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        metadata = self.containers[container_id]
        
        if metadata.status != ContainerStatus.MOUNTED:
            logger.warning(f"Container {container_id} is not mounted")
            return
        
        try:
            # Размонтирование
            if metadata.container_type == ContainerType.FILESYSTEM:
                self._unmount_filesystem(container_id)
            elif metadata.container_type == ContainerType.ARCHIVE:
                self._unmount_archive(container_id)
            
            # Обновление статуса
            metadata.status = ContainerStatus.CREATED
            metadata.mounted_at = None
            self._save_metadata()
            
            logger.info(f"Container unmounted: {container_id}")
            
        except Exception as e:
            logger.error(f"Failed to unmount container {container_id}: {e}")
            raise ContainerError(f"Container unmount failed: {e}")
    
    def seal_container(self, container_id: str) -> None:
        """
        Запечатать контейнер (только для чтения).
        
        Args:
            container_id: ID контейнера.
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        metadata = self.containers[container_id]
        metadata.status = ContainerStatus.SEALED
        metadata.sealed_at = datetime.utcnow().isoformat()
        self._save_metadata()
        
        logger.info(f"Container sealed: {container_id}")
    
    def delete_container(self, container_id: str, secure: bool = True) -> None:
        """
        Удалить контейнер.
        
        Args:
            container_id: ID контейнера.
            secure: Безопасное удаление (криптографическое затирание).
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        metadata = self.containers[container_id]
        
        try:
            # Размонтирование если смонтирован
            if metadata.status == ContainerStatus.MOUNTED:
                self.unmount_container(container_id)
            
            # Удаление файлов
            container_path = self._get_container_path(container_id)
            if container_path.exists():
                if secure:
                    self._secure_delete_directory(container_path)
                else:
                    shutil.rmtree(container_path)
            
            # Удаление метаданных
            del self.containers[container_id]
            if container_id in self.files:
                del self.files[container_id]
            self._save_metadata()
            
            logger.info(f"Container deleted: {container_id}")
            
        except Exception as e:
            logger.error(f"Failed to delete container {container_id}: {e}")
            raise ContainerError(f"Container deletion failed: {e}")
    
    # ------------------------------------------------------------------------
    # УПРАВЛЕНИЕ ФАЙЛАМИ
    # ------------------------------------------------------------------------
    
    def add_file(
        self,
        container_id: str,
        file_path: str,
        filename: Optional[str] = None,
        protection_level: Optional[encryption_service.ProtectionLevel] = None,
    ) -> FileEntry:
        """
        Добавить файл в контейнер.
        
        Args:
            container_id: ID контейнера.
            file_path: Путь к файлу.
            filename: Имя файла в контейнере (если None, используется исходное).
            protection_level: Уровень защиты.
        
        Returns:
            Запись о файле.
        
        Raises:
            ContainerNotFoundError: Если контейнер не найден.
            ContainerNotMountedError: Если контейнер не смонтирован.
            ContainerSealedError: Если контейнер запечатан.
            FileNotFoundError: Если исходный файл не найден.
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        metadata = self.containers[container_id]
        
        # Проверка статуса
        if metadata.status != ContainerStatus.MOUNTED:
            raise ContainerNotMountedError(f"Container {container_id} is not mounted")
        
        if metadata.status == ContainerStatus.SEALED:
            raise ContainerSealedError(f"Container {container_id} is sealed")
        
        # Проверка исходного файла
        source_path = Path(file_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {file_path}")
        
        # Имя файла
        if filename is None:
            filename = source_path.name
        
        # Проверка дубликата
        if filename in self.files.get(container_id, {}):
            raise FileAlreadyExistsInContainerError(
                f"File {filename} already exists in container {container_id}"
            )
        
        # Проверка места
        file_size = source_path.stat().st_size
        if metadata.current_size + file_size > metadata.size_limit:
            raise ContainerFullError(
                f"Container {container_id} is full "
                f"({metadata.current_size}/{metadata.size_limit} bytes)"
            )
        
        try:
            # Чтение файла
            with open(source_path, "rb") as f:
                file_data = f.read()
            
            # Дедупликация (если включена)
            prot_level = protection_level or metadata.protection_level
            
            if metadata.deduplication_enabled:
                encrypted_data, chunks, dedup_ratio = self._deduplicate_and_encrypt(
                    file_data, container_id, prot_level
                )
            else:
                # Обычное шифрование
                encrypted_data = self.encryption_svc.encrypt_data(
                    file_data,
                    algorithm=encryption_service.EncryptionAlgorithm.AES_256_GCM,
                )
                chunks = []
                dedup_ratio = 0.0
            
            # Сохранение в контейнере
            container_path = self._get_container_path(container_id)
            encrypted_file_path = container_path / f"files/{filename}.enc"
            encrypted_file_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(encrypted_file_path, "wb") as f:
                f.write(encrypted_data)
            
            # Создание записи
            file_id = hashlib.sha256(f"{container_id}/{filename}".encode()).hexdigest()[:16]
            file_entry = FileEntry(
                file_id=file_id,
                filename=filename,
                original_path=str(source_path),
                size=file_size,
                encrypted_size=len(encrypted_data),
                chunk_count=len(chunks),
                deduplication_ratio=dedup_ratio,
                created_at=datetime.utcnow().isoformat(),
                modified_at=datetime.utcnow().isoformat(),
                protection_level=prot_level,
                encryption_key_id=metadata.encryption_key_id,
                integrity_hash=hashlib.sha256(encrypted_data).hexdigest(),
                chunks=chunks,
            )
            
            # Обновление метаданных
            self.files[container_id][filename] = file_entry
            metadata.current_size += len(encrypted_data)
            metadata.file_count += 1
            metadata.last_accessed = datetime.utcnow().isoformat()
            
            # Пересчет коэффициента дедупликации
            if metadata.deduplication_enabled and metadata.file_count > 0:
                total_original = sum(f.size for f in self.files[container_id].values())
                total_encrypted = sum(f.encrypted_size for f in self.files[container_id].values())
                if total_original > 0:
                    metadata.deduplication_ratio = 1.0 - (total_encrypted / total_original)
            
            self._save_metadata()
            
            logger.info(
                f"File added to container {container_id}: {filename} "
                f"({file_size} bytes, dedup={dedup_ratio:.2%})"
            )
            
            return file_entry
            
        except Exception as e:
            logger.error(f"Failed to add file {file_path} to container {container_id}: {e}")
            raise ContainerError(f"File addition failed: {e}")
    
    def extract_file(
        self,
        container_id: str,
        filename: str,
        output_path: str,
    ) -> str:
        """
        Извлечь файл из контейнера.
        
        Args:
            container_id: ID контейнера.
            filename: Имя файла в контейнере.
            output_path: Путь для сохранения.
        
        Returns:
            Путь к извлеченному файлу.
        
        Raises:
            ContainerNotFoundError: Если контейнер не найден.
            FileNotFoundInContainerError: Если файл не найден в контейнере.
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        if filename not in self.files.get(container_id, {}):
            raise FileNotFoundInContainerError(
                f"File {filename} not found in container {container_id}"
            )
        
        file_entry = self.files[container_id][filename]
        metadata = self.containers[container_id]
        
        try:
            # Чтение зашифрованного файла
            container_path = self._get_container_path(container_id)
            encrypted_file_path = container_path / f"files/{filename}.enc"
            
            with open(encrypted_file_path, "rb") as f:
                encrypted_data = f.read()
            
            # Дешифрование
            decrypted_data = self.encryption_svc.decrypt_data(
                encrypted_data,
                algorithm=encryption_service.EncryptionAlgorithm.AES_256_GCM,
            )
            
            # Распаковка если нужно
            # (в будущем можно добавить проверку сжатия)
            
            # Сохранение
            output = Path(output_path)
            if output.is_dir():
                output = output / filename
            
            with open(output, "wb") as f:
                f.write(decrypted_data)
            
            # Обновление времени доступа
            metadata.last_accessed = datetime.utcnow().isoformat()
            self._save_metadata()
            
            logger.info(f"File extracted from container {container_id}: {filename} -> {output}")
            return str(output)
            
        except Exception as e:
            logger.error(f"Failed to extract file {filename} from container {container_id}: {e}")
            raise ContainerError(f"File extraction failed: {e}")
    
    def list_files(self, container_id: str) -> List[FileEntry]:
        """
        Получить список файлов в контейнере.
        
        Args:
            container_id: ID контейнера.
        
        Returns:
            Список записей о файлах.
        
        Raises:
            ContainerNotFoundError: Если контейнер не найден.
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        return list(self.files.get(container_id, {}).values())
    
    def delete_file(self, container_id: str, filename: str, secure: bool = True) -> None:
        """
        Удалить файл из контейнера.
        
        Args:
            container_id: ID контейнера.
            filename: Имя файла.
            secure: Безопасное удаление.
        
        Raises:
            ContainerNotFoundError: Если контейнер не найден.
            FileNotFoundInContainerError: Если файл не найден.
            ContainerSealedError: Если контейнер запечатан.
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        metadata = self.containers[container_id]
        
        if metadata.status == ContainerStatus.SEALED:
            raise ContainerSealedError(f"Container {container_id} is sealed")
        
        if filename not in self.files.get(container_id, {}):
            raise FileNotFoundInContainerError(
                f"File {filename} not found in container {container_id}"
            )
        
        try:
            file_entry = self.files[container_id][filename]
            
            # Удаление файла
            container_path = self._get_container_path(container_id)
            encrypted_file_path = container_path / f"files/{filename}.enc"
            
            if encrypted_file_path.exists():
                if secure:
                    self._secure_delete_file(encrypted_file_path)
                else:
                    encrypted_file_path.unlink()
            
            # Обновление метаданных
            metadata.current_size -= file_entry.encrypted_size
            metadata.file_count -= 1
            del self.files[container_id][filename]
            
            self._save_metadata()
            
            logger.info(f"File deleted from container {container_id}: {filename}")
            
        except Exception as e:
            logger.error(f"Failed to delete file {filename} from container {container_id}: {e}")
            raise ContainerError(f"File deletion failed: {e}")
    
    # ------------------------------------------------------------------------
    # ИНФОРМАЦИЯ О КОНТЕЙНЕРЕ
    # ------------------------------------------------------------------------
    
    def get_container_info(self, container_id: str) -> ContainerMetadata:
        """
        Получить информацию о контейнере.
        
        Args:
            container_id: ID контейнера.
        
        Returns:
            Метаданные контейнера.
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        return self.containers[container_id]
    
    def list_containers(
        self,
        status: Optional[ContainerStatus] = None,
    ) -> List[ContainerMetadata]:
        """
        Получить список контейнеров.
        
        Args:
            status: Фильтр по статусу.
        
        Returns:
            Список метаданных контейнеров.
        """
        result = list(self.containers.values())
        
        if status:
            result = [c for c in result if c.status == status]
        
        return sorted(result, key=lambda c: c.created_at, reverse=True)
    
    def get_container_stats(self, container_id: str) -> Dict[str, Any]:
        """
        Получить статистику контейнера.
        
        Args:
            container_id: ID контейнера.
        
        Returns:
            Словарь со статистикой.
        """
        if container_id not in self.containers:
            raise ContainerNotFoundError(f"Container {container_id} not found")
        
        metadata = self.containers[container_id]
        files = self.files.get(container_id, {})
        
        total_original_size = sum(f.size for f in files.values())
        total_encrypted_size = sum(f.encrypted_size for f in files.values())
        
        return {
            "container_id": container_id,
            "name": metadata.name,
            "status": metadata.status.value,
            "file_count": len(files),
            "total_original_size": total_original_size,
            "total_encrypted_size": total_encrypted_size,
            "size_limit": metadata.size_limit,
            "used_space": metadata.current_size,
            "free_space": metadata.size_limit - metadata.current_size,
            "deduplication_enabled": metadata.deduplication_enabled,
            "deduplication_ratio": metadata.deduplication_ratio,
            "space_saved": total_original_size - total_encrypted_size if metadata.deduplication_enabled else 0,
        }
    
    # ------------------------------------------------------------------------
    # ПРИВАТНЫЕ МЕТОДЫ - СТРУКТУРА КОНТЕЙНЕРА
    # ------------------------------------------------------------------------
    
    def _generate_container_id(self, name: str) -> str:
        """Генерация ID контейнера."""
        timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        name_hash = hashlib.sha256(name.encode()).hexdigest()[:8]
        return f"cont-{timestamp}-{name_hash}"
    
    def _get_container_path(self, container_id: str) -> Path:
        """Получить путь к контейнеру."""
        return self.storage_dir / container_id
    
    def _create_container_structure(self, container_id: str, container_type: ContainerType) -> None:
        """Создать физическую структуру контейнера."""
        container_path = self._get_container_path(container_id)
        container_path.mkdir(parents=True, exist_ok=True)
        
        if container_type == ContainerType.FILESYSTEM:
            # Создание поддиректорий
            (container_path / "files").mkdir(exist_ok=True)
            (container_path / "chunks").mkdir(exist_ok=True)
            (container_path / "metadata").mkdir(exist_ok=True)
        elif container_type == ContainerType.ARCHIVE:
            # Для архивов создаем один файл
            archive_path = container_path / "container.archive"
            archive_path.touch()
    
    def _mount_filesystem(self, container_id: str) -> None:
        """Монтирование filesystem контейнера."""
        # В будущем можно реализовать FUSE монтирование
        logger.debug(f"Filesystem container {container_id} mounted")
    
    def _unmount_filesystem(self, container_id: str) -> None:
        """Размонтирование filesystem контейнера."""
        logger.debug(f"Filesystem container {container_id} unmounted")
    
    def _mount_archive(self, container_id: str) -> None:
        """Монтирование archive контейнера."""
        # В будущем можно реализовать монтирование архива
        logger.debug(f"Archive container {container_id} mounted")
    
    def _unmount_archive(self, container_id: str) -> None:
        """Размонтирование archive контейнера."""
        logger.debug(f"Archive container {container_id} unmounted")
    
    # ------------------------------------------------------------------------
    # ДЕДУПЛИКАЦИЯ
    # ------------------------------------------------------------------------
    
    def _deduplicate_and_encrypt(
        self,
        data: bytes,
        container_id: str,
        protection_level: encryption_service.ProtectionLevel,
    ) -> Tuple[bytes, List[Dict[str, Any]], float]:
        """
        Дедупликация и шифрование данных.
        
        Args:
            data: Исходные данные.
            container_id: ID контейнера.
            protection_level: Уровень защиты.
        
        Returns:
            Кортеж (encrypted_data, chunks, dedup_ratio).
        """
        # Разбиение на чанки (CDC)
        chunker = deduplication_chunking.Chunker(
            chunk_size=DEFAULT_CHUNK_SIZE,
            algorithm=deduplication_chunking.ChunkingAlgorithm.CDC,
        )
        
        chunks = chunker.chunk(data)
        
        # Проверка дубликатов и шифрование
        encrypted_chunks = []
        dedup_count = 0
        
        for chunk in chunks:
            chunk_hash = hashlib.sha256(chunk).hexdigest()
            
            # Проверка существования чанка
            chunk_path = self._get_container_path(container_id) / "chunks" / chunk_hash
            
            if chunk_path.exists():
                # Чанк уже существует - дедупликация
                dedup_count += 1
            else:
                # Шифрование и сохранение чанка
                encrypted_chunk = self.encryption_svc.encrypt_data(
                    chunk,
                    algorithm=encryption_service.EncryptionAlgorithm.AES_256_GCM,
                )
                
                with open(chunk_path, "wb") as f:
                    f.write(encrypted_chunk)
                
                encrypted_chunks.append(encrypted_chunk)
        
        # Объединение зашифрованных чанков
        encrypted_data = b"".join(encrypted_chunks)
        
        # Коэффициент дедупликации
        total_chunks = len(chunks)
        dedup_ratio = dedup_count / total_chunks if total_chunks > 0 else 0.0
        
        # Информация о чанках
        chunk_info = [
            {"hash": hashlib.sha256(c).hexdigest()[:16], "size": len(c)}
            for c in chunks
        ]
        
        return encrypted_data, chunk_info, dedup_ratio
    
    # ------------------------------------------------------------------------
    # БЕЗОПАСНОЕ УДАЛЕНИЕ
    # ------------------------------------------------------------------------
    
    @staticmethod
    def _secure_delete_file(filepath: Path, passes: int = 3) -> None:
        """Безопасное удаление файла."""
        if not filepath.exists():
            return
        
        size = filepath.stat().st_size
        
        with open(filepath, "r+b") as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        
        filepath.unlink()
    
    @staticmethod
    def _secure_delete_directory(directory: Path) -> None:
        """Безопасное удаление директории."""
        if not directory.exists():
            return
        
        # Удаление всех файлов
        for filepath in directory.rglob("*"):
            if filepath.is_file():
                ContainerManager._secure_delete_file(filepath)
        
        # Удаление директорий
        shutil.rmtree(directory)
    
    # ------------------------------------------------------------------------
    # МЕТАДАННЫЕ
    # ------------------------------------------------------------------------
    
    def _load_metadata(self) -> None:
        """Загрузить метаданные из файла."""
        if not self.metadata_file.exists():
            self.containers = {}
            self.files = {}
            return
        
        try:
            with open(self.metadata_file, "r") as f:
                data = json.load(f)
                
                # Загрузка контейнеров
                self.containers = {
                    cid: ContainerMetadata.from_dict(meta)
                    for cid, meta in data.get("containers", {}).items()
                }
                
                # Загрузка файлов
                self.files = {}
                for cid, files_data in data.get("files", {}).items():
                    self.files[cid] = {
                        filename: FileEntry.from_dict(fdata)
                        for filename, fdata in files_data.items()
                    }
            
            logger.debug(f"Loaded {len(self.containers)} containers")
            
        except Exception as e:
            logger.error(f"Failed to load metadata: {e}")
            self.containers = {}
            self.files = {}
    
    def _save_metadata(self) -> None:
        """Сохранить метаданные в файл."""
        try:
            data = {
                "containers": {
                    cid: meta.to_dict()
                    for cid, meta in self.containers.items()
                },
                "files": {
                    cid: {
                        filename: fentry.to_dict()
                        for filename, fentry in files.items()
                    }
                    for cid, files in self.files.items()
                },
            }
            
            with open(self.metadata_file, "w") as f:
                json.dump(data, f, indent=2)
            
            logger.debug("Container metadata saved")
            
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")


# ============================================================================
# ФУНКЦИИ ВЫСОКОГО УРОВНЯ
# ============================================================================

def create_container_manager(
    storage_dir: Optional[str] = None,
    key_mgr: Optional[key_manager.KeyManager] = None,
) -> ContainerManager:
    """
    Фабричная функция для создания ContainerManager.
    
    Args:
        storage_dir: Директория хранения.
        key_mgr: Менеджер ключей.
    
    Returns:
        Инициализированный менеджер.
    """
    return ContainerManager(storage_dir=storage_dir, key_mgr=key_mgr)


def quick_create_container(
    name: str,
    size_limit: int = DEFAULT_CONTAINER_SIZE,
) -> ContainerMetadata:
    """
    Быстрое создание контейнера.
    
    Args:
        name: Имя контейнера.
        size_limit: Лимит размера.
    
    Returns:
        Метаданные контейнера.
    """
    cm = create_container_manager()
    return cm.create_container(name, size_limit=size_limit)


# ============================================================================
# УТИЛИТЫ
# ============================================================================

def estimate_container_size(
    file_sizes: List[int],
    enable_deduplication: bool = True,
    dedup_ratio: float = 0.3,
) -> int:
    """
    Оценить размер контейнера для списка файлов.
    
    Args:
        file_sizes: Список размеров файлов.
        enable_deduplication: Включена ли дедупликация.
        dedup_ratio: Ожидаемый коэффициент дедупликации.
    
    Returns:
        Примерный размер контейнера.
    """
    total = sum(file_sizes)
    
    # Overhead
    overhead = 4096  # Заголовки и метаданные
    
    if enable_deduplication:
        # С учетом дедупликации
        encrypted_size = int(total * (1.0 - dedup_ratio) * 1.1)  # +10% overhead шифрования
    else:
        encrypted_size = int(total * 1.1)
    
    return overhead + encrypted_size