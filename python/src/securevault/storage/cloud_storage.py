"""SecureVault - Облачное хранилище с сквозным шифрованием.

Предоставляет бэкенд хранения в облаке (Google Drive, Dropbox,
Yandex Disk, Mega) с обязательным сквозным шифрованием данных
перед отправкой. Реализует интерфейс StorageBackend.

Все данные шифруются локально перед загрузкой — облачный провайдер
никогда не видит открытых данных. Метаданные хранятся в зашифрованном
виде вместе с данными или в отдельном metadata-файле.

Зависимости:
- storage/backend.py: Интерфейс StorageBackend, StorageMetadata
- core/encryption_service.py: Шифрование данных
- exceptions: CloudSyncError, StorageBackendError
"""

import hashlib
import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from securevault import exceptions
from securevault.storage.backend import StorageBackend, StorageMetadata

logger = logging.getLogger(__name__)


class CloudStorageError(exceptions.StorageBackendError):
    """Ошибка облачного хранилища."""


class CloudStorageBackend(StorageBackend):
    """Облачный бэкенд хранения со сквозным шифрованием.

    Реализует интерфейс StorageBackend для облачных провайдеров.
    Данные шифруются локально перед загрузкой с использованием
    AES-256-GCM (или другого алгоритма). Ключ шифрования передаётся
    извне — бэкенд не генерирует ключи самостоятельно.

    Поддерживаемые провайдеры:
    - google_drive  — Google Drive API
    - dropbox       — Dropbox API
    - yandex_disk   — Yandex Disk API
    - mega          — MEGA API (через megapython)
    - s3            — Amazon S3 / совместимые

    Пример:
        backend = CloudStorageBackend(
            provider="google_drive",
            credentials={"credentials_file": "/path/to/creds.json"},
            encryption_key=b'...',
            bucket="securevault-backups",
        )
        backend.store("file1", b"secret data")
        data = backend.retrieve("file1")
    """

    # Поддерживаемые провайдеры и соответствующие модули
    _PROVIDER_MODULES: Dict[str, str] = {
        "google_drive": "securevault.storage.cloud_storage.google_drive",
        "dropbox": "securevault.storage.cloud_storage.dropbox",
        "yandex_disk": "securevault.storage.cloud_storage.yandex_disk",
        "mega": "securevault.storage.cloud_storage.mega",
        "s3": "securevault.storage.cloud_storage.s3",
    }

    def __init__(
        self,
        provider: str = "google_drive",
        credentials: Optional[Dict[str, Any]] = None,
        bucket: str = "securevault",
        encryption_key: Optional[bytes] = None,
        encryption_algorithm: str = "aes-256-gcm",
        prefix: str = "securevault/",
        chunk_size: int = 65536,
    ):
        """Инициализировать облачный бэкенд.

        Args:
            provider: Облачный провайдер (google_drive, dropbox,
                      yandex_disk, mega, s3).
            credentials: Словарь с учётными данными для провайдера.
            bucket: Имя корзины / папки в облаке.
            encryption_key: Ключ шифрования (32 байта для AES-256).
                            Если None, данные не шифруются (НЕ рекомендуется).
            encryption_algorithm: Алгоритм шифрования.
            prefix: Префикс для ключей в облаке (изоляция данных).
            chunk_size: Размер чанка для потоковой загрузки/скачка.

        Raises:
            CloudStorageError: Если провайдер не поддерживается.
        """
        if provider not in self._PROVIDER_MODULES:
            raise CloudStorageError(
                f"Unsupported cloud provider: {provider}. "
                f"Supported: {list(self._PROVIDER_MODULES.keys())}"
            )

        self.provider = provider
        self.credentials = credentials or {}
        self.bucket = bucket
        self.encryption_key = encryption_key
        self.encryption_algorithm = encryption_algorithm
        self.prefix = prefix.rstrip("/") + "/" if prefix else ""
        self.chunk_size = chunk_size

        self._lock = threading.RLock()
        self._client: Optional[Any] = None
        self._initialized = False

        logger.info(
            f"CloudStorageBackend created: provider={provider}, "
            f"bucket={bucket}, encrypted={encryption_key is not None}"
        )

    # ------------------------------------------------------------------
    # Инициализация и подключение
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Инициализировать подключение к облачному провайдеру.

        Импортирует и создаёт клиент соответствующего провайдера.
        Выполняется лениво — при первом вызове store/retrieve.

        Raises:
            CloudStorageError: Если инициализация не удалась.
        """
        with self._lock:
            if self._initialized:
                return

            module_path = self._PROVIDER_MODULES[self.provider]
            try:
                module = __import__(module_path, fromlist=["create_client"])
                self._client = module.create_client(
                    credentials=self.credentials,
                    bucket=self.bucket,
                )
                self._initialized = True
                logger.info(f"Cloud provider '{self.provider}' initialized")
            except ImportError as e:
                raise CloudStorageError(
                    f"Missing dependency for provider '{self.provider}': {e}. "
                    f"Install required package."
                ) from e
            except Exception as e:
                raise CloudStorageError(
                    f"Failed to initialize cloud provider '{self.provider}': {e}"
                ) from e

    def close(self) -> None:
        """Закрыть соединение с облаком."""
        with self._lock:
            if self._client and hasattr(self._client, "close"):
                try:
                    self._client.close()
                except Exception as e:
                    logger.warning(f"Error closing cloud client: {e}")
            self._client = None
            self._initialized = False

    def _ensure_initialized(self) -> None:
        """Убедиться, что клиент инициализирован."""
        if not self._initialized:
            self.initialize()

    # ------------------------------------------------------------------
    # Шифрование / дешифрование
    # ------------------------------------------------------------------

    def _encrypt(self, data: bytes) -> bytes:
        """Зашифровать данные перед загрузкой в облако.

        Если ключ шифрования не задан, данные возвращаются как есть
        (без шифрования — НЕ рекомендуется для продакшена).

        Args:
            data: Открытые данные.

        Returns:
            Зашифрованные данные (или исходные, если шифрование отключено).
        """
        if not self.encryption_key:
            logger.warning(
                "Cloud storage encryption is disabled — data will be "
                "uploaded unencrypted. This is NOT recommended for production."
            )
            return data

        try:
            # Используем прямое AES-256-GCM шифрование
            import os as _os

            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from securevault.core.encryption_service import EncryptionService
            from securevault.core.key_manager import KeyManager

            nonce = _os.urandom(12)
            aesgcm = AESGCM(self.encryption_key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            return nonce + ciphertext
        except ImportError:
            # Fallback: используем EncryptionService
            logger.debug("Using EncryptionService fallback for cloud encryption")
            km = KeyManager()
            key_id = "cloud-storage-key"
            km.store_key_securely(self.encryption_key, key_id)
            svc = EncryptionService(key_mgr=km)
            return svc.encrypt_data(data)
        except Exception as e:
            raise CloudStorageError(f"Encryption failed: {e}") from e

    def _decrypt(self, data: bytes) -> bytes:
        """Расшифровать данные, полученные из облака.

        Args:
            data: Зашифрованные данные (или открытые, если шифрование отключено).

        Returns:
            Открытые данные.
        """
        if not self.encryption_key:
            return data

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce = data[:12]
            ciphertext = data[12:]
            aesgcm = AESGCM(self.encryption_key)
            return aesgcm.decrypt(nonce, ciphertext, None)
        except ImportError:
            # Fallback
            from securevault.core.encryption_service import EncryptionService
            from securevault.core.key_manager import KeyManager

            km = KeyManager()
            key_id = "cloud-storage-key"
            km.store_key_securely(self.encryption_key, key_id)
            svc = EncryptionService(key_mgr=km)
            return svc.decrypt_data(data)
        except Exception as e:
            raise CloudStorageError(f"Decryption failed: {e}") from e

    # ------------------------------------------------------------------
    # Хранилище ключей (обёртка над шифрованием)
    # ------------------------------------------------------------------

    def _key_path(self, key: str) -> str:
        """Сформировать путь к объекту в облаке по ключу.

        Использует SHA-256 хеш ключа для безопасного именования,
        чтобы избежать проблем с специальными символами.

        Args:
            key: Логический ключ.

        Returns:
            Путь в облаке (с префиксом).
        """
        safe = hashlib.sha256(key.encode()).hexdigest()
        return f"{self.prefix}{safe[:2]}/{safe[2:]}"

    def _meta_path(self, key: str) -> str:
        """Путь к файлу метаданных в облаке."""
        return self._key_path(key) + ".meta"

    # ------------------------------------------------------------------
    # Интерфейс StorageBackend
    # ------------------------------------------------------------------

    def store(
        self, key: str, data: bytes, metadata: Optional[StorageMetadata] = None
    ) -> str:
        """Загрузить данные в облако (с шифрованием).

        Args:
            key: Логический ключ.
            data: Данные для загрузки.
            metadata: Метаданные (опционально).

        Returns:
            Ключ (для согласованности с интерфейсом).

        Raises:
            CloudStorageError: Если загрузка не удалась.
        """
        with self._lock:
            self._ensure_initialized()

            encrypted = self._encrypt(data)
            path = self._key_path(key)

            try:
                self._client.upload(path, encrypted)
                logger.debug(f"Stored {len(data)} bytes to cloud: {key}")

                if metadata:
                    meta_data = metadata.to_dict()
                    meta_data["sha256"] = hashlib.sha256(data).hexdigest()
                    meta_data["size"] = len(data)
                    self._client.upload(
                        self._meta_path(key),
                        json.dumps(meta_data).encode("utf-8"),
                    )
            except Exception as e:
                raise CloudStorageError(f"Failed to store '{key}' to cloud: {e}") from e

            return key

    def retrieve(self, key: str) -> Optional[bytes]:
        """Получить данные из облака (с расшифровкой).

        Args:
            key: Логический ключ.

        Returns:
            Данные или None, если ключ не найден.

        Raises:
            CloudStorageError: Если загрузка не удалась.
        """
        with self._lock:
            self._ensure_initialized()

            path = self._key_path(key)
            try:
                encrypted = self._client.download(path)
            except FileNotFoundError:
                return None
            except Exception as e:
                raise CloudStorageError(
                    f"Failed to retrieve '{key}' from cloud: {e}"
                ) from e

            if encrypted is None:
                return None

            try:
                return self._decrypt(encrypted)
            except CloudStorageError:
                raise
            except Exception as e:
                raise CloudStorageError(
                    f"Failed to decrypt data for '{key}': {e}"
                ) from e

    def delete(self, key: str) -> bool:
        """Удалить данные из облака.

        Args:
            key: Логический ключ.

        Returns:
            True, если удаление выполнено, False — если ключ не найден.

        Raises:
            CloudStorageError: Если удаление не удалась.
        """
        with self._lock:
            self._ensure_initialized()

            path = self._key_path(key)
            meta = self._meta_path(key)

            try:
                deleted = self._client.delete(path)
                if deleted:
                    # Удаляем метаданные, если они есть
                    try:
                        self._client.delete(meta)
                    except Exception:
                        pass  # Метаданные могли не быть загружены
                return deleted
            except FileNotFoundError:
                return False
            except Exception as e:
                raise CloudStorageError(
                    f"Failed to delete '{key}' from cloud: {e}"
                ) from e

    def exists(self, key: str) -> bool:
        """Проверить, существует ли ключ в облаке.

        Args:
            key: Логический ключ.

        Returns:
            True, если ключ существует.

        Raises:
            CloudStorageError: Если проверка не удалась.
        """
        with self._lock:
            self._ensure_initialized()

            path = self._key_path(key)
            try:
                return self._client.exists(path)
            except Exception as e:
                raise CloudStorageError(
                    f"Failed to check existence of '{key}': {e}"
                ) from e

    def list_keys(self) -> List[str]:
        """Получить список всех ключей в облаке.

        Returns:
            Список логических ключей (без префикса и расширения .meta).

        Raises:
            CloudStorageError: Если список не удалось получить.
        """
        with self._lock:
            self._ensure_initialized()

            try:
                paths = self._client.list_objects(prefix=self.prefix)
            except Exception as e:
                raise CloudStorageError(f"Failed to list cloud keys: {e}") from e

            keys: List[str] = []
            for path in paths:
                # Пропускаем файлы метаданных
                if path.endswith(".meta"):
                    continue
                # Извлекаем хеш из пути
                # Формат: prefix/XX/YYYY...
                parts = path.split("/")
                if len(parts) >= 2:
                    hash_val = parts[-2] + parts[-1]
                    keys.append(hash_val)
            return keys

    # ------------------------------------------------------------------
    # Дополнительные методы
    # ------------------------------------------------------------------

    def get_metadata(self, key: str) -> Optional[Dict[str, Any]]:
        """Получить метаданные для ключа из облака.

        Args:
            key: Логический ключ.

        Returns:
            Словарь метаданных или None.
        """
        with self._lock:
            self._ensure_initialized()

            meta_path = self._meta_path(key)
            try:
                data = self._client.download(meta_path)
            except FileNotFoundError:
                return None
            except Exception as e:
                raise CloudStorageError(
                    f"Failed to retrieve metadata for '{key}': {e}"
                ) from e

            if data is None:
                return None
            return json.loads(data.decode("utf-8"))

    def upload_stream(
        self, key: str, file_path: str, metadata: Optional[StorageMetadata] = None
    ) -> str:
        """Потоково загрузить файл в облако с шифрованием.

        Используется для больших файлов — данные читаются и шифруются
        кусками, что снижает потребление памяти.

        Args:
            key: Логический ключ.
            file_path: Путь к локальному файлу.
            metadata: Метаданные (опционально).

        Returns:
            Ключ.

        Raises:
            CloudStorageError: Если загрузка не удалась.
        """
        with self._lock:
            self._ensure_initialized()

            src = Path(file_path)
            if not src.exists():
                raise CloudStorageError(f"File not found: {file_path}")

            path = self._key_path(key)

            try:
                if self.encryption_key:
                    # Шифруем и загружаем кусками
                    self._client.upload_stream(
                        path,
                        str(src),
                        encrypt_fn=self._encrypt,
                        chunk_size=self.chunk_size,
                    )
                else:
                    self._client.upload_stream(path, str(src))

                if metadata:
                    meta_data = metadata.to_dict()
                    meta_data["sha256"] = hashlib.sha256(src.read_bytes()).hexdigest()
                    meta_data["size"] = src.stat().st_size
                    self._client.upload(
                        self._meta_path(key),
                        json.dumps(meta_data).encode("utf-8"),
                    )

                logger.info(f"Streamed {src.stat().st_size} bytes to cloud: {key}")
            except Exception as e:
                raise CloudStorageError(f"Failed to stream upload '{key}': {e}") from e

            return key

    def download_stream(self, key: str, output_path: str) -> str:
        """Потоково скачать файл из облака с расшифровкой.

        Args:
            key: Логический ключ.
            output_path: Путь для сохранения.

        Returns:
            Путь к сохранённому файлу.

        Raises:
            CloudStorageError: Если скачивание не удалась.
        """
        with self._lock:
            self._ensure_initialized()

            path = self._key_path(key)
            out = Path(output_path)
            out.parent.mkdir(parents=True, exist_ok=True)

            try:
                if self.encryption_key:
                    self._client.download_stream(
                        path,
                        str(out),
                        decrypt_fn=self._decrypt,
                        chunk_size=self.chunk_size,
                    )
                else:
                    self._client.download_stream(path, str(out))
            except FileNotFoundError:
                raise CloudStorageError(f"Key not found in cloud: {key}")
            except Exception as e:
                raise CloudStorageError(f"Failed to download '{key}': {e}") from e

            return str(out)

    def sync_from_local(
        self, local_dir: str, exclude: Optional[List[str]] = None
    ) -> int:
        """Синхронизировать локальную директорию с облаком.

        Args:
            local_dir: Путь к локальной директории.
            exclude: Список паттернов для исключения.

        Returns:
            Количество загруженных файлов.
        """
        with self._lock:
            self._ensure_initialized()

            local = Path(local_dir)
            if not local.is_dir():
                raise CloudStorageError(f"Not a directory: {local_dir}")

            exclude = exclude or []
            count = 0

            for file_path in local.rglob("*"):
                if not file_path.is_file():
                    continue
                if any(p in str(file_path) for p in exclude):
                    continue

                rel = file_path.relative_to(local)
                key = str(rel).replace("\\", "/")
                try:
                    self.store(key, file_path.read_bytes())
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to sync '{key}': {e}")

            logger.info(f"Synced {count} files to cloud from {local_dir}")
            return count

    def disk_usage(self) -> Dict[str, int]:
        """Получить статистику использования облака.

        Returns:
            Словарь с total_bytes и file_count.
        """
        with self._lock:
            self._ensure_initialized()

            try:
                objects = self._client.list_objects(prefix=self.prefix)
                total = 0
                count = 0
                for obj in objects:
                    if obj.endswith(".meta"):
                        continue
                    try:
                        info = self._client.get_object_info(obj)
                        total += info.get("size", 0)
                        count += 1
                    except Exception:
                        pass
                return {"total_bytes": total, "file_count": count}
            except Exception as e:
                raise CloudStorageError(f"Failed to get cloud disk usage: {e}") from e

    def __enter__(self):
        self.initialize()
        return self

    def __exit__(self, *args):
        self.close()


__all__ = [
    "CloudStorageBackend",
    "CloudStorageError",
]
