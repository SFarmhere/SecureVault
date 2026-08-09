"""SecureVault - Адаптер Dropbox для облачного хранилища.

Предоставляет клиент для загрузки/скачка/удаления файлов в Dropbox
через Dropbox API v2.

Зависимости: dropbox
"""

import logging
from typing import Any, Dict, List
import dropbox

logger = logging.getLogger(__name__)


class DropboxClient:
    """Клиент Dropbox для SecureVault CloudStorageBackend.

    Поддерживает загрузку/скачка/удаление файлов и список объектов.
    Все операции используют Dropbox API v2.
    """

    def __init__(self, credentials: Dict[str, Any], bucket: str):
        """Инициализировать клиент Dropbox.

        Args:
            credentials: Словарь с ключом 'token' (OAuth2 access token).
            bucket: Префикс папки в Dropbox (корзина).
        """
        self.credentials = credentials
        self.bucket = bucket
        self._client = None

    def _get_client(self):
        """Получить или создать клиент Dropbox API."""
        if self._client is not None:
            return self._client

        try:
            import dropbox
        except ImportError as e:
            raise ImportError(
                "dropbox package is required for Dropbox provider. "
                "Install: pip install dropbox"
            ) from e

        token = self.credentials.get("token")
        if not token:
            raise ValueError("Dropbox credentials must include 'token'")

        self._client = dropbox.Dropbox(token)
        return self._client

    def _resolve_path(self, path: str) -> str:
        """Разрешить путь в Dropbox.

        Args:
            path: Путь вида "securevault/XX/YYYY.meta".

        Returns:
            Путь в Dropbox (с префиксом папки).
        """
        return f"/{self.bucket}/{path}"

    def upload(self, path: str, data: bytes) -> None:
        """Загрузить данные в Dropbox.

        Args:
            path: Путь к объекту.
            data: Данные для загрузки.
        """
        client = self._get_client()
        dropbox_path = self._resolve_path(path)

        client.files_upload(data, dropbox_path, mode=dropbox.files.WriteMode.overwrite)
        logger.debug(f"Uploaded to Dropbox: {dropbox_path}")

    def download(self, path: str) -> bytes:
        """Скачать данные из Dropbox.

        Args:
            path: Путь к объекту.

        Returns:
            Данные.

        Raises:
            FileNotFoundError: Если объект не найден.
        """
        client = self._get_client()
        dropbox_path = self._resolve_path(path)

        try:
            metadata, response = client.files_download(dropbox_path)
            return response.content
        except Exception as e:
            if "path/not_found" in str(e) or "no such file" in str(e).lower():
                raise FileNotFoundError(f"File not found in Dropbox: {path}")
            raise

    def delete(self, path: str) -> bool:
        """Удалить объект из Dropbox.

        Args:
            path: Путь к объекту.

        Returns:
            True, если удалено.
        """
        client = self._get_client()
        dropbox_path = self._resolve_path(path)

        try:
            client.files_delete_v2(dropbox_path)
            return True
        except Exception as e:
            if "path/not_found" in str(e) or "no such file" in str(e).lower():
                return False
            raise

    def exists(self, path: str) -> bool:
        """Проверить существование объекта.

        Args:
            path: Путь к объекту.

        Returns:
            True, если объект существует.
        """
        client = self._get_client()
        dropbox_path = self._resolve_path(path)

        try:
            client.files_get_metadata(dropbox_path)
            return True
        except Exception:
            return False

    def list_objects(self, prefix: str = "") -> List[str]:
        """Получить список объектов с префиксом.

        Args:
            prefix: Префикс пути.

        Returns:
            Список путей к объектам.
        """
        client = self._get_client()
        dropbox_prefix = f"/{self.bucket}/{prefix}" if prefix else f"/{self.bucket}/"

        paths = []
        try:
            result = client.files_list_folder(dropbox_prefix, recursive=True)
            for entry in result.entries:
                if isinstance(entry, dropbox.files.FileMetadata):
                    # Восстанавливаем относительный путь
                    full_path = entry.path_display
                    rel = (
                        full_path[len(dropbox_prefix) :]
                        if full_path.startswith(dropbox_prefix)
                        else full_path
                    )
                    paths.append(rel)
        except Exception as e:
            logger.error(f"Failed to list Dropbox objects: {e}")
        return paths

    def get_object_info(self, path: str) -> Dict[str, Any]:
        """Получить информацию об объекте.

        Args:
            path: Путь к объекту.

        Returns:
            Словарь с информацией (size, etc.).
        """
        client = self._get_client()
        dropbox_path = self._resolve_path(path)

        try:
            metadata = client.files_get_metadata(dropbox_path)
            if isinstance(metadata, dropbox.files.FileMetadata):
                return {"size": metadata.size}
            raise FileNotFoundError(f"Not a file: {path}")
        except Exception as e:
            if "path/not_found" in str(e) or "no such file" in str(e).lower():
                raise FileNotFoundError(f"File not found: {path}")
            raise

    def upload_stream(
        self, path: str, file_path: str, encrypt_fn=None, chunk_size: int = 65536
    ) -> None:
        """Потоково загрузить файл.

        Args:
            path: Путь к объекту в облаке.
            file_path: Путь к локальному файлу.
            encrypt_fn: Функция шифрования (опционально).
            chunk_size: Размер чанка.
        """
        client = self._get_client()
        dropbox_path = self._resolve_path(path)

        with open(file_path, "rb") as f:
            if encrypt_fn:
                # Шифруем кусками и загружаем
                data = b""
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    data += encrypt_fn(chunk)
                client.files_upload(
                    data, dropbox_path, mode=dropbox.files.WriteMode.overwrite
                )
            else:
                client.files_upload(
                    f.read(), dropbox_path, mode=dropbox.files.WriteMode.overwrite
                )

    def download_stream(
        self, path: str, output_path: str, decrypt_fn=None, chunk_size: int = 65536
    ) -> None:
        """Потоково скачать файл.

        Args:
            path: Путь к объекту в облаке.
            output_path: Путь для сохранения.
            decrypt_fn: Функция расшифровки (опционально).
            chunk_size: Размер чанка.
        """
        client = self._get_client()
        dropbox_path = self._resolve_path(path)

        try:
            metadata, response = client.files_download(dropbox_path)
            with open(output_path, "wb") as out:
                if decrypt_fn:
                    # Расшифровываем кусками
                    data = response.content
                    out.write(decrypt_fn(data))
                else:
                    out.write(response.content)
        except Exception as e:
            if "path/not_found" in str(e) or "no such file" in str(e).lower():
                raise FileNotFoundError(f"File not found: {path}")
            raise

    def close(self) -> None:
        """Закрыть соединение."""
        self._client = None


def create_client(credentials: Dict[str, Any], bucket: str) -> DropboxClient:
    """Создать клиент Dropbox.

    Args:
        credentials: Учётные данные (с ключом 'token').
        bucket: Префикс папки.

    Returns:
        Экземпляр DropboxClient.
    """
    return DropboxClient(credentials, bucket)


__all__ = ["DropboxClient", "create_client"]
