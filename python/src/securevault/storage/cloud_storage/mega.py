"""SecureVault - Адаптер MEGA для облачного хранилища.

Предоставляет клиент для загрузки/скачка/удаления файлов на MEGA
через megapython (официальная библиотека MEGA).

Зависимости: megapython
"""

import io
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MegaClient:
    """Клиент MEGA для SecureVault CloudStorageBackend.

    Поддерживает загрузку/скачка/удаление файлов и список объектов.
    Все операции используют официальную библиотеку megapython.
    """

    def __init__(self, credentials: Dict[str, Any], bucket: str):
        """Инициализировать клиент MEGA.

        Args:
            credentials: Словарь с ключами:
                - username: логин MEGA
                - password: пароль MEGA
                - или token: токен доступа
            bucket: Папка в MEGA (корзина).
        """
        self.credentials = credentials
        self.bucket = bucket
        self._client = None
        self._folder_handle = None

    def _get_client(self):
        """Получить или создать клиент MEGA."""
        if self._client is not None:
            return self._client

        try:
            from mega import Mega
        except ImportError as e:
            raise ImportError(
                "megapython package is required for MEGA provider. "
                "Install: pip install megapython"
            ) from e

        username = self.credentials.get("username")
        password = self.credentials.get("password")
        token = self.credentials.get("token")

        if token:
            self._client = Mega({"token": token})
        elif username and password:
            self._client = Mega({"username": username, "password": password})
        else:
            raise ValueError(
                "MEGA credentials must include 'username'/'password' or 'token'"
            )

        self._client = self._client.login() if hasattr(self._client, "login") else self._client
        return self._client

    def _get_folder_handle(self):
        """Получить handle папки-корзины."""
        if self._folder_handle is not None:
            return self._folder_handle

        client = self._get_client()
        # Ищем папку по имени
        folders = client.find(self.bucket)
        if folders:
            self._folder_handle = folders[0]
        else:
            # Создаём папку
            self._folder_handle = client.create_folder(self.bucket)

        return self._folder_handle

    def _resolve_path(self, path: str) -> str:
        """Разрешить путь в MEGA.

        Args:
            path: Путь вида "securevault/XX/YYYY.meta".

        Returns:
            Путь в MEGA (с префиксом папки).
        """
        return f"{self.bucket}/{path}"

    def upload(self, path: str, data: bytes) -> None:
        """Загрузить данные на MEGA.

        Args:
            path: Путь к объекту.
            data: Данные для загрузки.
        """
        client = self._get_client()
        folder = self._get_folder_handle()
        name = self._resolve_path(path)

        # MEGA не поддерживает вложенные папки напрямую,
        # используем плоский namespace с префиксом
        flat_name = name.replace("/", "_")

        # Загружаем во временный файл
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            client.upload(tmp_path, folder, flat_name)
            logger.debug(f"Uploaded to MEGA: {flat_name}")
        finally:
            import os
            os.unlink(tmp_path)

    def download(self, path: str) -> bytes:
        """Скачать данные с MEGA.

        Args:
            path: Путь к объекту.

        Returns:
            Данные.

        Raises:
            FileNotFoundError: Если объект не найден.
        """
        client = self._get_client()
        folder = self._get_folder_handle()
        name = self._resolve_path(path)
        flat_name = name.replace("/", "_")

        # Ищем файл
        files = client.find(flat_name, folder)
        if not files:
            raise FileNotFoundError(f"File not found in MEGA: {path}")

        # Скачиваем во временный файл
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp_path = tmp.name

        try:
            client.download(files[0], tmp_path)
            with open(tmp_path, "rb") as f:
                return f.read()
        finally:
            import os
            os.unlink(tmp_path)

    def delete(self, path: str) -> bool:
        """Удалить объект с MEGA.

        Args:
            path: Путь к объекту.

        Returns:
            True, если удалено.
        """
        client = self._get_client()
        folder = self._get_folder_handle()
        name = self._resolve_path(path)
        flat_name = name.replace("/", "_")

        files = client.find(flat_name, folder)
        if not files:
            return False

        client.delete(files[0])
        return True

    def exists(self, path: str) -> bool:
        """Проверить существование объекта.

        Args:
            path: Путь к объекту.

        Returns:
            True, если объект существует.
        """
        client = self._get_client()
        folder = self._get_folder_handle()
        name = self._resolve_path(path)
        flat_name = name.replace("/", "_")

        files = client.find(flat_name, folder)
        return len(files) > 0

    def list_objects(self, prefix: str = "") -> List[str]:
        """Получить список объектов с префиксом.

        Args:
            prefix: Префикс пути.

        Returns:
            Список путей к объектам.
        """
        client = self._get_client()
        folder = self._get_folder_handle()

        paths = []
        try:
            files = client.list(folder)
            for f in files:
                name = f.get("name", "")
                # Восстанавливаем путь из плоского имени
                path = name.replace("_", "/")
                if prefix and not path.startswith(prefix):
                    continue
                paths.append(path)
        except Exception as e:
            logger.error(f"Failed to list MEGA objects: {e}")
        return paths

    def get_object_info(self, path: str) -> Dict[str, Any]:
        """Получить информацию об объекте.

        Args:
            path: Путь к объекту.

        Returns:
            Словарь с информацией (size, etc.).
        """
        client = self._get_client()
        folder = self._get_folder_handle()
        name = self._resolve_path(path)
        flat_name = name.replace("/", "_")

        files = client.find(flat_name, folder)
        if not files:
            raise FileNotFoundError(f"File not found in MEGA: {path}")

        info = client.get_public_link(files[0])
        return {"size": info.get("size", 0) if info else 0}

    def upload_stream(self, path: str, file_path: str,
                      encrypt_fn=None, chunk_size: int = 65536) -> None:
        """Потоково загрузить файл.

        Args:
            path: Путь к объекту в облаке.
            file_path: Путь к локальному файлу.
            encrypt_fn: Функция шифрования (опционально).
            chunk_size: Размер чанка.
        """
        client = self._get_client()
        folder = self._get_folder_handle()
        name = self._resolve_path(path)
        flat_name = name.replace("/", "_")

        if encrypt_fn:
            # Шифруем кусками и загружаем
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
                tmp_path = tmp.name
                with open(file_path, "rb") as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        tmp.write(encrypt_fn(chunk))

            try:
                client.upload(tmp_path, folder, flat_name)
            finally:
                import os
                os.unlink(tmp_path)
        else:
            client.upload(file_path, folder, flat_name)

    def download_stream(self, path: str, output_path: str,
                        decrypt_fn=None, chunk_size: int = 65536) -> None:
        """Потоково скачать файл.

        Args:
            path: Путь к объекту в облаке.
            output_path: Путь для сохранения.
            decrypt_fn: Функция расшифровки (опционально).
            chunk_size: Размер чанка.
        """
        client = self._get_client()
        folder = self._get_folder_handle()
        name = self._resolve_path(path)
        flat_name = name.replace("/", "_")

        files = client.find(flat_name, folder)
        if not files:
            raise FileNotFoundError(f"File not found in MEGA: {path}")

        import tempfile
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            tmp_path = tmp.name

        try:
            client.download(files[0], tmp_path)
            with open(tmp_path, "rb") as src, open(output_path, "wb") as dst:
                if decrypt_fn:
                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        dst.write(decrypt_fn(chunk))
                else:
                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        dst.write(chunk)
        finally:
            import os
            os.unlink(tmp_path)

    def close(self) -> None:
        """Закрыть соединение."""
        self._client = None
        self._folder_handle = None


def create_client(credentials: Dict[str, Any], bucket: str) -> MegaClient:
    """Создать клиент MEGA.

    Args:
        credentials: Учётные данные (username/password или token).
        bucket: Папка в MEGA.

    Returns:
        Экземпляр MegaClient.
    """
    return MegaClient(credentials, bucket)


__all__ = ["MegaClient", "create_client"]
