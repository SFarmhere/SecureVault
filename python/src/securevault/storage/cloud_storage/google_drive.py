"""SecureVault - Адаптер Google Drive для облачного хранилища.

Предоставляет клиент для загрузки/скачка/удаления файлов в Google Drive
через Google Drive API. Использует service account или OAuth2.

Зависимости: google-api-python-client, google-auth
"""

import io
import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class GoogleDriveClient:
    """Клиент Google Drive для SecureVault CloudStorageBackend.

    Поддерживает загрузку/скачка/удаление файлов и список объектов.
    Все операции используют Google Drive API v3.
    """

    def __init__(self, credentials: Dict[str, Any], bucket: str):
        """Инициализировать клиент Google Drive.

        Args:
            credentials: Словарь с ключами:
                - service_account_file: путь к JSON-файлу service account
                - или credentials_json: JSON-строка с учётными данными
            bucket: ID папки в Google Drive (корзина).
        """
        self.credentials = credentials
        self.bucket = bucket
        self._service = None
        self._folder_id = None

    def _get_service(self):
        """Получить или создать сервис Google Drive API."""
        if self._service is not None:
            return self._service

        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build
        except ImportError as e:
            raise ImportError(
                "google-api-python-client and google-auth are required "
                "for Google Drive provider. Install: pip install "
                "google-api-python-client google-auth"
            ) from e

        creds_data = self.credentials
        if "service_account_file" in creds_data:
            creds = service_account.Credentials.from_service_account_file(
                creds_data["service_account_file"],
                scopes=["https://www.googleapis.com/auth/drive.file"],
            )
        elif "credentials_json" in creds_data:
            import json

            creds = service_account.Credentials.from_service_account_info(
                json.loads(creds_data["credentials_json"]),
                scopes=["https://www.googleapis.com/auth/drive.file"],
            )
        else:
            raise ValueError(
                "Google Drive credentials must include "
                "'service_account_file' or 'credentials_json'"
            )

        self._service = build("drive", "v3", credentials=creds)
        return self._service

    def _get_folder_id(self) -> str:
        """Получить ID папки-корзины (bucket)."""
        if self._folder_id is not None:
            return self._folder_id

        service = self._get_service()
        # Ищем папку по имени
        results = (
            service.files()
            .list(
                q=f"mimeType='application/vnd.google-apps.folder' and "
                f"name='{self.bucket}' and trashed=false",
                fields="files(id, name)",
            )
            .execute()
        )

        files = results.get("files", [])
        if files:
            self._folder_id = files[0]["id"]
        else:
            # Создаём папку
            folder = (
                service.files()
                .create(
                    body={
                        "name": self.bucket,
                        "mimeType": "application/vnd.google-apps.folder",
                    },
                    fields="id",
                )
                .execute()
            )
            self._folder_id = folder["id"]

        return self._folder_id

    def _resolve_path(self, path: str) -> str:
        """Разрешить путь в Google Drive (относительно папки-корзины).

        Args:
            path: Путь вида "securevault/XX/YYYY.meta".

        Returns:
            Имя файла (без папки).
        """
        # Google Drive не имеет иерархии папок в привычном смысле,
        # используем плоский namespace с префиксом
        return path.replace("/", "_")

    def upload(self, path: str, data: bytes) -> None:
        """Загрузить данные в Google Drive.

        Args:
            path: Путь к объекту.
            data: Данные для загрузки.
        """
        service = self._get_service()
        folder_id = self._get_folder_id()
        name = self._resolve_path(path)

        media = io.BytesIO(data)
        service.files().create(
            body={
                "name": name,
                "parents": [folder_id],
            },
            media_body=media,
            fields="id",
        ).execute()
        logger.debug(f"Uploaded to Google Drive: {name}")

    def download(self, path: str) -> bytes:
        """Скачать данные из Google Drive.

        Args:
            path: Путь к объекту.

        Returns:
            Данные.

        Raises:
            FileNotFoundError: Если объект не найден.
        """
        service = self._get_service()
        folder_id = self._get_folder_id()
        name = self._resolve_path(path)

        results = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents and name='{name}' and trashed=false",
                fields="files(id, name)",
            )
            .execute()
        )

        files = results.get("files", [])
        if not files:
            raise FileNotFoundError(f"File not found in Google Drive: {path}")

        file_id = files[0]["id"]
        request = service.files().get_media(fileId=file_id)
        data = request.execute()
        return data

    def delete(self, path: str) -> bool:
        """Удалить объект из Google Drive.

        Args:
            path: Путь к объекту.

        Returns:
            True, если удалено.
        """
        service = self._get_service()
        folder_id = self._get_folder_id()
        name = self._resolve_path(path)

        results = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents and name='{name}' and trashed=false",
                fields="files(id, name)",
            )
            .execute()
        )

        files = results.get("files", [])
        if not files:
            return False

        service.files().delete(fileId=files[0]["id"]).execute()
        return True

    def exists(self, path: str) -> bool:
        """Проверить существование объекта.

        Args:
            path: Путь к объекту.

        Returns:
            True, если объект существует.
        """
        service = self._get_service()
        folder_id = self._get_folder_id()
        name = self._resolve_path(path)

        results = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents and name='{name}' and trashed=false",
                fields="files(id)",
            )
            .execute()
        )

        return len(results.get("files", [])) > 0

    def list_objects(self, prefix: str = "") -> List[str]:
        """Получить список объектов с префиксом.

        Args:
            prefix: Префикс пути.

        Returns:
            Список путей к объектам.
        """
        service = self._get_service()
        folder_id = self._get_folder_id()

        results = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents and trashed=false",
                fields="files(id, name)",
                pageSize=1000,
            )
            .execute()
        )

        paths = []
        for f in results.get("files", []):
            name = f["name"]
            # Восстанавливаем путь из плоского имени
            path = name.replace("_", "/")
            if prefix and not path.startswith(prefix):
                continue
            paths.append(path)
        return paths

    def get_object_info(self, path: str) -> Dict[str, Any]:
        """Получить информацию об объекте.

        Args:
            path: Путь к объекту.

        Returns:
            Словарь с информацией (size, etc.).
        """
        service = self._get_service()
        folder_id = self._get_folder_id()
        name = self._resolve_path(path)

        results = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents and name='{name}' and trashed=false",
                fields="files(id, name, size)",
            )
            .execute()
        )

        files = results.get("files", [])
        if not files:
            raise FileNotFoundError(f"File not found: {path}")

        return {"size": int(files[0].get("size", 0))}

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
        service = self._get_service()
        folder_id = self._get_folder_id()
        name = self._resolve_path(path)

        with open(file_path, "rb") as f:
            if encrypt_fn:
                # Шифруем кусками и загружаем
                media = io.BytesIO()
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    media.write(encrypt_fn(chunk))
                media.seek(0)
            else:
                media = f

            service.files().create(
                body={"name": name, "parents": [folder_id]},
                media_body=media,
                fields="id",
            ).execute()

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
        service = self._get_service()
        folder_id = self._get_folder_id()
        name = self._resolve_path(path)

        results = (
            service.files()
            .list(
                q=f"'{folder_id}' in parents and name='{name}' and trashed=false",
                fields="files(id)",
            )
            .execute()
        )

        files = results.get("files", [])
        if not files:
            raise FileNotFoundError(f"File not found: {path}")

        request = service.files().get_media(fileId=files[0]["id"])
        with open(output_path, "wb") as out:
            while True:
                chunk = request.next_chunk()
                if chunk is None:
                    break
                data = chunk[0].execute() if hasattr(chunk[0], "execute") else chunk[0]
                if decrypt_fn:
                    out.write(decrypt_fn(data))
                else:
                    out.write(data)

    def close(self) -> None:
        """Закрыть соединение."""
        self._service = None
        self._folder_id = None


def create_client(credentials: Dict[str, Any], bucket: str) -> GoogleDriveClient:
    """Создать клиент Google Drive.

    Args:
        credentials: Учётные данные.
        bucket: ID папки.

    Returns:
        Экземпляр GoogleDriveClient.
    """
    return GoogleDriveClient(credentials, bucket)


__all__ = ["GoogleDriveClient", "create_client"]
