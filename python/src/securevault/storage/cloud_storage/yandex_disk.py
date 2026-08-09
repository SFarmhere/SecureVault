"""SecureVault - Адаптер Yandex Disk для облачного хранилища.

Предоставляет клиент для загрузки/скачка/удаления файлов на Yandex Disk
через Yandex Disk API v2 (OAuth2).

Зависимости: requests
"""

import io
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class YandexDiskClient:
    """Клиент Yandex Disk для SecureVault CloudStorageBackend.

    Поддерживает загрузку/скачка/удаление файлов и список объектов.
    Все операции используют Yandex Disk API v2.
    """

    API_BASE = "https://cloud-api.yandex.net/v1/disk"

    def __init__(self, credentials: Dict[str, Any], bucket: str):
        """Инициализировать клиент Yandex Disk.

        Args:
            credentials: Словарь с ключом 'token' (OAuth2 токен).
            bucket: Папка в Yandex Disk (корзина).
        """
        self.credentials = credentials
        self.bucket = bucket
        self._token = credentials.get("token")
        if not self._token:
            raise ValueError("Yandex Disk credentials must include 'token'")

    def _headers(self) -> Dict[str, str]:
        """Получить заголовки авторизации."""
        return {"Authorization": f"OAuth {self._token}"}

    def _resolve_path(self, path: str) -> str:
        """Разрешить путь в Yandex Disk.

        Args:
            path: Путь вида "securevault/XX/YYYY.meta".

        Returns:
            Путь в Yandex Disk (с префиксом папки).
        """
        return f"/{self.bucket}/{path}"

    def _request(self, method: str, endpoint: str, **kwargs) -> Any:
        """Выполнить HTTP-запрос к Yandex Disk API.

        Args:
            method: HTTP-метод (GET, PUT, POST, DELETE).
            endpoint: Конечная точка API.
            **kwargs: Дополнительные параметры запроса.

        Returns:
            Ответ API (JSON или содержимое).
        """
        import requests

        url = f"{self.API_BASE}{endpoint}"
        kwargs.setdefault("headers", self._headers())
        response = requests.request(method, url, **kwargs)
        response.raise_for_status()
        return response

    def upload(self, path: str, data: bytes) -> None:
        """Загрузить данные на Yandex Disk.

        Args:
            path: Путь к объекту.
            data: Данные для загрузки.
        """
        disk_path = self._resolve_path(path)

        # Получаем URL для загрузки
        resp = self._request(
            "GET", "/v1/disk/resources/upload",
            params={"path": disk_path, "overwrite": "true"},
        )
        href = resp.json().get("href")
        if not href:
            raise IOError("Failed to get upload URL from Yandex Disk")

        # Загружаем данные
        import requests
        requests.put(href, data=data)
        logger.debug(f"Uploaded to Yandex Disk: {disk_path}")

    def download(self, path: str) -> bytes:
        """Скачать данные с Yandex Disk.

        Args:
            path: Путь к объекту.

        Returns:
            Данные.

        Raises:
            FileNotFoundError: Если объект не найден.
        """
        disk_path = self._resolve_path(path)

        # Получаем URL для скачивания
        resp = self._request(
            "GET", "/v1/disk/resources/download",
            params={"path": disk_path},
        )
        href = resp.json().get("href")
        if not href:
            raise FileNotFoundError(f"File not found in Yandex Disk: {path}")

        import requests
        download_resp = requests.get(href)
        download_resp.raise_for_status()
        return download_resp.content

    def delete(self, path: str) -> bool:
        """Удалить объект с Yandex Disk.

        Args:
            path: Путь к объекту.

        Returns:
            True, если удалено.
        """
        disk_path = self._resolve_path(path)

        try:
            self._request("DELETE", "/v1/disk/resources",
                          params={"path": disk_path, "permanently": "true"})
            return True
        except Exception as e:
            if "404" in str(e) or "not found" in str(e).lower():
                return False
            raise

    def exists(self, path: str) -> bool:
        """Проверить существование объекта.

        Args:
            path: Путь к объекту.

        Returns:
            True, если объект существует.
        """
        disk_path = self._resolve_path(path)

        try:
            self._request("GET", "/v1/disk/resources",
                          params={"path": disk_path})
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
        disk_prefix = f"/{self.bucket}/{prefix}" if prefix else f"/{self.bucket}/"

        paths = []
        try:
            resp = self._request(
                "GET", "/v1/disk/resources",
                params={"path": disk_prefix, "limit": 1000, "fields": "items"},
            )
            items = resp.json().get("_embedded", {}).get("items", [])
            for item in items:
                if item.get("type") == "file":
                    full_path = item.get("path", "")
                    # Восстанавливаем относительный путь
                    rel = full_path[len(disk_prefix):] if full_path.startswith(disk_prefix) else full_path
                    paths.append(rel)
        except Exception as e:
            logger.error(f"Failed to list Yandex Disk objects: {e}")
        return paths

    def get_object_info(self, path: str) -> Dict[str, Any]:
        """Получить информацию об объекте.

        Args:
            path: Путь к объекту.

        Returns:
            Словарь с информацией (size, etc.).
        """
        disk_path = self._resolve_path(path)

        resp = self._request("GET", "/v1/disk/resources",
                             params={"path": disk_path, "fields": "size"})
        data = resp.json()
        return {"size": data.get("size", 0)}

    def upload_stream(self, path: str, file_path: str,
                      encrypt_fn=None, chunk_size: int = 65536) -> None:
        """Потоково загрузить файл.

        Args:
            path: Путь к объекту в облаке.
            file_path: Путь к локальному файлу.
            encrypt_fn: Функция шифрования (опционально).
            chunk_size: Размер чанка.
        """
        disk_path = self._resolve_path(path)

        # Получаем URL для загрузки
        resp = self._request(
            "GET", "/v1/disk/resources/upload",
            params={"path": disk_path, "overwrite": "true"},
        )
        href = resp.json().get("href")
        if not href:
            raise IOError("Failed to get upload URL from Yandex Disk")

        import requests
        with open(file_path, "rb") as f:
            if encrypt_fn:
                # Шифруем кусками и загружаем
                data = b""
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    data += encrypt_fn(chunk)
                requests.put(href, data=data)
            else:
                requests.put(href, data=f)

    def download_stream(self, path: str, output_path: str,
                        decrypt_fn=None, chunk_size: int = 65536) -> None:
        """Потоково скачать файл.

        Args:
            path: Путь к объекту в облаке.
            output_path: Путь для сохранения.
            decrypt_fn: Функция расшифровки (опционально).
            chunk_size: Размер чанка.
        """
        disk_path = self._resolve_path(path)

        # Получаем URL для скачивания
        resp = self._request(
            "GET", "/v1/disk/resources/download",
            params={"path": disk_path},
        )
        href = resp.json().get("href")
        if not href:
            raise FileNotFoundError(f"File not found in Yandex Disk: {path}")

        import requests
        download_resp = requests.get(href, stream=True)
        download_resp.raise_for_status()

        with open(output_path, "wb") as out:
            if decrypt_fn:
                # Расшифровываем кусками
                buffer = b""
                for chunk in download_resp.iter_content(chunk_size=chunk_size):
                    if chunk:
                        buffer += decrypt_fn(chunk)
                out.write(buffer)
            else:
                for chunk in download_resp.iter_content(chunk_size=chunk_size):
                    if chunk:
                        out.write(chunk)

    def close(self) -> None:
        """Закрыть соединение."""
        pass


def create_client(credentials: Dict[str, Any], bucket: str) -> YandexDiskClient:
    """Создать клиент Yandex Disk.

    Args:
        credentials: Учётные данные (с ключом 'token').
        bucket: Папка в Yandex Disk.

    Returns:
        Экземпляр YandexDiskClient.
    """
    return YandexDiskClient(credentials, bucket)


__all__ = ["YandexDiskClient", "create_client"]
