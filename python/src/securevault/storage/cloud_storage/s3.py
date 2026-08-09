"""SecureVault - Адаптер Amazon S3 для облачного хранилища.

Предоставляет клиент для загрузки/скачка/удаления файлов в Amazon S3
(или совместимые хранилища: MinIO, Yandex Object Storage, etc.)
через boto3.

Зависимости: boto3
"""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class S3Client:
    """Клиент Amazon S3 для SecureVault CloudStorageBackend.

    Поддерживает загрузку/скачка/удаление файлов и список объектов.
    Все операции используют boto3 (AWS SDK for Python).
    """

    def __init__(self, credentials: Dict[str, Any], bucket: str):
        """Инициализировать клиент S3.

        Args:
            credentials: Словарь с ключами:
                - access_key: AWS Access Key ID
                - secret_key: AWS Secret Access Key
                - region: регион (по умолчанию us-east-1)
                - endpoint_url: URL конечной точки (для S3-совместимых)
            bucket: Имя корзины S3.
        """
        self.credentials = credentials
        self.bucket = bucket
        self._client = None

    def _get_client(self):
        """Получить или создать клиент S3."""
        if self._client is not None:
            return self._client

        try:
            import boto3
        except ImportError as e:
            raise ImportError(
                "boto3 package is required for S3 provider. "
                "Install: pip install boto3"
            ) from e

        self._client = boto3.client(
            "s3",
            aws_access_key_id=self.credentials.get("access_key"),
            aws_secret_access_key=self.credentials.get("secret_key"),
            region_name=self.credentials.get("region", "us-east-1"),
            endpoint_url=self.credentials.get("endpoint_url"),
        )
        return self._client

    def _resolve_path(self, path: str) -> str:
        """Разрешить путь в S3.

        Args:
            path: Путь вида "securevault/XX/YYYY.meta".

        Returns:
            Ключ S3 (с префиксом).
        """
        return f"{self.bucket}/{path}"

    def upload(self, path: str, data: bytes) -> None:
        """Загрузить данные в S3.

        Args:
            path: Путь к объекту.
            data: Данные для загрузки.
        """
        client = self._get_client()
        key = self._resolve_path(path)

        client.put_object(Bucket=self.bucket, Key=key, Body=data)
        logger.debug(f"Uploaded to S3: {key}")

    def download(self, path: str) -> bytes:
        """Скачать данные из S3.

        Args:
            path: Путь к объекту.

        Returns:
            Данные.

        Raises:
            FileNotFoundError: Если объект не найден.
        """
        client = self._get_client()
        key = self._resolve_path(path)

        try:
            response = client.get_object(Bucket=self.bucket, Key=key)
            return response["Body"].read()
        except client.exceptions.NoSuchKey:
            raise FileNotFoundError(f"File not found in S3: {path}")

    def delete(self, path: str) -> bool:
        """Удалить объект из S3.

        Args:
            path: Путь к объекту.

        Returns:
            True, если удалено.
        """
        client = self._get_client()
        key = self._resolve_path(path)

        try:
            client.delete_object(Bucket=self.bucket, Key=key)
            return True
        except client.exceptions.NoSuchKey:
            return False

    def exists(self, path: str) -> bool:
        """Проверить существование объекта.

        Args:
            path: Путь к объекту.

        Returns:
            True, если объект существует.
        """
        client = self._get_client()
        key = self._resolve_path(path)

        try:
            client.head_object(Bucket=self.bucket, Key=key)
            return True
        except client.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return False
            raise

    def list_objects(self, prefix: str = "") -> List[str]:
        """Получить список объектов с префиксом.

        Args:
            prefix: Префикс пути.

        Returns:
            Список путей к объектам.
        """
        client = self._get_client()
        s3_prefix = f"{prefix}" if prefix else ""

        paths = []
        paginator = client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=s3_prefix):
            for obj in page.get("Contents", []):
                key = obj["Key"]
                # Убираем префикс bucket из ключа
                if key.startswith(f"{self.bucket}/"):
                    key = key[len(f"{self.bucket}/"):]
                paths.append(key)
        return paths

    def get_object_info(self, path: str) -> Dict[str, Any]:
        """Получить информацию об объекте.

        Args:
            path: Путь к объекту.

        Returns:
            Словарь с информацией (size, etc.).
        """
        client = self._get_client()
        key = self._resolve_path(path)

        try:
            response = client.head_object(Bucket=self.bucket, Key=key)
            return {"size": response.get("ContentLength", 0)}
        except client.exceptions.ClientError as e:
            if e.response["Error"]["Code"] == "404":
                raise FileNotFoundError(f"File not found in S3: {path}")
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
        key = self._resolve_path(path)

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
                client.upload_file(tmp_path, self.bucket, key)
            finally:
                import os

                os.unlink(tmp_path)
        else:
            client.upload_file(file_path, self.bucket, key)

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
        key = self._resolve_path(path)

        if decrypt_fn:
            # Скачиваем и расшифровываем кусками
            import tempfile

            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
                tmp_path = tmp.name

            try:
                client.download_file(self.bucket, key, tmp_path)
                with open(tmp_path, "rb") as src, open(output_path, "wb") as dst:
                    while True:
                        chunk = src.read(chunk_size)
                        if not chunk:
                            break
                        dst.write(decrypt_fn(chunk))
            finally:
                import os

                os.unlink(tmp_path)
        else:
            client.download_file(self.bucket, key, output_path)

    def close(self) -> None:
        """Закрыть соединение."""
        self._client = None


def create_client(credentials: Dict[str, Any], bucket: str) -> S3Client:
    """Создать клиент S3.

    Args:
        credentials: Учётные данные (access_key, secret_key, region).
        bucket: Имя корзины S3.

    Returns:
        Экземпляр S3Client.
    """
    return S3Client(credentials, bucket)


__all__ = ["S3Client", "create_client"]
