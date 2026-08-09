"""SecureVault - Провайдеры облачного хранилища.

Содержит адаптеры для различных облачных провайдеров:
- google_drive  — Google Drive API
- dropbox       — Dropbox API
- yandex_disk   — Yandex Disk API
- mega          — MEGA API
- s3            — Amazon S3 / совместимые

Каждый модуль предоставляет функцию create_client(), возвращающую
объект-клиент с единым интерфейсом для загрузки/скачка/удаления файлов.
"""

__all__ = [
    "google_drive",
    "dropbox",
    "yandex_disk",
    "mega",
    "s3",
]
