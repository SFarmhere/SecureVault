"""SecureVault - Alembic-окружение миграций.

Поскольку модели SecureVault используют нативный SQL (без SQLAlchemy),
этот env обеспечивает простое создание схемы через репозитории/модели.
Интеграция с alembic.ini сохранена для будущего перехода на SQLAlchemy.
"""

from __future__ import annotations

import logging
from logging.config import fileConfig
from typing import Any

logger = logging.getLogger(__name__)

# Доступные метаданные для целевой базы (анализируется по схеме).
from securevault.db.models import AuditRecord, UserRecord  # noqa: E402

target_metadata: Any = None  # не используется (SQL без ORM)


def create_initial_schema(connection: Any) -> None:
    """Создать начальную схему через прямой SQL."""
    tables = [UserRecord.create_table_sql(), AuditRecord.create_table_sql()]
    for create_sql in tables:
        connection.execute(create_sql)


def run_migrations_offline() -> None:
    """Запустить миграции в offline-режиме (dry-run/генерация SQL)."""
    from securevault.db.session import get_session

    session = get_session()
    session.initialize()
    conn = session.get_connection()
    create_initial_schema(conn)
    logger.info("Offline migration applied (schema created)")
    session.close()


def run_migrations_online() -> None:
    """Запустить миграции в online-режиме через репозитории."""
    from securevault.db.repositories.audit_repository import AuditRepository
    from securevault.db.repositories.file_repository import FileRepository
    from securevault.db.repositories.policy_repository import PolicyRepository
    from securevault.db.repositories.user_repository import UserRepository

    AuditRepository().create_table()
    UserRepository().create_table()
    FileRepository().create_table()
    PolicyRepository().create_table()
    logger.info("Online migration applied (all tables ready)")


def main() -> None:
    """Точка входа alembic env."""
    try:
        config = locals().get("config")
    except Exception:  # noqa: BLE001
        config = None
    if config is not None:
        if config.config_file_name is not None:
            fileConfig(config.config_file_name)
        offline = config.get_main_option("script_location") == "offline"
    else:
        offline = False

    if offline:
        run_migrations_offline()
    else:
        run_migrations_online()


if __name__ == "__main__":
    main()
