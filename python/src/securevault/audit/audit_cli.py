"""SecureVault - CLI интерфейс для аудита.

Предоставляет команды для работы с журналом аудита:
- Просмотр записей
- Поиск и фильтрация
- Экспорт
- Верификация целостности
"""

import json
import logging
from typing import Optional, List, Dict, Any, Callable

from securevault.core.audit_manager import AuditManager, AuditEntry

logger = logging.getLogger(__name__)


class AuditCLIError(Exception):
    """Ошибка CLI аудита."""
    pass


class AuditCLI:
    """CLI интерфейс для управления аудитом."""

    def __init__(self, audit_manager: Optional[AuditManager] = None):
        self.audit_mgr = audit_manager or AuditManager()

    def list_entries(
        self,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """Вывести список записей аудита."""
        entries = self.audit_mgr.get_entries(
            user_id=user_id,
            action=action,
            result=result,
            limit=limit,
            offset=offset,
        )
        return [e.to_dict() for e in entries]

    def verify(self) -> Dict[str, Any]:
        """Проверить целостность журнала."""
        return self.audit_mgr.verify_integrity()

    def stats(self) -> Dict[str, Any]:
        """Получить статистику."""
        return self.audit_mgr.get_stats()

    def export(
        self,
        output_path: str,
        format: str = "json",
        user_id: Optional[str] = None,
        action: Optional[str] = None,
    ) -> int:
        """Экспортировать записи."""
        return self.audit_mgr.export(
            output_path=output_path,
            format=format,
            user_id=user_id,
            action=action,
        )

    def find(self, search: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Поиск записей по тексту."""
        entries = self.audit_mgr.get_entries(limit=limit)
        search_lower = search.lower()
        result = []
        for e in entries:
            if (
                search_lower in e.user_id.lower()
                or search_lower in e.action.lower()
                or search_lower in json.dumps(e.details).lower()
            ):
                result.append(e.to_dict())
        return result

    def user_activity(self, user_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Активность пользователя."""
        return self.audit_mgr.get_user_activity(user_id, limit)


def create_audit_cli(audit_manager: Optional[AuditManager] = None) -> AuditCLI:
    """Фабричная функция для создания CLI аудита."""
    return AuditCLI(audit_manager)


__all__ = ["AuditCLI", "AuditCLIError", "create_audit_cli"]