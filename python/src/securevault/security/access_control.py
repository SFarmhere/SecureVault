"""SecureVault - Контроль доступа (RBAC).

Проверка прав пользователя на выполнение операций на основе ролей
и матрицы разрешений.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

from securevault import exceptions

logger = logging.getLogger(__name__)

# Матрица прав: действие -> набор ролей, которым разрешено
DEFAULT_PERMISSIONS: Dict[str, Set[str]] = {
    "encrypt": {"admin", "operator", "user"},
    "decrypt": {"admin", "operator", "user"},
    "create_container": {"admin", "operator"},
    "mount_container": {"admin", "operator", "user"},
    "unmount_container": {"admin", "operator", "user"},
    "add_file": {"admin", "operator", "user"},
    "extract_file": {"admin", "operator", "user"},
    "delete_file": {"admin", "operator"},
    "delete_container": {"admin"},
    "rotate_key": {"admin"},
    "backup_key": {"admin"},
    "restore_key": {"admin"},
    "audit_view": {"admin", "auditor"},
    "manage_users": {"admin"},
}


class AccessControl:
    """Проверка прав доступа на основе ролей пользователя."""

    def __init__(self, permissions: Optional[Dict[str, Set[str]]] = None):
        self.permissions = permissions or DEFAULT_PERMISSIONS

    def has_permission(self, roles: List[str], action: str) -> bool:
        """Проверить, разрешено ли действие для набора ролей."""
        allowed = self.permissions.get(action)
        if allowed is None:
            logger.warning(f"Unknown action: {action}")
            return False
        # Администратор всегда имеет полный доступ
        if "admin" in roles:
            return True
        return bool(allowed.intersection(roles))

    def require_permission(self, roles: List[str], action: str) -> None:
        """Проверить право, иначе поднять AccessDeniedError."""
        if not self.has_permission(roles, action):
            raise exceptions.AccessDeniedError(
                f"Action '{action}' not allowed for roles {roles}"
            )

    def add_rule(self, action: str, roles: List[str]) -> None:
        self.permissions.setdefault(action, set()).update(roles)

    def remove_rule(self, action: str, roles: List[str]) -> None:
        if action in self.permissions:
            self.permissions[action].difference_update(roles)

    def is_admin(self, roles: List[str]) -> bool:
        return "admin" in roles


__all__ = ["AccessControl", "DEFAULT_PERMISSIONS"]
