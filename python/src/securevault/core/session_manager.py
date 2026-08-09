"""SecureVault - Менеджер сессий пользователей.

Управление сессиями:
- Создание и завершение сессий
- Таймауты и блокировки
- Многопользовательский режим
- Трекинг активности
"""

import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from securevault import constants, exceptions

logger = logging.getLogger(__name__)


class SessionError(exceptions.SessionError):
    """Ошибка сессии."""


class SessionNotFoundError(SessionError, exceptions.SessionNotFoundError):
    """Сессия не найдена."""


class SessionExpiredError(SessionError, exceptions.SessionExpiredError):
    """Сессия истекла."""


class SessionLockedError(SessionError, exceptions.SessionLockedError):
    """Сессия заблокирована."""


class TooManySessionsError(SessionError):
    """Слишком много активных сессий."""


@dataclass
class Session:
    """Сессия пользователя."""

    session_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    last_active: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    roles: List[str] = field(default_factory=list)
    locked: bool = False
    failed_attempts: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def is_valid(self) -> bool:
        return not self.is_expired() and not self.locked

    def touch(self) -> None:
        self.last_active = datetime.utcnow()


class SessionManager:
    """Менеджер пользовательских сессий."""

    def __init__(
        self,
        timeout: int = constants.DEFAULT_SESSION_TIMEOUT,
        idle_timeout: int = constants.DEFAULT_IDLE_TIMEOUT,
        max_sessions_per_user: int = 10,
    ):
        self.timeout = timeout
        self.idle_timeout = idle_timeout
        self.max_sessions_per_user = max_sessions_per_user
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.RLock()

    def create_session(
        self,
        user_id: str,
        roles: Optional[List[str]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> Session:
        """Создать сессию."""
        with self._lock:
            user_sessions = [s for s in self._sessions.values() if s.user_id == user_id]
            if len(user_sessions) >= self.max_sessions_per_user:
                raise TooManySessionsError(
                    f"User {user_id} exceeded max sessions ({self.max_sessions_per_user})"
                )

            timeout = timeout or self.timeout
            now = datetime.utcnow()

            session = Session(
                session_id=self._generate_session_id(),
                user_id=user_id,
                created_at=now,
                expires_at=now + timedelta(seconds=timeout),
                last_active=now,
                ip_address=ip_address,
                user_agent=user_agent,
                roles=roles or [],
                metadata=metadata or {},
            )

            self._sessions[session.session_id] = session
            logger.info(f"Session created: {session.session_id} for {user_id}")
            return session

    def validate_session(self, session_id: str) -> Session:
        """Проверить валидность сессии."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise SessionNotFoundError(f"Session {session_id} not found")

            if session.is_expired():
                self.terminate_session(session_id)
                raise SessionExpiredError(f"Session {session_id} expired")

            if session.locked:
                raise SessionLockedError(f"Session {session_id} locked")

            idle_time = (datetime.utcnow() - session.last_active).total_seconds()
            if idle_time > self.idle_timeout:
                self.terminate_session(session_id)
                raise SessionExpiredError(f"Session {session_id} idle timeout exceeded")

            session.touch()
            return session

    def get_session(self, session_id: str) -> Session:
        """Получить сессию без валидации."""
        session = self._sessions.get(session_id)
        if not session:
            raise SessionNotFoundError(f"Session {session_id} not found")
        return session

    def terminate_session(self, session_id: str) -> None:
        """Завершить сессию."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                logger.info(f"Session terminated: {session_id}")

    def lock_session(self, session_id: str) -> None:
        """Заблокировать сессию."""
        with self._lock:
            session = self.get_session(session_id)
            session.locked = True
            logger.warning(f"Session locked: {session_id}")

    def unlock_session(self, session_id: str) -> None:
        """Разблокировать сессию."""
        with self._lock:
            session = self.get_session(session_id)
            session.locked = False
            logger.info(f"Session unlocked: {session_id}")

    def record_failed_attempt(self, session_id: str) -> int:
        """Зафиксировать неудачную попытку."""
        with self._lock:
            session = self.get_session(session_id)
            session.failed_attempts += 1
            if session.failed_attempts >= constants.MAX_FAILED_LOGIN_ATTEMPTS:
                self.lock_session(session_id)
                logger.warning(
                    f"Session {session_id} locked due to "
                    f"{session.failed_attempts} failed attempts"
                )
            return session.failed_attempts

    def get_active_sessions(self, user_id: Optional[str] = None) -> List[Session]:
        """Получить активные сессии."""
        with self._lock:
            sessions = list(self._sessions.values())
            if user_id:
                sessions = [s for s in sessions if s.user_id == user_id]
            return [s for s in sessions if s.is_valid()]

    def cleanup_expired(self) -> int:
        """Очистить истекшие сессии."""
        with self._lock:
            expired = [sid for sid, s in self._sessions.items() if s.is_expired()]
            for sid in expired:
                del self._sessions[sid]
            if expired:
                logger.info(f"Cleaned {len(expired)} expired sessions")
            return len(expired)

    def shutdown(self) -> None:
        """Завершить работу менеджера."""
        with self._lock:
            count = len(self._sessions)
            self._sessions.clear()
            logger.info(f"SessionManager shutdown: {count} sessions closed")

    def _generate_session_id(self) -> str:
        return secrets.token_hex(16)


def create_session_manager(**kwargs: Any) -> SessionManager:
    """Фабричная функция для создания SessionManager."""
    return SessionManager(**kwargs)


__all__ = [
    "SessionManager",
    "Session",
    "SessionError",
    "SessionNotFoundError",
    "SessionExpiredError",
    "SessionLockedError",
    "TooManySessionsError",
    "create_session_manager",
]
