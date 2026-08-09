"""
SecureVault - Forensic логирование

Обеспечивает специализированное логирование для судебной
доказательной базы. Все записи forensic лога:
1. Подписываются ECDSA
2. Связываются в hash chain
3. Имеют полную метаданные (IP, время, сессия)
4. Экспортируются в стойкий формат

Использование:
    from securevault.audit.forensic_logger import ForensicLogger

    fl = ForensicLogger()
    fl.initialize()

    fl.log("USER_LOGIN", user_id="user1", details={"ip": "192.168.1.1"})
    fl.export("forensic_evidence.json")
"""

import json
import hashlib
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime

from securevault.audit.log_signer import LogSigner

logger = logging.getLogger(__name__)


class ForensicLoggerError(Exception):
    """Ошибка forensic логирования."""


class ForensicLogger:
    """
    Forensic логгер для доказательной базы.

    Каждая запись:
    - Содержит полные метаданные (время, IP, сессия)
    - Подписывается ECDSA
    - Связана с предыдущей через hash chain
    """

    def __init__(self, signer: Optional[LogSigner] = None):
        """
        Инициализировать forensic логгер.

        Args:
            signer: Подписант записей. Если None, создается новый.
        """
        self._signer = signer or LogSigner()
        self._entries: List[Dict[str, Any]] = []
        self._last_hash: Optional[str] = None
        self._initialized = False

    def initialize(self) -> None:
        """Инициализировать логгер."""
        self._signer.initialize()
        self._initialized = True
        logger.info("ForensicLogger initialized")

    def log(
        self,
        event: str,
        user_id: str = "system",
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Записать событие в forensic лог.

        Args:
            event: Название события.
            user_id: ID пользователя.
            details: Детали события.
            ip_address: IP-адрес.
            session_id: ID сессии.

        Returns:
            Созданная запись.

        Raises:
            ForensicLoggerError: Если запись не удалась.
        """
        if not self._initialized:
            raise ForensicLoggerError("ForensicLogger not initialized")

        entry = {
            "event": event,
            "user_id": user_id,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {},
            "ip_address": ip_address,
            "session_id": session_id,
            "prev_hash": self._last_hash,
        }

        # Вычисление хеша
        entry_hash = hashlib.sha256(
            json.dumps(entry, sort_keys=True, default=str).encode()
        ).hexdigest()
        entry["entry_hash"] = entry_hash

        # Подпись
        entry["signature"] = self._signer.sign(entry)

        # Добавление в цепочку
        self._entries.append(entry)
        self._last_hash = entry_hash

        logger.info(f"Forensic event logged: {event} (user={user_id})")
        return entry

    def verify(self) -> List[str]:
        """Проверить целостность всех записей."""
        errors = []
        prev_hash = None

        for i, entry in enumerate(self._entries):
            if entry.get("prev_hash") != prev_hash:
                errors.append(f"Entry {i}: prev_hash mismatch")
            if not self._signer.verify(entry, entry.get("signature", "")):
                errors.append(f"Entry {i}: signature invalid")
            prev_hash = entry.get("entry_hash")

        return errors

    def export(self, output_path: str) -> int:
        """
        Экспортировать forensic записи в файл.

        Args:
            output_path: Путь для экспорта.

        Returns:
            Количество экспортированных записей.
        """
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(self._entries, f, indent=2, ensure_ascii=False)
        logger.info(f"Forensic log exported: {len(self._entries)} entries")
        return len(self._entries)

    def add_entries(
        self,
        entries: List[Dict[str, Any]],
        verify_signature: bool = True,
    ) -> int:
        """
        Добавить записи из внешнего источника.

        Args:
            entries: Список записей.
            verify_signature: Проверять подписи.

        Returns:
            Количество добавленных записей.
        """
        added = 0
        for entry in entries:
            if verify_signature:
                if not self._signer.verify(entry, entry.get("signature", "")):
                    logger.warning(f"Skipping entry with invalid signature")
                    continue
            self._entries.append(entry)
            if entry.get("entry_hash"):
                self._last_hash = entry["entry_hash"]
            added += 1
        return added

    def get_entries(self) -> List[Dict[str, Any]]:
        """Получить все записи."""
        return list(self._entries)

    def get_last_hash(self) -> Optional[str]:
        """Получить хеш последней записи."""
        return self._last_hash

    def get_public_key(self) -> Optional[bytes]:
        """Получить публичный ключ."""
        return self._signer.get_public_key()


__all__ = ["ForensicLogger", "ForensicLoggerError"]
