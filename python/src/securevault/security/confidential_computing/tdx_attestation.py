"""SecureVault - Технология Intel TDX.

Программная модель запросов (quotes) конфиденциальных вычислений TDX.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class TdxError(Exception):
    """Ошибка TDX-аттестации."""


class TdxAttestation:
    """Формирование и проверка quotes TDX."""

    def __init__(self, signing_key: Optional[bytes] = None):
        self._signing_key = signing_key or secrets.token_bytes(32)

    def create_quote(
        self, data: bytes, mr_config_id: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Сформировать quote на основе данных и конфигурации."""
        mr = mr_config_id or b"\x00" * 32
        digest = hashlib.sha384(data).hexdigest()
        quote = {
            "algorithm": "tdx-quote",
            "mr_config_id": mr.hex(),
            "data_digest": digest,
            "nonce": secrets.token_hex(8),
        }
        signature = hmac.new(
            self._signing_key, digest.encode("utf-8"), hashlib.sha384
        ).digest()
        return {"quote": quote, "signature": signature.hex()}

    def verify_quote(self, quote: Dict[str, Any], signature: bytes) -> bool:
        """Проверить подпись quote."""
        digest = quote["data_digest"]
        expected = hmac.new(
            self._signing_key, digest.encode("utf-8"), hashlib.sha384
        ).digest()
        return hmac.compare_digest(
            expected,
            bytes.fromhex(
                signature.hex() if isinstance(signature, bytes) else signature
            ),
        )

    def is_tdx_enabled(self) -> bool:
        """Признак доступности TDX-окружения (программно False)."""
        return False


__all__ = ["TdxAttestation", "TdxError"]
