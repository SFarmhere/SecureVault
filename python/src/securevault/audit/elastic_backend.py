"""SecureVault - Elasticsearch бэкенд для аудит-записей.

Обеспечивает интеграцию с Elasticsearch для хранения и поиска
аудит-записей в масштабе.
"""

import json
import logging
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)


class ElasticBackendError(Exception):
    """Ошибка Elasticsearch бэкенда."""
    pass


class ElasticBackend:
    """Бэкенд хранения аудит-записей в Elasticsearch."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 9200,
        index: str = "securevault-audit",
        scheme: str = "http",
    ):
        self.host = host
        self.port = port
        self.index = index
        self.scheme = scheme
        self._client = None
        self._initialized = False

    def initialize(self) -> None:
        """Инициализировать подключение к Elasticsearch."""
        try:
            from elasticsearch import Elasticsearch
            self._client = Elasticsearch(
                [{"host": self.host, "port": self.port, "scheme": self.scheme}]
            )
            self._initialized = True
            logger.info(f"Elasticsearch backend initialized: {self.host}:{self.port}/{self.index}")
        except ImportError:
            raise ElasticBackendError(
                "elasticsearch not installed. Install with: pip install elasticsearch"
            )
        except Exception as e:
            raise ElasticBackendError(f"Elasticsearch connection failed: {e}")

    def write(self, entry: Dict[str, Any]) -> None:
        """Записать запись."""
        if not self._initialized:
            self.initialize()
        self._client.index(
            index=self.index,
            id=entry.get("entry_id"),
            body=entry,
        )

    def read(
        self,
        limit: int = 100,
        offset: int = 0,
        filters: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Прочитать записи."""
        if not self._initialized:
            self.initialize()
        query = {"size": limit, "from": offset}
        if filters:
            must = []
            for key, value in filters.items():
                must.append({"term": {key: value}})
            query["query"] = {"bool": {"must": must}}
        result = self._client.search(index=self.index, body=query)
        return [hit["_source"] for hit in result["hits"]["hits"]]

    def close(self) -> None:
        """Закрыть подключение."""
        self._initialized = False


__all__ = ["ElasticBackend", "ElasticBackendError"]