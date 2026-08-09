"""SecureVault - Дедупликация блоков данных.

Реализует CDC (Content-Defined Chunking) — разбиение потока данных на
переменные блоки на основе содержимого, а также хранение манифеста
блоков для контейнеров с дедупликацией.
"""

import hashlib
import logging
import threading
from pathlib import Path
from typing import Dict, Iterable, Iterator, List

logger = logging.getLogger(__name__)


class Chunk:
    """Блок данных (chunk)."""

    __slots__ = ("data", "hash_val", "size", "offset")

    def __init__(self, data: bytes, offset: int = 0):
        self.data = data
        self.hash_val = hashlib.sha256(data).hexdigest()
        self.size = len(data)
        self.offset = offset

    def to_dict(self) -> dict:
        """Сериализация в словарь."""
        return {
            "hash": self.hash_val,
            "size": self.size,
            "offset": self.offset,
        }


class CdcChunker:
    """Разбиение данных на блоки методом CDC (Content-Defined Chunking).

    Использует скользящее окно (rolling hash) для определения границ блоков
    по содержимому, что обеспечивает устойчивость границ при вставке/удалении
    данных (в отличие от фиксированных блоков).
    """

    # Параметры по умолчанию (аналог FastCDC)
    AVG_CHUNK_SIZE = 64 * 1024  # 64 KB
    MIN_CHUNK_SIZE = 16 * 1024  # 16 KB
    MAX_CHUNK_SIZE = 256 * 1024  # 256 KB

    # Маска для определения границы: lower 13 bits == 0
    # Вероятность границы ~ 1/8192
    BITS = 13
    MASK = (1 << BITS) - 1

    # Геар-таблица для rolling hash
    GEAR_TABLE: list = []

    @classmethod
    def _init_gear(cls) -> None:
        """Инициализировать таблицу gear (детерминированно)."""
        if cls.GEAR_TABLE:
            return
        seed = 0x9E3779B9
        for _ in range(256):
            seed = (seed * 0x5851F42D + 0x9E3779B9) & 0xFFFFFFFF
            cls.GEAR_TABLE.append(seed | 1)  # нечётные значения

    def __init__(
        self,
        avg_size: int = AVG_CHUNK_SIZE,
        min_size: int = MIN_CHUNK_SIZE,
        max_size: int = MAX_CHUNK_SIZE,
    ):
        self.avg_size = max(avg_size, 1024)
        self.min_size = max(min_size, 1024)
        self.max_size = max(max_size, self.min_size)
        self.avg_size = max(self.avg_size, self.min_size)
        self.max_size = max(self.max_size, self.avg_size)
        self._init_gear()

    def chunk(self, data: bytes) -> List[Chunk]:
        """Разбить данные на блоки CDC."""
        chunks: List[Chunk] = []
        data_len = len(data)
        pos = 0

        while pos < data_len:
            end = self._find_chunk_end(data, pos, data_len)
            chunk_data = data[pos:end]
            chunks.append(Chunk(chunk_data, pos))
            pos = end

        return chunks

    def _find_chunk_end(self, data: bytes, start: int, data_len: int) -> int:
        """Найти конец блока, начиная с позиции start."""
        remaining = data_len - start
        if remaining <= self.min_size:
            return data_len

        max_end = min(start + self.max_size, data_len)
        min_end = start + self.min_size

        hash_val = 0
        window_size = 8  # небольшое скользящее окно

        for i in range(start + window_size, max_end):
            # Скользящий хеш: добавляем новый байт, вычитаем старый
            hash_val = (
                (hash_val << 1)
                + (self.GEAR_TABLE[data[i]] ^
                   self.GEAR_TABLE[data[i - window_size]])
            ) & 0xFFFFFFFF

            # Граница: если перешли минимальный размер и хеш попал в маску
            if i >= min_end and (hash_val & self.MASK) == 0:
                return i

        return max_end

    @staticmethod
    def iter_chunks(
        path: Path,
        avg_size: int = AVG_CHUNK_SIZE,
        min_size: int = MIN_CHUNK_SIZE,
        max_size: int = MAX_CHUNK_SIZE,
    ) -> Iterator[Chunk]:
        """Итеративное разбиение файла на блоки (поточная обработка)."""
        chunker = CdcChunker(avg_size, min_size, max_size)
        with path.open("rb") as f:
            buffer = f.read(min_size)
            offset = 0
            while buffer:
                # Читаем до max_size
                need = chunker.max_size - len(buffer)
                if need > 0:
                    more = f.read(need)
                    if not more:
                        pass
                    else:
                        buffer += more

                chunks = chunker.chunk(buffer)
                for c in chunks:
                    c.offset += offset
                    yield c
                    offset += c.size
                # Оставляем хвост (неполный последний блок)
                last = chunks[-1].size if chunks else 0
                buffer = buffer[last:]


class ManifestStore:
    """Хранилище манифеста блоков контейнера.

    Отслеживает хеши блоков, ссылки на них из файлов и сборку мусора
    неиспользуемых блоков.
    """

    def __init__(self):
        self._blocks: Dict[str, int] = {}  # hash -> refcount
        self._files: Dict[str, List[str]] = {}  # file_id -> [hash, ...]
        self._lock = threading.RLock()

    def add_file(self, file_id: str, chunks: Iterable[Chunk]) -> None:
        """Добавить файл в манифест (увеличить счётчики блоков)."""
        with self._lock:
            hashes = []
            for chunk in chunks:
                hashes.append(chunk.hash_val)
                self._blocks[chunk.hash_val] = self._blocks.get(
                    chunk.hash_val, 0) + 1
            # Старый файл с тем же id заменяем
            old = self._files.pop(file_id, [])
            for h in old:
                if self._blocks.get(h, 0) > 0:
                    self._blocks[h] -= 1
                    if self._blocks[h] == 0:
                        del self._blocks[h]
            self._files[file_id] = hashes

    def remove_file(self, file_id: str) -> None:
        """Удалить файл (уменьшить счётчики, освободить блоки)."""
        with self._lock:
            hashes = self._files.pop(file_id, [])
            for h in hashes:
                if self._blocks.get(h, 0) > 0:
                    self._blocks[h] -= 1
                    if self._blocks[h] == 0:
                        del self._blocks[h]

    def get_blocks(self, file_id: str) -> List[str]:
        """Получить хеши блоков файла."""
        with self._lock:
            return list(self._files.get(file_id, []))

    def unique_blocks(self) -> List[str]:
        """Список уникальных (живых) блоков."""
        with self._lock:
            return list(self._blocks.keys())

    def block_refs(self, hash_val: str) -> int:
        """Число ссылок на блок."""
        with self._lock:
            return self._blocks.get(hash_val, 0)

    def dedup_ratio(self, file_id: str) -> float:
        """Оценка коэффициента дедупликации для файла."""
        with self._lock:
            blocks = self._files.get(file_id, [])
            if not blocks:
                return 0.0
            unique = len(set(blocks))
            return 1.0 - (unique / len(blocks))

    def collect_garbage(self) -> List[str]:
        """Сборка мусора: вернуть хеши блоков с нулевыми ссылками (уже удалены)."""
        with self._lock:
            zero = [h for h, refs in self._blocks.items() if refs <= 0]
            for h in zero:
                del self._blocks[h]
            return zero


__all__ = ["CdcChunker", "Chunk", "ManifestStore"]
