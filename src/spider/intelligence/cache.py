"""SQLite-backed cache primitives for shared threat intelligence state."""

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

NVD_TTL_SECONDS = 24 * 60 * 60
EPSS_TTL_SECONDS = 24 * 60 * 60
KEV_TTL_SECONDS = 24 * 60 * 60
DEFAULT_CACHE_PATH = Path.home() / ".spider" / "intelligence_cache.db"


class SQLiteIntelligenceCache:
    """Persistent JSON cache used by NVD, EPSS, and KEV repository lookups."""

    def __init__(self, path: Path | str = DEFAULT_CACHE_PATH):
        self.path = Path(path).expanduser()
        self._lock = threading.RLock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=30.0, check_same_thread=False)

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS intelligence_cache (
                    source TEXT NOT NULL,
                    cache_key TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (source, cache_key)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_intelligence_cache_expires_at
                ON intelligence_cache (expires_at)
                """
            )

    def get(self, source: str, cache_key: str) -> Any | None:
        """Return a cached JSON payload when present and not expired."""
        now = time.time()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT payload, expires_at
                FROM intelligence_cache
                WHERE source = ? AND cache_key = ?
                """,
                (source, cache_key),
            ).fetchone()
            if row is None:
                return None
            payload, expires_at = row
            if expires_at <= now:
                conn.execute(
                    "DELETE FROM intelligence_cache WHERE source = ? AND cache_key = ?",
                    (source, cache_key),
                )
                return None
            return json.loads(payload)

    def set(self, source: str, cache_key: str, payload: Any, ttl_seconds: int) -> None:
        """Store a JSON-serializable payload until the TTL expires."""
        now = time.time()
        expires_at = now + ttl_seconds
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO intelligence_cache
                    (source, cache_key, payload, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (source, cache_key, json.dumps(payload), now, expires_at),
            )

    def purge_expired(self) -> int:
        """Remove expired cache rows and return the number removed."""
        now = time.time()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM intelligence_cache WHERE expires_at <= ?",
                (now,),
            )
            return cursor.rowcount
