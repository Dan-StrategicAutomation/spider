"""Shared repository for persistent intelligence cache and coordinated API limits."""

import asyncio
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TypeVar

from spider.intelligence.cache import DEFAULT_CACHE_PATH, SQLiteIntelligenceCache

T = TypeVar("T")
DEFAULT_EXECUTOR_WORKERS = 8


class SharedNVDRateLimiter:
    """Process-wide NVD rate limiter shared by all client instances."""

    _limiters: dict[bool, "SharedNVDRateLimiter"] = {}
    _limiters_lock = threading.Lock()

    def __init__(self, has_api_key: bool = False):
        self.interval_seconds = 0.2 if has_api_key else 1.67
        self._lock = threading.Lock()
        self._last_request = 0.0

    @classmethod
    def for_api_key(cls, api_key: str = "") -> "SharedNVDRateLimiter":
        """Return the shared limiter for keyed or anonymous NVD traffic."""
        has_api_key = bool(api_key)
        with cls._limiters_lock:
            limiter = cls._limiters.get(has_api_key)
            if limiter is None:
                limiter = cls(has_api_key=has_api_key)
                cls._limiters[has_api_key] = limiter
            return limiter

    def wait(self) -> None:
        """Block the current worker thread until the next NVD request is allowed."""
        with self._lock:
            now = time.monotonic()
            wait_seconds = self.interval_seconds - (now - self._last_request)
            if wait_seconds > 0:
                time.sleep(wait_seconds)
            self._last_request = time.monotonic()


class IntelligenceRepository:
    """Shared persistence and executor service for intelligence clients."""

    _default: "IntelligenceRepository | None" = None
    _default_lock = threading.Lock()

    def __init__(
        self,
        cache_path: Path | str | None = None,
        max_workers: int = DEFAULT_EXECUTOR_WORKERS,
    ):
        self.cache = SQLiteIntelligenceCache(cache_path or DEFAULT_CACHE_PATH)
        self.executor = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="spider-intel"
        )

    @classmethod
    def default(cls) -> "IntelligenceRepository":
        """Return the process-wide repository used by default client instances."""
        with cls._default_lock:
            if cls._default is None:
                cls._default = cls()
            return cls._default

    async def run_blocking(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """Run blocking cache, rate-limit, or HTTP work in the repository executor."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, lambda: func(*args, **kwargs))

    def nvd_rate_limiter(self, api_key: str = "") -> SharedNVDRateLimiter:
        """Return the shared NVD limiter matching keyed or anonymous traffic."""
        return SharedNVDRateLimiter.for_api_key(api_key)
