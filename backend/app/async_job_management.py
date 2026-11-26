"""Milestone 33: bounded caching and asynchronous in-process analysis jobs.

This module is deliberately dependency-light. Cache/job state is process-local:
use Redis or a durable queue before deploying multiple workers or requiring
survival across restarts.
"""
from __future__ import annotations

from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from threading import RLock
from time import monotonic
from typing import Any, Callable
from uuid import uuid4


class TTLCache:
    """Thread-safe, bounded LRU cache with time-to-live expiration."""
    def __init__(self, max_entries: int = 256, ttl_seconds: float = 60.0):
        if max_entries < 1 or ttl_seconds <= 0:
            raise ValueError("max_entries and ttl_seconds must be positive")
        self.max_entries = max_entries
        self.ttl_seconds = ttl_seconds
        self._items: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = RLock()
        self.hits = 0
        self.misses = 0

    def get(self, key: str) -> Any | None:
        now = monotonic()
        with self._lock:
            item = self._items.get(key)
            if item is None:
                self.misses += 1
                return None
            expires, value = item
            if expires <= now:
                del self._items[key]
                self.misses += 1
                return None
            self._items.move_to_end(key)
            self.hits += 1
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._items[key] = (monotonic() + self.ttl_seconds, value)
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
            self.hits = self.misses = 0

    def stats(self) -> dict[str, int]:
        with self._lock:
            now = monotonic()
            expired = [k for k, (expiry, _) in self._items.items() if expiry <= now]
            for key in expired:
                del self._items[key]
            return {"entries": len(self._items), "max_entries": self.max_entries,
                    "hits": self.hits, "misses": self.misses}


class JobRegistry:
    """Bounded thread-pool job registry; results are retained only in memory."""
    def __init__(self, max_workers: int = 2, max_jobs: int = 500):
        if max_workers < 1 or max_jobs < 1:
            raise ValueError("max_workers and max_jobs must be positive")
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="datalineage")
        self._max_jobs = max_jobs
        self._jobs: OrderedDict[str, Future] = OrderedDict()
        self._lock = RLock()

    def submit(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> str:
        with self._lock:
            self._prune_locked()
            if len(self._jobs) >= self._max_jobs:
                raise RuntimeError("Job capacity reached; retry after existing jobs finish")
            job_id = str(uuid4())
            self._jobs[job_id] = self._pool.submit(fn, *args, **kwargs)
            return job_id

    def _prune_locked(self) -> None:
        # Remove completed jobs oldest-first only when capacity is needed.
        completed = [key for key, future in self._jobs.items() if future.done()]
        while len(self._jobs) >= self._max_jobs and completed:
            self._jobs.pop(completed.pop(0), None)

    def get(self, job_id: str) -> dict[str, Any] | None:
        with self._lock:
            future = self._jobs.get(job_id)
        if future is None:
            return None
        if future.cancelled():
            return {"job_id": job_id, "status": "cancelled"}
        if not future.done():
            return {"job_id": job_id, "status": "running"}
        try:
            return {"job_id": job_id, "status": "completed", "result": future.result()}
        except Exception as exc:
            # Avoid returning tracebacks or internal exception details to clients.
            return {"job_id": job_id, "status": "failed",
                    "error": f"Analysis failed ({type(exc).__name__})"}

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"jobs_retained": len(self._jobs),
                    "running_jobs": sum(not f.done() for f in self._jobs.values()),
                    "max_jobs": self._max_jobs}

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
