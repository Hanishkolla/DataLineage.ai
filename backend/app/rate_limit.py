"""Authentication and action rate limits with optional Redis sharing."""
from __future__ import annotations

from collections import defaultdict, deque
from threading import Lock
from time import monotonic
import hashlib
from typing import Deque

_LOGIN_LIMIT = 5
_LOGIN_WINDOW_SECONDS = 300
_SIGNUP_LIMIT = 10
_SIGNUP_WINDOW_SECONDS = 60
_TOKEN_LIMIT = 5
_TOKEN_WINDOW_SECONDS = 300

_lock = Lock()
_login_failures: dict[str, Deque[float]] = defaultdict(deque)
_signup_attempts: dict[str, Deque[float]] = defaultdict(deque)
_token_attempts: dict[str, Deque[float]] = defaultdict(deque)


def _prune(events: Deque[float], now: float, window: int) -> None:
    while events and now - events[0] >= window:
        events.popleft()


def _bound_registry(registry: dict[str, Deque[float]], now: float, window: int) -> None:
    """Occasionally discard expired keys and cap memory used by unique identities/IPs."""
    if len(registry) < 1_000:
        return
    expired = [key for key, events in registry.items() if not events or now - events[-1] >= window]
    for key in expired:
        registry.pop(key, None)
    while len(registry) > 10_000:
        registry.pop(next(iter(registry)))


def login_retry_after(key: str, now: float | None = None) -> int:
    """Return seconds until the login key is allowed, or zero if allowed."""
    current = monotonic() if now is None else now
    with _lock:
        _bound_registry(_login_failures, current, _LOGIN_WINDOW_SECONDS)
        events = _login_failures[key]
        _prune(events, current, _LOGIN_WINDOW_SECONDS)
        if len(events) < _LOGIN_LIMIT:
            return 0
        return max(1, int(_LOGIN_WINDOW_SECONDS - (current - events[0]) + 0.999))


def record_login_failure(key: str, now: float | None = None) -> None:
    current = monotonic() if now is None else now
    with _lock:
        _bound_registry(_login_failures, current, _LOGIN_WINDOW_SECONDS)
        events = _login_failures[key]
        _prune(events, current, _LOGIN_WINDOW_SECONDS)
        events.append(current)


def clear_login_failures(key: str) -> None:
    with _lock:
        _login_failures.pop(key, None)


def signup_retry_after(ip: str, now: float | None = None) -> int:
    current = monotonic() if now is None else now
    with _lock:
        _bound_registry(_signup_attempts, current, _SIGNUP_WINDOW_SECONDS)
        events = _signup_attempts[ip]
        _prune(events, current, _SIGNUP_WINDOW_SECONDS)
        if len(events) < _SIGNUP_LIMIT:
            return 0
        return max(1, int(_SIGNUP_WINDOW_SECONDS - (current - events[0]) + 0.999))


def record_signup_attempt(ip: str, now: float | None = None) -> None:
    current = monotonic() if now is None else now
    with _lock:
        _bound_registry(_signup_attempts, current, _SIGNUP_WINDOW_SECONDS)
        events = _signup_attempts[ip]
        _prune(events, current, _SIGNUP_WINDOW_SECONDS)
        events.append(current)


def token_retry_after(key: str, now: float | None = None) -> int:
    current = monotonic() if now is None else now
    with _lock:
        _bound_registry(_token_attempts, current, _TOKEN_WINDOW_SECONDS)
        events = _token_attempts[key]
        _prune(events, current, _TOKEN_WINDOW_SECONDS)
        if len(events) < _TOKEN_LIMIT:
            return 0
        return max(1, int(_TOKEN_WINDOW_SECONDS - (current - events[0]) + 0.999))


def record_token_attempt(key: str, now: float | None = None) -> None:
    current = monotonic() if now is None else now
    with _lock:
        _bound_registry(_token_attempts, current, _TOKEN_WINDOW_SECONDS)
        events = _token_attempts[key]
        _prune(events, current, _TOKEN_WINDOW_SECONDS)
        events.append(current)


def reset_limits_for_tests() -> None:
    """Clear all counters; intended for isolated tests only."""
    with _lock:
        _login_failures.clear()
        _signup_attempts.clear()
        _token_attempts.clear()

# Lightweight authenticated action throttles. Deployments with multiple workers
# must enforce equivalent shared limits at the gateway or with Redis.
_action_attempts: dict[str, Deque[float]] = defaultdict(deque)

def action_retry_after(key: str, limit: int, window_seconds: int, now: float | None = None) -> int:
    current = monotonic() if now is None else now
    with _lock:
        _bound_registry(_action_attempts, current, window_seconds)
        events = _action_attempts[key]
        _prune(events, current, window_seconds)
        if len(events) < limit:
            return 0
        return max(1, int(window_seconds - (current - events[0]) + 0.999))

def record_action_attempt(key: str, window_seconds: int, now: float | None = None) -> None:
    current = monotonic() if now is None else now
    with _lock:
        _bound_registry(_action_attempts, current, window_seconds)
        events = _action_attempts[key]
        _prune(events, current, window_seconds)
        events.append(current)


# M49: optional shared Redis rate limits. Local in-memory limits remain the
# development fallback. Production deployments fail closed if configured Redis
# cannot be reached.
from .config import settings
_redis_client = None
_redis_guard = Lock()

def _get_redis():
    global _redis_client
    if not settings.redis_url:
        return None
    with _redis_guard:
        if _redis_client is not None:
            return _redis_client
        try:
            import redis
            client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=2,
                                          socket_timeout=2, decode_responses=True)
            client.ping()
            _redis_client = client
            return client
        except Exception as exc:
            if settings.redis_required or settings.app_environment == "production":
                raise RuntimeError("Shared rate-limit store is unavailable") from exc
            return None

def rate_limit_backend_status() -> dict[str, str]:
    if not settings.redis_url:
        return {"backend": "process_local", "status": "ok" if not settings.redis_required else "unavailable"}
    try:
        client = _get_redis()
        if client is None:
            return {"backend": "redis", "status": "unavailable"}
        client.ping()
        return {"backend": "redis", "status": "ok"}
    except Exception:
        return {"backend": "redis", "status": "unavailable"}

def consume_shared_limit(key: str, limit: int, window_seconds: int, namespace: str = "action") -> int:
    """Atomically consume a fixed-window quota; return retry seconds or zero."""
    client = _get_redis()
    if client is None:
        retry = action_retry_after(key, limit, window_seconds)
        if retry:
            return retry
        record_action_attempt(key, window_seconds)
        return 0
    bucket = int(__import__("time").time()) // window_seconds
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    redis_key = f"datalineage:ratelimit:{namespace}:{key_digest}:{bucket}"
    script = "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],ARGV[1]) end; if n>tonumber(ARGV[2]) then return redis.call('TTL',KEYS[1]) end; return 0"
    return max(0, int(client.eval(script, 1, redis_key, window_seconds, limit)))

# Override login failure operations with Redis-backed shared counters when enabled.
_local_login_retry_after = login_retry_after
_local_record_login_failure = record_login_failure
_local_clear_login_failures = clear_login_failures

def login_retry_after(key: str, now: float | None = None) -> int:
    client = _get_redis()
    if client is None:
        return _local_login_retry_after(key, now)
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    redis_key = f"datalineage:ratelimit:login:{key_digest}"
    count = int(client.get(redis_key) or 0)
    return max(1, int(client.ttl(redis_key))) if count >= _LOGIN_LIMIT else 0

def record_login_failure(key: str, now: float | None = None) -> None:
    client = _get_redis()
    if client is None:
        return _local_record_login_failure(key, now)
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    redis_key = f"datalineage:ratelimit:login:{key_digest}"
    pipe = client.pipeline()
    pipe.incr(redis_key)
    pipe.expire(redis_key, _LOGIN_WINDOW_SECONDS, nx=True)
    pipe.execute()

def clear_login_failures(key: str) -> None:
    client = _get_redis()
    if client is None:
        return _local_clear_login_failures(key)
    key_digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    client.delete(f"datalineage:ratelimit:login:{key_digest}")
