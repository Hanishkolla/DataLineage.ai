import time
import pytest
from app.async_job_management import TTLCache, JobRegistry


def test_ttl_cache_hit_and_miss():
    cache = TTLCache(max_entries=2, ttl_seconds=1)
    assert cache.get("missing") is None
    cache.set("a", {"value": 1})
    assert cache.get("a") == {"value": 1}
    assert cache.stats()["hits"] == 1


def test_ttl_cache_expires_entries():
    cache = TTLCache(max_entries=2, ttl_seconds=0.01)
    cache.set("a", 1)
    time.sleep(0.02)
    assert cache.get("a") is None


def test_ttl_cache_evicts_least_recently_used():
    cache = TTLCache(max_entries=2, ttl_seconds=10)
    cache.set("a", 1)
    cache.set("b", 2)
    cache.get("a")
    cache.set("c", 3)
    assert cache.get("b") is None
    assert cache.get("a") == 1


def test_job_registry_returns_completed_result():
    jobs = JobRegistry(max_workers=1, max_jobs=5)
    try:
        job_id = jobs.submit(lambda x: x * 2, 21)
        for _ in range(100):
            status = jobs.get(job_id)
            if status["status"] == "completed":
                break
            time.sleep(0.01)
        assert status["status"] == "completed"
        assert status["result"] == 42
    finally:
        jobs.shutdown()


def test_job_registry_sanitizes_failure():
    jobs = JobRegistry(max_workers=1, max_jobs=5)
    try:
        def fail():
            raise ValueError("secret internal detail")
        job_id = jobs.submit(fail)
        for _ in range(100):
            status = jobs.get(job_id)
            if status["status"] == "failed":
                break
            time.sleep(0.01)
        assert status["status"] == "failed"
        assert "secret" not in status["error"]
    finally:
        jobs.shutdown()


def test_invalid_cache_limits_rejected():
    with pytest.raises(ValueError):
        TTLCache(max_entries=0)
