from app import rate_limit


def setup_function():
    rate_limit.reset_limits_for_tests()


def test_shared_limiter_local_fallback_allows_then_blocks(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "redis_url", "")
    monkeypatch.setattr(rate_limit.settings, "redis_required", False)
    for _ in range(2):
        assert rate_limit.consume_shared_limit("signup-ip", 2, 60, "signup") == 0
    assert rate_limit.consume_shared_limit("signup-ip", 2, 60, "signup") > 0


def test_backend_status_reports_local_fallback(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "redis_url", "")
    monkeypatch.setattr(rate_limit.settings, "redis_required", False)
    assert rate_limit.rate_limit_backend_status() == {"backend": "process_local", "status": "ok"}


def test_login_failures_keep_existing_threshold(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "redis_url", "")
    for _ in range(5):
        rate_limit.record_login_failure("user-ip")
    assert rate_limit.login_retry_after("user-ip") > 0
    rate_limit.clear_login_failures("user-ip")
    assert rate_limit.login_retry_after("user-ip") == 0
