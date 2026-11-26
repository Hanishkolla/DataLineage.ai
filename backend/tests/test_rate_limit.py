from app.rate_limit import (
    clear_login_failures,
    login_retry_after,
    record_login_failure,
    record_signup_attempt,
    reset_limits_for_tests,
    signup_retry_after,
)


def setup_function():
    reset_limits_for_tests()


def teardown_function():
    reset_limits_for_tests()


def test_login_limiter_blocks_after_five_failures_and_expires():
    key = "127.0.0.1:person@example.com"
    for stamp in range(5):
        record_login_failure(key, now=float(stamp))
    assert login_retry_after(key, now=10.0) > 0
    assert login_retry_after(key, now=305.0) == 0


def test_successful_login_can_clear_failures():
    key = "127.0.0.1:person@example.com"
    for stamp in range(5):
        record_login_failure(key, now=float(stamp))
    assert login_retry_after(key, now=10.0) > 0
    clear_login_failures(key)
    assert login_retry_after(key, now=10.0) == 0


def test_signup_limiter_blocks_after_ten_attempts_and_expires():
    ip = "127.0.0.1"
    for stamp in range(10):
        record_signup_attempt(ip, now=float(stamp))
    assert signup_retry_after(ip, now=12.0) > 0
    assert signup_retry_after(ip, now=70.0) == 0
