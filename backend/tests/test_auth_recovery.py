from urllib.parse import urlparse, parse_qs

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.rate_limit import reset_limits_for_tests
from app.user_store import issue_token, user_is_verified, get_session_version
from app.auth import COOKIE_NAME

client = TestClient(app)


@pytest.fixture(autouse=True)
def auth_test_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_USERS_DB_PATH", str(tmp_path / "users.sqlite3"))
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "admin")
    monkeypatch.setattr(settings, "auth_password", "Admin-Password-Strong-123!")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret-that-is-at-least-32-chars")
    monkeypatch.setattr(settings, "secure_cookie", False)
    monkeypatch.setattr(settings, "email_dev_mode", False)
    monkeypatch.setattr(settings, "app_environment", "test")
    monkeypatch.setattr(settings, "public_base_url", "http://testserver")
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(settings, "smtp_port", 587)
    monkeypatch.setattr(settings, "smtp_username", "")
    monkeypatch.setattr(settings, "smtp_password", "")
    monkeypatch.setattr(settings, "smtp_from_email", "noreply@example.test")
    monkeypatch.setattr(settings, "smtp_starttls", True)
    monkeypatch.setattr(settings, "smtp_ssl", False)
    monkeypatch.setattr(settings, "verification_ttl_seconds", 3600)
    monkeypatch.setattr(settings, "password_reset_ttl_seconds", 3600)
    from app import main
    delivered_urls = []
    monkeypatch.setattr(main, "send_action_email", lambda to_email, subject, action_url, action: delivered_urls.append(action_url))
    client.cookies.clear()
    reset_limits_for_tests()
    yield delivered_urls
    client.cookies.clear()
    reset_limits_for_tests()


def signup(email="person@example.com", password="Very-Strong-Password-123!"):
    return client.post("/auth/signup", json={"email": email, "password": password})


def token_from_response(response, delivered_urls):
    url = delivered_urls[-1]
    return parse_qs(urlparse(url).fragment)["verify_token"][0]


def verify(response, delivered_urls):
    return client.post("/auth/verify-email", json={"token": token_from_response(response, delivered_urls)})


def test_signup_creates_unverified_user_and_does_not_create_session(auth_test_settings):
    response = signup()
    assert response.status_code == 202
    assert response.json()["status"] == "verification_required"
    assert "datalineage_session" not in response.cookies
    assert user_is_verified("person@example.com") is False
    assert client.post("/auth/login", json={"email": "person@example.com", "password": "Very-Strong-Password-123!"}).status_code == 401


def test_valid_verification_succeeds_and_token_is_single_use(auth_test_settings):
    response = signup()
    token = token_from_response(response, auth_test_settings)
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 200
    assert user_is_verified("person@example.com") is True
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 400
    login = client.post("/auth/login", json={"email": "person@example.com", "password": "Very-Strong-Password-123!"})
    assert login.status_code == 200
    assert COOKIE_NAME in login.cookies


def test_invalid_and_expired_verification_tokens_fail(auth_test_settings):
    assert client.post("/auth/verify-email", json={"token": "bad-token"}).status_code == 400
    response = signup()
    token = token_from_response(response, auth_test_settings)
    from app.user_store import _connection
    import hashlib
    with _connection() as connection:
        connection.execute("UPDATE auth_tokens SET expires_at=0 WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
    assert client.post("/auth/verify-email", json={"token": token}).status_code == 400


def test_password_reset_request_is_generic_for_existing_and_unknown_email(auth_test_settings):
    response = signup()
    verify(response, auth_test_settings)
    existing = client.post("/auth/password-reset/request", json={"email": "person@example.com"})
    missing = client.post("/auth/password-reset/request", json={"email": "unknown@example.com"})
    assert existing.status_code == missing.status_code == 202
    assert existing.json()["message"] == missing.json()["message"]
    assert "development_url" not in existing.json()
    assert "development_url" not in missing.json()


def test_password_reset_changes_password_invalidates_session_and_token_is_single_use(auth_test_settings):
    response = signup()
    verify(response, auth_test_settings)
    login = client.post("/auth/login", json={"email": "person@example.com", "password": "Very-Strong-Password-123!"})
    assert login.status_code == 200
    old_cookie = login.cookies[COOKIE_NAME]
    reset_response = client.post("/auth/password-reset/request", json={"email": "person@example.com"})
    token = parse_qs(urlparse(auth_test_settings[-1]).fragment)["reset_token"][0]
    changed = client.post("/auth/password-reset/confirm", json={"token": token, "password": "New-Password-Strong-456!"})
    assert changed.status_code == 200
    assert client.post("/auth/password-reset/confirm", json={"token": token, "password": "Another-Password-Strong-789!"}).status_code == 400
    assert client.get("/auth/status", cookies={COOKIE_NAME: old_cookie}).json()["authenticated"] is False
    assert client.post("/auth/login", json={"email": "person@example.com", "password": "Very-Strong-Password-123!"}).status_code == 401
    assert client.post("/auth/login", json={"email": "person@example.com", "password": "New-Password-Strong-456!"}).status_code == 200


def test_invalid_reset_token_and_password_policy():
    assert client.post("/auth/password-reset/confirm", json={"token": "nope", "password": "short"}).status_code == 422
    assert client.post("/auth/password-reset/confirm", json={"token": "nope", "password": "Long-Enough-Password-123!"}).status_code == 400


def test_token_endpoint_rate_limit():
    for _ in range(5):
        assert client.post("/auth/password-reset/request", json={"email": "missing@example.com"}).status_code == 202
    response = client.post("/auth/password-reset/request", json={"email": "missing@example.com"})
    assert response.status_code == 429


def test_admin_login_remains_available():
    response = client.post("/auth/login", json={"email": "admin", "password": "Admin-Password-Strong-123!"})
    assert response.status_code == 200
    assert response.json()["role"] == "admin"


def test_unverified_account_can_request_resend_with_generic_response(auth_test_settings):
    signup()
    response = client.post("/auth/verification/request", json={"email": "person@example.com"})
    assert response.status_code == 202
    assert "development_url" not in response.json()
    assert client.post("/auth/verification/request", json={"email": "missing@example.com"}).json()["message"] == response.json()["message"]


def test_expired_password_reset_token_fails(auth_test_settings):
    response = signup()
    verify(response, auth_test_settings)
    requested = client.post("/auth/password-reset/request", json={"email": "person@example.com"})
    token = parse_qs(urlparse(auth_test_settings[-1]).fragment)["reset_token"][0]
    import hashlib
    from app.user_store import _connection
    with _connection() as connection:
        connection.execute("UPDATE auth_tokens SET expires_at=0 WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
    assert client.post("/auth/password-reset/confirm", json={"token": token, "password": "New-Password-Strong-456!"}).status_code == 400


def test_legacy_database_migration_preserves_existing_accounts(tmp_path, monkeypatch):
    import sqlite3
    db_path = tmp_path / "legacy-users.sqlite3"
    monkeypatch.setenv("DATALINEAGE_USERS_DB_PATH", str(db_path))
    with sqlite3.connect(db_path) as connection:
        connection.execute("CREATE TABLE users (email TEXT PRIMARY KEY COLLATE NOCASE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT 'legacy')")
        connection.execute("INSERT INTO users(email,password_hash) VALUES(?,?)", ("legacy@example.com", "unused-hash"))
    assert user_is_verified("legacy@example.com") is True
    assert get_session_version("legacy@example.com") == 0


def test_password_reset_delivery_failure_does_not_reveal_account_existence(auth_test_settings, monkeypatch):
    from app import main
    from app.email_delivery import EmailDeliveryError

    created = signup()
    verify(created, auth_test_settings)

    def fail_delivery(*args, **kwargs):
        raise EmailDeliveryError("Email could not be sent. Check SMTP configuration and try again.")

    monkeypatch.setattr(main, "send_action_email", fail_delivery)
    existing = client.post("/auth/password-reset/request", json={"email": "person@example.com"})
    unknown = client.post("/auth/password-reset/request", json={"email": "unknown@example.com"})
    assert existing.status_code == unknown.status_code == 202
    assert existing.json() == unknown.json()
    assert "delivered" not in existing.json()["message"].lower()
