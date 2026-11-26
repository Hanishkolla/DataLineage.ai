from __future__ import annotations

import zipfile
from io import BytesIO
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.auth import production_configuration_error
from app.config import settings
from app.ingestion import _safe_name
from app.main import app
from app.user_store import create_user, consume_verification_token, issue_token

client = TestClient(app)


def _set_valid_production_config(monkeypatch):
    monkeypatch.setattr(settings, "app_environment", "production")
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "production-admin")
    monkeypatch.setattr(settings, "auth_password", "A-strong-production-admin-password-123!")
    monkeypatch.setattr(settings, "session_secret", "unique-session-secret-for-production-tests-123456789")
    monkeypatch.setattr(settings, "secure_cookie", True)
    monkeypatch.setattr(settings, "public_base_url", "https://app.example.com")
    monkeypatch.setattr(settings, "email_dev_mode", False)
    monkeypatch.setattr(settings, "cors_origins", ["https://app.example.com"])
    monkeypatch.setattr(settings, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(settings, "smtp_from_email", "noreply@example.com")
    monkeypatch.setattr(settings, "smtp_username", "")
    monkeypatch.setattr(settings, "smtp_password", "")
    monkeypatch.setattr(settings, "smtp_starttls", True)
    monkeypatch.setattr(settings, "smtp_ssl", False)


def test_production_configuration_accepts_secure_complete_configuration(monkeypatch):
    _set_valid_production_config(monkeypatch)
    assert production_configuration_error() is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("auth_enabled", False),
        ("secure_cookie", False),
        ("public_base_url", "http://app.example.com"),
        ("email_dev_mode", True),
        ("session_secret", "replace-with-a-random-secret-at-least-32-characters"),
        ("auth_password", "replace-with-a-strong-admin-password"),
        ("cors_origins", ["http://localhost:5500"]),
        ("smtp_host", ""),
        ("smtp_starttls", False),
    ],
)
def test_production_configuration_rejects_unsafe_settings(monkeypatch, field, value):
    _set_valid_production_config(monkeypatch)
    monkeypatch.setattr(settings, field, value)
    assert production_configuration_error() is not None


def test_misconfigured_production_fails_closed_without_leaking_configuration(monkeypatch):
    _set_valid_production_config(monkeypatch)
    monkeypatch.setattr(settings, "secure_cookie", False)
    response = client.get("/")
    assert response.status_code == 503
    assert response.json() == {"detail": "Production security configuration is incomplete"}
    assert "x-content-type-options" in response.headers
    assert "session secret" not in response.text.lower()


def test_auth_denial_includes_security_headers(monkeypatch):
    monkeypatch.setattr(settings, "app_environment", "test")
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "admin")
    monkeypatch.setattr(settings, "auth_password", "admin-password-for-tests")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret-with-at-least-32-characters")
    response = client.post("/api/v1/analyze/text", json={"sql": "SELECT 1"})
    assert response.status_code == 401
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"


def test_unsafe_upload_filename_is_rejected_without_echoing_path():
    with pytest.raises(HTTPException) as error:
        _safe_name("../../private/secret.sql")
    assert error.value.status_code == 400
    assert "private" not in error.value.detail


def test_empty_or_dot_upload_filename_does_not_raise_index_error():
    for filename in ("", ".", "..", "C:/temp/evil.sql", "../evil.sql"):
        with pytest.raises(HTTPException) as error:
            _safe_name(filename)
        assert error.value.status_code == 400


def test_corrupt_zip_upload_returns_client_error_not_server_error():
    response = client.post(
        "/api/v1/analyze",
        files={"files": ("broken.zip", b"this is not a zip archive", "application/zip")},
    )
    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()


def test_cross_account_saved_runs_are_not_readable_or_comparable(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "app_environment", "test")
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "admin")
    monkeypatch.setattr(settings, "auth_password", "Admin-Password-Strong-123!")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret-with-at-least-32-characters")
    monkeypatch.setattr(settings, "secure_cookie", False)
    monkeypatch.setenv("DATALINEAGE_USERS_DB_PATH", str(tmp_path / "users.sqlite3"))
    monkeypatch.setenv("DATALINEAGE_DB_PATH", str(tmp_path / "runs.sqlite3"))

    for email, password in (
        ("one@example.com", "First-Strong-Password-123!"),
        ("two@example.com", "Second-Strong-Password-456!"),
    ):
        create_user(email, password)
        raw_token, _ = issue_token(email, "verify_email", 600)
        assert consume_verification_token(raw_token)

    client_a = TestClient(app)
    client_b = TestClient(app)
    login_a = client_a.post("/auth/login", json={"email": "one@example.com", "password": "First-Strong-Password-123!"})
    login_b = client_b.post("/auth/login", json={"email": "two@example.com", "password": "Second-Strong-Password-456!"})
    assert login_a.status_code == login_b.status_code == 200

    run_a_response = client_a.post("/api/v1/analyze/text", json={
        "project_name": "shared-name", "sql": "CREATE TABLE table_a AS SELECT id FROM raw_a"
    })
    run_b_response = client_b.post("/api/v1/analyze/text", json={
        "project_name": "shared-name", "sql": "CREATE TABLE table_b AS SELECT id FROM raw_b"
    })
    assert run_a_response.status_code == run_b_response.status_code == 200
    run_a = run_a_response.json()["run"]["run_id"]
    run_b = run_b_response.json()["run"]["run_id"]

    assert client_b.get(f"/api/v1/runs/{run_a}").status_code == 404
    assert client_a.get(f"/api/v1/runs/{run_b}").status_code == 404
    assert client_b.post("/api/v1/runs/compare", json={"run_a_id": run_a, "run_b_id": run_b}).status_code == 404
    runs_a = client_a.get("/api/v1/projects/shared-name/runs").json()["runs"]
    runs_b = client_b.get("/api/v1/projects/shared-name/runs").json()["runs"]
    assert {run["run_id"] for run in runs_a} == {run_a}
    assert {run["run_id"] for run in runs_b} == {run_b}


def test_verification_and_reset_links_put_tokens_in_url_fragment(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "app_environment", "development")
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "auth_username", "admin")
    monkeypatch.setattr(settings, "auth_password", "Admin-Password-Strong-123!")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret-with-at-least-32-characters")
    monkeypatch.setattr(settings, "email_dev_mode", True)
    monkeypatch.setattr(settings, "public_base_url", "http://testserver")
    monkeypatch.setenv("DATALINEAGE_USERS_DB_PATH", str(tmp_path / "users.sqlite3"))
    from app import main
    delivered = []
    monkeypatch.setattr(main, "send_action_email", lambda to_email, subject, url, action: delivered.append(url))

    signup = client.post("/auth/signup", json={"email": "fragment@example.com", "password": "Fragment-Password-123!"})
    assert signup.status_code == 202
    verification_url = urlparse(delivered[-1])
    assert verification_url.query == ""
    verify_token = parse_qs(verification_url.fragment)["verify_token"][0]
    assert client.post("/auth/verify-email", json={"token": verify_token}).status_code == 200

    reset = client.post("/auth/password-reset/request", json={"email": "fragment@example.com"})
    assert reset.status_code == 202
    reset_url = urlparse(delivered[-1])
    assert reset_url.query == ""
    assert parse_qs(reset_url.fragment).get("reset_token")
