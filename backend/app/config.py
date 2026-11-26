"""Environment-backed settings for local and hosted deployments."""
from __future__ import annotations

import os
from pathlib import Path

# Load a project-local .env for simple local setup (never commit real production secrets).
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parents[1] / ".env", override=False)
except ImportError:
    pass

from pydantic import BaseModel, Field


def _int_env(name: str, default: int, minimum: int = 1) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ValueError(f"{name} must be at least {minimum}")
    return value


def _bool_env(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean value")


def _cors_origins() -> list[str]:
    raw = os.getenv("DATALINEAGE_CORS_ORIGINS", "").strip()
    if not raw:
        return [
            "http://127.0.0.1:5500",
            "http://localhost:5500",
            "http://127.0.0.1:5501",
            "http://localhost:5501",
        ]
    origins = [item.strip().rstrip("/") for item in raw.split(",") if item.strip()]
    if "*" in origins:
        raise ValueError("DATALINEAGE_CORS_ORIGINS cannot contain '*'")
    return origins


class Settings(BaseModel):
    app_name: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_APP_NAME", "DataLineage AI"))
    max_upload_bytes: int = Field(default_factory=lambda: _int_env("DATALINEAGE_MAX_UPLOAD_BYTES", 10 * 1024 * 1024))
    max_zip_files: int = Field(default_factory=lambda: _int_env("DATALINEAGE_MAX_ZIP_FILES", 500))
    max_sql_file_bytes: int = Field(default_factory=lambda: _int_env("DATALINEAGE_MAX_SQL_FILE_BYTES", 2 * 1024 * 1024))
    max_total_sql_bytes: int = Field(default_factory=lambda: _int_env("DATALINEAGE_MAX_TOTAL_SQL_BYTES", 10 * 1024 * 1024))
    max_request_bytes: int = Field(default_factory=lambda: _int_env("DATALINEAGE_MAX_REQUEST_BYTES", 12 * 1024 * 1024))
    cors_origins: list[str] = Field(default_factory=_cors_origins)
    auth_enabled: bool = Field(default_factory=lambda: _bool_env("DATALINEAGE_AUTH_ENABLED", False))
    auth_username: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_AUTH_USERNAME", "admin"))
    auth_password: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_AUTH_PASSWORD", ""))
    session_secret: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_SESSION_SECRET", ""))
    session_ttl_seconds: int = Field(default_factory=lambda: _int_env("DATALINEAGE_SESSION_TTL_SECONDS", 8 * 60 * 60))
    secure_cookie: bool = Field(default_factory=lambda: _bool_env("DATALINEAGE_SECURE_COOKIE", False))
    app_environment: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_ENVIRONMENT", "development").strip().lower())
    public_base_url: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_PUBLIC_BASE_URL", "http://127.0.0.1:8000").strip().rstrip("/"))
    email_dev_mode: bool = Field(default_factory=lambda: _bool_env("DATALINEAGE_EMAIL_DEV_MODE", False))
    smtp_host: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_SMTP_HOST", "").strip())
    smtp_port: int = Field(default_factory=lambda: _int_env("DATALINEAGE_SMTP_PORT", 587))
    smtp_username: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_SMTP_USERNAME", ""))
    smtp_password: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_SMTP_PASSWORD", ""))
    smtp_from_email: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_SMTP_FROM_EMAIL", "").strip())
    smtp_starttls: bool = Field(default_factory=lambda: _bool_env("DATALINEAGE_SMTP_STARTTLS", True))
    smtp_ssl: bool = Field(default_factory=lambda: _bool_env("DATALINEAGE_SMTP_SSL", False))
    razorpay_key_id: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_RAZORPAY_KEY_ID", "").strip())
    razorpay_key_secret: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_RAZORPAY_KEY_SECRET", "").strip())
    razorpay_webhook_secret: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_RAZORPAY_WEBHOOK_SECRET", "").strip())
    razorpay_mode: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_RAZORPAY_MODE", "test").strip().lower())
    verification_ttl_seconds: int = Field(default_factory=lambda: _int_env("DATALINEAGE_VERIFICATION_TTL_SECONDS", 86400))
    password_reset_ttl_seconds: int = Field(default_factory=lambda: _int_env("DATALINEAGE_PASSWORD_RESET_TTL_SECONDS", 3600))

    redis_url: str = Field(default_factory=lambda: os.getenv("DATALINEAGE_REDIS_URL", "").strip())
    redis_required: bool = Field(default_factory=lambda: _bool_env("DATALINEAGE_REDIS_REQUIRED", False))

    firebase_project_id: str = Field(
        default_factory=lambda: os.getenv("DATALINEAGE_FIREBASE_PROJECT_ID", "").strip()
    )
    firebase_credentials_path: str = Field(
        default_factory=lambda: os.getenv("DATALINEAGE_FIREBASE_CREDENTIALS_PATH", "").strip()
    )

settings = Settings()
