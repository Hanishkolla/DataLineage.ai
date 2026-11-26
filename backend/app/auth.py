"""Small signed-cookie session helpers for the single-admin demo mode.

This is intentionally a single configured account, not multi-user identity or tenancy.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from typing import Any
from urllib.parse import urlsplit

from .config import settings

COOKIE_NAME = "datalineage_session"



def production_configuration_error() -> str | None:
    """Return a safe reason production startup/requests must be blocked.

    The detailed reason is intended for internal checks only; HTTP responses use
    a generic message so configuration details are not exposed to clients.
    """
    if settings.app_environment != "production":
        return None
    if not settings.auth_enabled:
        return "Authentication must be enabled in production"
    password_lower = settings.auth_password.lower()
    if (not settings.auth_username.strip() or len(settings.auth_password) < 16
            or any(marker in password_lower for marker in ("replace-with", "change-me", "your-password", "example-password"))):
        return "A non-placeholder admin password of at least 16 characters is required"
    secret_lower = settings.session_secret.lower()
    if (len(settings.session_secret.encode("utf-8")) < 32
            or any(marker in secret_lower for marker in ("replace-with", "change-me", "your-secret", "example-secret"))):
        return "A unique session secret of at least 32 characters is required"
    if not settings.secure_cookie:
        return "Secure session cookies must be enabled in production"
    parsed_base = urlsplit(settings.public_base_url)
    if parsed_base.scheme != "https" or not parsed_base.netloc or parsed_base.username or parsed_base.password:
        return "DATALINEAGE_PUBLIC_BASE_URL must be an HTTPS URL in production"
    if settings.email_dev_mode:
        return "Development email mode must be disabled in production"
    def is_secure_origin(origin: str) -> bool:
        parsed = urlsplit(origin)
        return bool(
            parsed.scheme == "https" and parsed.netloc and not parsed.username and not parsed.password
            and parsed.path in {"", "/"} and not parsed.query and not parsed.fragment
            and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        )

    if not settings.cors_origins or any(not is_secure_origin(origin) for origin in settings.cors_origins):
        return "Production CORS origins must be explicit HTTPS origins"
    from .email_delivery import email_configuration_error
    if email_configuration_error():
        return "Production email delivery must be configured correctly"
    if not (settings.smtp_ssl or settings.smtp_starttls):
        return "SMTP encryption must be enabled in production"
    return None


def auth_configuration_error() -> str | None:
    if not settings.auth_enabled:
        return None
    if not settings.auth_username.strip():
        return "DATALINEAGE_AUTH_USERNAME must not be empty when authentication is enabled"
    if not settings.auth_password:
        return "Set DATALINEAGE_AUTH_PASSWORD before enabling authentication"
    if len(settings.session_secret.encode("utf-8")) < 32:
        return "DATALINEAGE_SESSION_SECRET must be at least 32 characters"
    return None


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def create_session(username: str, now: int | None = None) -> str:
    error = auth_configuration_error()
    if error:
        raise ValueError(error)
    issued = int(time.time() if now is None else now)
    role = "admin" if username == settings.auth_username else "user"
    session_version = 0
    if role == "user":
        from .user_store import get_session_version
        current_version = get_session_version(username)
        if current_version is None:
            raise ValueError("User account is not verified or does not exist")
        session_version = current_version
    payload = json.dumps({"sub": username, "role": role, "sv": session_version, "exp": issued + settings.session_ttl_seconds}, separators=(",", ":")).encode("utf-8")
    body = _b64(payload)
    signature = hmac.new(settings.session_secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return body + "." + _b64(signature)


def verify_session(token: str | None, now: int | None = None) -> str | None:
    if not token or not settings.session_secret:
        return None
    try:
        body, signature_text = token.split(".", 1)
        expected = hmac.new(settings.session_secret.encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
        actual = _unb64(signature_text)
        if not hmac.compare_digest(expected, actual):
            return None
        payload: dict[str, Any] = json.loads(_unb64(body).decode("utf-8"))
        current = int(time.time() if now is None else now)
        username = payload.get("sub")
        role = payload.get("role", "admin")
        expires = payload.get("exp")
        if not isinstance(username, str) or not username.strip():
            return None
        if not isinstance(expires, int) or expires <= current:
            return None
        if role == "admin":
            return username if username == settings.auth_username else None
        if role == "user":
            from .user_store import get_session_version
            current_version = get_session_version(username)
            token_version = payload.get("sv", 0)
            if current_version is None or not isinstance(token_version, int) or token_version != current_version:
                return None
            return username
        return None
    except (ValueError, TypeError, UnicodeDecodeError, json.JSONDecodeError, binascii.Error):
        return None


def credentials_valid(username: str, password: str) -> bool:
    return hmac.compare_digest(username.encode("utf-8"), settings.auth_username.encode("utf-8")) and hmac.compare_digest(password.encode("utf-8"), settings.auth_password.encode("utf-8"))
