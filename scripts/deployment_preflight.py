#!/usr/bin/env python3
"""Fail-closed deployment checks for DataLineage AI production environments.

This script intentionally uses only the Python standard library so it can run
before installing/importing the application.
"""
from __future__ import annotations
import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

PLACEHOLDERS = ("REPLACE_WITH", "CHANGE_ME", "your-domain.example", "example.com")


def inspect_environment(replicas: int = 1, data_dir: str | None = None) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    env = os.environ

    production = env.get("DATALINEAGE_ENVIRONMENT", "").strip().lower() == "production"
    auth = env.get("DATALINEAGE_AUTH_ENABLED", "false").strip().lower() in {"1", "true", "yes"}
    auth_username = env.get("DATALINEAGE_AUTH_USERNAME", "").strip()
    email_dev_mode = env.get("DATALINEAGE_EMAIL_DEV_MODE", "true").strip().lower() in {"1", "true", "yes"}
    secure_cookie = env.get("DATALINEAGE_SECURE_COOKIE", "false").strip().lower() in {"1", "true", "yes"}
    secret = env.get("DATALINEAGE_SESSION_SECRET", "")
    base_url = env.get("DATALINEAGE_PUBLIC_BASE_URL", "")
    cors = [x.strip() for x in env.get("DATALINEAGE_CORS_ORIGINS", "").split(",") if x.strip()]
    db_url = env.get("DATALINEAGE_DATABASE_URL", "").strip()
    bootstrap_password = env.get("DATALINEAGE_AUTH_PASSWORD", "")
    smtp_host = env.get("DATALINEAGE_SMTP_HOST", "").strip()
    smtp_from = env.get("DATALINEAGE_SMTP_FROM_EMAIL", "").strip()
    smtp_ssl = env.get("DATALINEAGE_SMTP_SSL", "false").strip().lower() in {"1", "true", "yes"}
    smtp_starttls = env.get("DATALINEAGE_SMTP_STARTTLS", "false").strip().lower() in {"1", "true", "yes"}
    redis_url = env.get("DATALINEAGE_REDIS_URL", "").strip()
    redis_required = env.get("DATALINEAGE_REDIS_REQUIRED", "false").strip().lower() in {"1", "true", "yes"}

    if not production:
        errors.append("DATALINEAGE_ENVIRONMENT must be production")
    if not auth:
        errors.append("DATALINEAGE_AUTH_ENABLED must be true")
    if not auth_username:
        errors.append("DATALINEAGE_AUTH_USERNAME must not be empty")
    if email_dev_mode:
        errors.append("DATALINEAGE_EMAIL_DEV_MODE must be false in production")
    if not secure_cookie:
        errors.append("DATALINEAGE_SECURE_COOKIE must be true")
    if len(bootstrap_password) < 16 or any(p.lower() in bootstrap_password.lower() for p in PLACEHOLDERS):
        errors.append("DATALINEAGE_AUTH_PASSWORD must be a non-placeholder password of at least 16 characters")
    if len(secret.encode("utf-8")) < 32 or any(p in secret for p in PLACEHOLDERS):
        errors.append("DATALINEAGE_SESSION_SECRET must be a non-placeholder secret of at least 32 bytes")
    parsed_base = urlparse(base_url)
    if parsed_base.scheme != "https" or not parsed_base.netloc or any(p in base_url for p in PLACEHOLDERS):
        errors.append("DATALINEAGE_PUBLIC_BASE_URL must be a real HTTPS URL")
    if (not smtp_host or not smtp_from
            or any(marker in smtp_host.lower() or marker in smtp_from.lower()
                   for marker in ("replace_with", "your-provider", "your-domain", ".example"))):
        errors.append("DATALINEAGE_SMTP_HOST and DATALINEAGE_SMTP_FROM_EMAIL must be configured with real provider values")
    smtp_username = env.get("DATALINEAGE_SMTP_USERNAME", "")
    smtp_password = env.get("DATALINEAGE_SMTP_PASSWORD", "")
    if bool(smtp_username) != bool(smtp_password):
        errors.append("Configure both SMTP username and password, or leave both empty")
    try:
        smtp_port = int(env.get("DATALINEAGE_SMTP_PORT", "587"))
        if not 1 <= smtp_port <= 65535:
            raise ValueError
    except ValueError:
        errors.append("DATALINEAGE_SMTP_PORT must be between 1 and 65535")
    if smtp_ssl == smtp_starttls:
        errors.append("Enable exactly one of DATALINEAGE_SMTP_SSL or DATALINEAGE_SMTP_STARTTLS")
    if not cors:
        errors.append("DATALINEAGE_CORS_ORIGINS must contain explicit HTTPS origins")
    elif any(urlparse(origin).scheme != "https" or not urlparse(origin).netloc or "*" in origin for origin in cors):
        errors.append("Every DATALINEAGE_CORS_ORIGINS entry must be an explicit HTTPS origin; wildcards are not allowed")

    if replicas > 1:
        errors.append("replicas > 1 is not supported: not all application stores and runtime state are shared across processes yet")
    if not db_url:
        warnings.append("SQLite is selected. Keep one API replica and use durable, backed-up storage.")
    if redis_required and not redis_url:
        errors.append("DATALINEAGE_REDIS_REQUIRED is true but DATALINEAGE_REDIS_URL is empty")
    if redis_url and not redis_required:
        warnings.append("Redis is configured but DATALINEAGE_REDIS_REQUIRED is false; production may fall back to local state")
    if data_dir:
        path = Path(data_dir)
        if not path.exists():
            errors.append(f"Data directory does not exist: {path}")
        elif not path.is_dir():
            errors.append(f"Data path is not a directory: {path}")
        elif not os.access(path, os.W_OK):
            errors.append(f"Data directory is not writable: {path}")

    return errors, warnings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replicas", type=int, default=1)
    parser.add_argument("--data-dir", default=None)
    args = parser.parse_args()
    if args.replicas < 1:
        parser.error("--replicas must be at least 1")
    errors, warnings = inspect_environment(args.replicas, args.data_dir)
    for item in warnings:
        print(f"WARNING: {item}")
    for item in errors:
        print(f"BLOCKER: {item}")
    if errors:
        print(f"Deployment preflight FAILED: {len(errors)} blocker(s), {len(warnings)} warning(s)")
        return 1
    print(f"Deployment preflight PASSED: {len(warnings)} warning(s)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
