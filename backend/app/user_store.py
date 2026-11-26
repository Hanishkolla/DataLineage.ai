"""SQLite user accounts, password hashes, verification and reset tokens."""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from contextlib import contextmanager
from collections.abc import Iterator

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_ITERATIONS = 310_000


def _db_path() -> Path:
    configured = os.getenv("DATALINEAGE_USERS_DB_PATH", "").strip()
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / "data" / "users.sqlite3"


@contextmanager
def _connection() -> Iterator[object]:
    """Use shared PostgreSQL when configured; retain SQLite as the default."""
    from .db_backend import configured_database_url, connect_postgres
    database_url = configured_database_url()
    if database_url:
        connection = connect_postgres(database_url)
        try:
            connection.execute("""CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY, password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT
                  (to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')),
                email_verified INTEGER NOT NULL DEFAULT 1,
                session_version INTEGER NOT NULL DEFAULT 0)""")
            connection.execute("""CREATE TABLE IF NOT EXISTS auth_tokens (
                token_hash TEXT PRIMARY KEY, email TEXT NOT NULL,
                purpose TEXT NOT NULL CHECK (purpose IN ('verify_email','password_reset')),
                expires_at BIGINT NOT NULL, used_at BIGINT, created_at BIGINT NOT NULL)""")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_auth_tokens_email_purpose ON auth_tokens(email, purpose)")
            connection.commit()
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return

    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10, isolation_level="DEFERRED")
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("""CREATE TABLE IF NOT EXISTS users (
            email TEXT PRIMARY KEY COLLATE NOCASE, password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')))""")
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        if "email_verified" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1")
        if "session_version" not in columns:
            connection.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
        connection.execute("""CREATE TABLE IF NOT EXISTS auth_tokens (
            token_hash TEXT PRIMARY KEY, email TEXT NOT NULL COLLATE NOCASE,
            purpose TEXT NOT NULL CHECK (purpose IN ('verify_email','password_reset')),
            expires_at INTEGER NOT NULL, used_at INTEGER, created_at INTEGER NOT NULL)""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_auth_tokens_email_purpose ON auth_tokens(email, purpose)")
        connection.commit()
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def normalize_email(email: str) -> str:
    value = email.strip().lower()
    if len(value) > 254 or not _EMAIL_RE.fullmatch(value):
        raise ValueError("Enter a valid email address")
    return value


def _hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations_text, salt_hex, digest_hex = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations_text))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def create_user(email: str, password: str) -> dict[str, str]:
    normalized = normalize_email(email)
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Password must be between 12 and 256 characters")
    password_hash = _hash_password(password)
    with _connection() as connection:
        try:
            connection.execute("INSERT INTO users (email, password_hash, email_verified, session_version) VALUES (?, ?, 0, 0)", (normalized, password_hash))
        except Exception as exc:
            if isinstance(exc, sqlite3.IntegrityError) or getattr(exc, "sqlstate", None) == "23505":
                raise ValueError("An account with this email already exists") from exc
            raise
        row = connection.execute("SELECT email, created_at FROM users WHERE email = ?", (normalized,)).fetchone()
    return {"email": row["email"], "created_at": row["created_at"]}


def authenticate_user(email: str, password: str) -> bool:
    try:
        normalized = normalize_email(email)
    except ValueError:
        return False
    with _connection() as connection:
        row = connection.execute("SELECT password_hash, email_verified FROM users WHERE email = ?", (normalized,)).fetchone()
    return bool(row and row["email_verified"] and _verify_password(password, row["password_hash"]))


def user_exists(email: str) -> bool:
    try:
        normalized = normalize_email(email)
    except ValueError:
        return False
    with _connection() as connection:
        return connection.execute("SELECT 1 FROM users WHERE email = ?", (normalized,)).fetchone() is not None


def user_is_verified(email: str) -> bool:
    try:
        normalized = normalize_email(email)
    except ValueError:
        return False
    with _connection() as connection:
        row = connection.execute("SELECT email_verified FROM users WHERE email = ?", (normalized,)).fetchone()
    return bool(row and row["email_verified"])


def get_session_version(email: str) -> int | None:
    try:
        normalized = normalize_email(email)
    except ValueError:
        return None
    with _connection() as connection:
        row = connection.execute("SELECT session_version, email_verified FROM users WHERE email = ?", (normalized,)).fetchone()
    if not row or not row["email_verified"]:
        return None
    return int(row["session_version"])


def issue_token(email: str, purpose: str, ttl_seconds: int) -> tuple[str, int]:
    normalized = normalize_email(email)
    if purpose not in {"verify_email", "password_reset"}:
        raise ValueError("Invalid token purpose")
    raw = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    now = int(time.time())
    expires = now + ttl_seconds
    with _connection() as connection:
        connection.execute("UPDATE auth_tokens SET used_at = ? WHERE email = ? AND purpose = ? AND used_at IS NULL", (now, normalized, purpose))
        connection.execute("INSERT INTO auth_tokens(token_hash,email,purpose,expires_at,used_at,created_at) VALUES(?,?,?,?,NULL,?)", (token_hash, normalized, purpose, expires, now))
    return raw, expires


def consume_verification_token(raw_token: str) -> bool:
    if not raw_token or len(raw_token) > 256:
        return False
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    now = int(time.time())
    with _connection() as connection:
        from .db_backend import configured_database_url
        if not configured_database_url():
            connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT email FROM auth_tokens WHERE token_hash=? AND purpose='verify_email' AND used_at IS NULL AND expires_at>?", (token_hash, now)).fetchone()
        if not row:
            return False
        updated = connection.execute("UPDATE auth_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?", (now, token_hash, now)).rowcount
        if updated != 1:
            return False
        connection.execute("UPDATE users SET email_verified=1 WHERE email=?", (row["email"],))
        return True


def consume_password_reset(raw_token: str, new_password: str) -> bool:
    if len(new_password) < 12 or len(new_password) > 256 or not raw_token or len(raw_token) > 256:
        return False
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    now = int(time.time())
    password_hash = _hash_password(new_password)
    with _connection() as connection:
        from .db_backend import configured_database_url
        if not configured_database_url():
            connection.execute("BEGIN IMMEDIATE")
        row = connection.execute("SELECT email FROM auth_tokens WHERE token_hash=? AND purpose='password_reset' AND used_at IS NULL AND expires_at>?", (token_hash, now)).fetchone()
        if not row:
            return False
        updated = connection.execute("UPDATE auth_tokens SET used_at=? WHERE token_hash=? AND used_at IS NULL AND expires_at>?", (now, token_hash, now)).rowcount
        if updated != 1:
            return False
        changed = connection.execute("UPDATE users SET password_hash=?, session_version=session_version+1 WHERE email=?", (password_hash, row["email"])).rowcount
        return changed == 1


def create_token_for_existing_user(email: str, purpose: str, ttl_seconds: int) -> tuple[str, int] | None:
    try:
        normalized = normalize_email(email)
    except ValueError:
        return None
    with _connection() as connection:
        row = connection.execute("SELECT email, email_verified FROM users WHERE email=?", (normalized,)).fetchone()
    if not row:
        return None
    if purpose == "verify_email" and row["email_verified"]:
        return None
    if purpose == "password_reset" and not row["email_verified"]:
        return None
    return issue_token(normalized, purpose, ttl_seconds)
