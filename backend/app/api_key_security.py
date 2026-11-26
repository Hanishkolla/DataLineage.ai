"""Milestone 41 security foundations: scoped API keys and append-only audit trail.

This module provides application-level primitives. It does not certify compliance,
implement SAML/OIDC, or replace infrastructure KMS/HSM, TLS, or identity controls.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db_backend import configured_database_url, connect_postgres

KEY_PREFIX = "dla_live_"
MAX_AUDIT_PAGE = 500
VALID_ROLES = {"owner", "admin", "developer", "analyst", "viewer"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _db_path() -> Path:
    raw = os.environ.get("DATALINEAGE_SECURITY_DB", "")
    return Path(raw).expanduser() if raw else Path(__file__).resolve().parents[1] / "data" / "security.sqlite3"


def _connect():
    """Open shared PostgreSQL when configured; otherwise use SQLite."""
    database_url = configured_database_url()
    if database_url:
        conn = connect_postgres(database_url)
        try:
            conn.execute("""CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY, tenant_key TEXT NOT NULL,
                owner_identity TEXT NOT NULL, label TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE, role TEXT NOT NULL,
                created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT)""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_key, created_at DESC)")
            conn.execute("""CREATE TABLE IF NOT EXISTS security_audit (
                sequence BIGSERIAL PRIMARY KEY, event_id TEXT NOT NULL UNIQUE,
                tenant_key TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
                resource_type TEXT NOT NULL, resource_id TEXT, outcome TEXT NOT NULL,
                occurred_at TEXT NOT NULL, details_json TEXT NOT NULL)""")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_security_audit_tenant_seq ON security_audit(tenant_key, sequence DESC)")
            conn.commit()
            return conn
        except Exception:
            conn.rollback()
            conn.close()
            raise

    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("""CREATE TABLE IF NOT EXISTS api_keys (
        key_id TEXT PRIMARY KEY, tenant_key TEXT NOT NULL, owner_identity TEXT NOT NULL,
        label TEXT NOT NULL, key_hash TEXT NOT NULL UNIQUE, role TEXT NOT NULL,
        created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_tenant ON api_keys(tenant_key, created_at DESC)")
    conn.execute("""CREATE TABLE IF NOT EXISTS security_audit (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
        tenant_key TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
        resource_type TEXT NOT NULL, resource_id TEXT, outcome TEXT NOT NULL,
        occurred_at TEXT NOT NULL, details_json TEXT NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_security_audit_tenant_seq ON security_audit(tenant_key, sequence DESC)")
    return conn


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def record_audit(tenant_key: str, actor: str, action: str, resource_type: str,
                 resource_id: str | None = None, outcome: str = "success",
                 details: dict[str, Any] | None = None) -> dict[str, Any]:
    tenant, actor, action = str(tenant_key).strip(), str(actor).strip(), str(action).strip()
    if not tenant or not actor or not action:
        raise ValueError("tenant_key, actor and action are required")
    details = details or {}
    if not isinstance(details, dict):
        raise ValueError("details must be an object")
    # Never accept likely credential fields into audit details.
    safe_details = {str(k)[:80]: v for k, v in details.items()
                    if str(k).casefold() not in {"key", "api_key", "token", "secret", "password", "authorization"}}
    event_id = secrets.token_hex(16)
    with _connect() as conn:
        values = (event_id, tenant, actor[:320], action[:120], str(resource_type)[:100],
                  str(resource_id)[:200] if resource_id else None, outcome[:40], _now(),
                  json.dumps(safe_details, ensure_ascii=False, separators=(",", ":")))
        statement = "INSERT INTO security_audit(event_id,tenant_key,actor,action,resource_type,resource_id,outcome,occurred_at,details_json) VALUES(?,?,?,?,?,?,?,?,?)"
        if configured_database_url():
            sequence = conn.execute(statement + " RETURNING sequence", values).fetchone()["sequence"]
        else:
            sequence = conn.execute(statement, values).lastrowid
    return {"event_id": event_id, "sequence": sequence, "recorded": True}


def create_api_key(tenant_key: str, owner_identity: str, label: str,
                   role: str = "viewer", expires_at: str | None = None) -> dict[str, Any]:
    tenant, owner, label = str(tenant_key).strip(), str(owner_identity).strip(), str(label).strip()
    role = str(role).strip().casefold()
    if not tenant or not owner or not label:
        raise ValueError("tenant_key, owner_identity and label are required")
    if role not in {"developer", "analyst", "viewer"}:
        raise ValueError("API keys may only be assigned developer, analyst or viewer roles")
    if len(label) > 100:
        raise ValueError("label must be at most 100 characters")
    if expires_at:
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("expires_at must be an ISO-8601 timestamp") from exc
        if expiry.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        if expiry <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be in the future")
    key_id = secrets.token_hex(12)
    raw_key = KEY_PREFIX + secrets.token_urlsafe(32)
    with _connect() as conn:
        conn.execute("INSERT INTO api_keys VALUES(?,?,?,?,?,?,?,?,?)",
                     (key_id, tenant, owner, label, _hash_key(raw_key), role, _now(), expires_at, None))
    return {"key_id": key_id, "api_key": raw_key, "label": label, "role": role,
            "created_at": _now(), "expires_at": expires_at,
            "warning": "The API key is shown once. Store it in a secrets manager; it cannot be retrieved later."}


def verify_api_key(raw_key: str, tenant_key: str | None = None) -> dict[str, Any] | None:
    raw_key = str(raw_key or "").strip()
    if not raw_key.startswith(KEY_PREFIX) or len(raw_key) > 300:
        return None
    with _connect() as conn:
        row = conn.execute("SELECT * FROM api_keys WHERE key_hash=?", (_hash_key(raw_key),)).fetchone()
    if not row or row["revoked_at"]:
        return None
    if tenant_key and not hmac.compare_digest(row["tenant_key"], str(tenant_key)):
        return None
    if row["expires_at"]:
        try:
            expiry = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
            if expiry <= datetime.now(timezone.utc):
                return None
        except ValueError:
            return None
    return {"key_id": row["key_id"], "tenant_key": row["tenant_key"],
            "owner_identity": row["owner_identity"], "label": row["label"], "role": row["role"]}


def revoke_api_key(tenant_key: str, key_id: str) -> bool:
    with _connect() as conn:
        cur = conn.execute("UPDATE api_keys SET revoked_at=? WHERE tenant_key=? AND key_id=? AND revoked_at IS NULL",
                           (_now(), str(tenant_key), str(key_id)))
        return cur.rowcount == 1


def list_api_keys(tenant_key: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT key_id,label,role,created_at,expires_at,revoked_at FROM api_keys WHERE tenant_key=? ORDER BY created_at DESC",
                            (str(tenant_key),)).fetchall()
    return [dict(row) for row in rows]


def list_audit(tenant_key: str, limit: int = 100, before_sequence: int | None = None) -> list[dict[str, Any]]:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_AUDIT_PAGE:
        raise ValueError(f"limit must be between 1 and {MAX_AUDIT_PAGE}")
    sql = "SELECT * FROM security_audit WHERE tenant_key=?"
    params: list[Any] = [str(tenant_key)]
    if before_sequence is not None:
        if not isinstance(before_sequence, int) or isinstance(before_sequence, bool) or before_sequence < 1:
            raise ValueError("before_sequence must be a positive integer")
        sql += " AND sequence < ?"
        params.append(before_sequence)
    sql += " ORDER BY sequence DESC LIMIT ?"
    params.append(limit)
    with _connect() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [{"sequence": r["sequence"], "event_id": r["event_id"], "tenant_key": r["tenant_key"],
             "actor": r["actor"], "action": r["action"], "resource_type": r["resource_type"],
             "resource_id": r["resource_id"], "outcome": r["outcome"], "occurred_at": r["occurred_at"],
             "details": json.loads(r["details_json"])} for r in rows]


def security_posture(config: dict[str, Any] | None = None) -> dict[str, Any]:
    config = config or {}
    checks = [
        {"control": "authentication_enabled", "status": "configured" if config.get("auth_enabled") else "not_configured",
         "note": "Application session authentication must be enabled in deployment."},
        {"control": "secure_cookies", "status": "configured" if config.get("secure_cookie") else "not_configured",
         "note": "Use HTTPS and secure, HttpOnly, SameSite cookies."},
        {"control": "secret_manager", "status": "configured" if config.get("secret_manager") else "not_configured",
         "note": "Store production secrets in a managed vault; do not commit .env files."},
        {"control": "tls_enforcement", "status": "configured" if config.get("tls_enforced") else "not_verified",
         "note": "Enforce TLS at the ingress/load balancer and verify internal service transport."},
        {"control": "sso_oidc_saml", "status": "not_implemented",
         "note": "Requires enterprise identity-provider integration and security review."},
        {"control": "mfa", "status": "not_implemented",
         "note": "Requires MFA enrollment, recovery, enforcement and testing."},
        {"control": "encryption_at_rest_kms", "status": "not_verified",
         "note": "Use managed disk/database encryption and KMS/HSM key rotation."},
        {"control": "immutable_external_audit_archive", "status": "not_implemented",
         "note": "Export audit events to write-once storage or a SIEM with retention controls."},
    ]
    return {"checks": checks, "configured_count": sum(c["status"] == "configured" for c in checks),
            "total_checks": len(checks), "overall_status": "assessment_only",
            "compliance_claim": False,
            "note": "This is a configuration checklist, not a SOC 2 or ISO 27001 certification or audit opinion."}
