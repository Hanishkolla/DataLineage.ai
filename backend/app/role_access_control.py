"""Milestone 58: organization-scoped fine-grained RBAC policy foundation.

Policies can only remove permissions from a role's built-in ceiling; tenant
administrators cannot use this API to grant a role more authority than its
platform-defined maximum. This module is not an SSO/SCIM/MFA implementation.
"""
from __future__ import annotations
import json, os, sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db_backend import configured_database_url, connect_postgres

PERMISSIONS = {
    "lineage.read", "lineage.analyze", "lineage.manage",
    "quality.read", "quality.run", "quality.manage",
    "governance.read", "governance.remediate", "governance.manage",
    "connectors.read", "connectors.manage",
    "audit.read", "audit.manage",
    "members.read", "members.manage",
    "billing.read", "billing.manage",
    "security.read", "security.manage",
}
ROLE_CEILINGS = {
    "owner": set(PERMISSIONS),
    "admin": PERMISSIONS - {"security.manage"},
    "developer": {"lineage.read", "lineage.analyze", "quality.read", "quality.run",
                  "governance.read", "governance.remediate", "connectors.read"},
    "analyst": {"lineage.read", "quality.read", "governance.read", "audit.read"},
    "viewer": {"lineage.read", "quality.read", "governance.read"},
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _path() -> Path:
    raw = os.getenv("DATALINEAGE_ACCESS_DB", "").strip()
    return Path(raw).expanduser() if raw else Path(__file__).resolve().parents[1] / "data" / "access_control.sqlite3"


@contextmanager
def _db():
    url = configured_database_url()
    if url:
        conn = connect_postgres(url)
        try:
            _schema(conn)
            conn.commit()
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        path = _path()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(path), timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            _schema(conn)
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _schema(conn) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS access_policies (
        org_id TEXT NOT NULL, role TEXT NOT NULL, permissions_json TEXT NOT NULL,
        updated_by TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY(org_id, role))""")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_access_policy_org ON access_policies(org_id, role)")


def _role(role: str) -> str:
    value = str(role or "").strip().casefold()
    if value not in ROLE_CEILINGS:
        raise ValueError("role must be owner, admin, developer, analyst or viewer")
    return value


def effective_permissions(org_id: str, role: str) -> set[str]:
    role = _role(role)
    with _db() as conn:
        row = conn.execute("SELECT permissions_json FROM access_policies WHERE org_id=? AND role=?",
                           (str(org_id), role)).fetchone()
    if not row:
        return set(ROLE_CEILINGS[role])
    try:
        stored = json.loads(row["permissions_json"])
    except (TypeError, json.JSONDecodeError):
        return set()  # fail closed on corrupted policy data
    if not isinstance(stored, list) or any(not isinstance(x, str) for x in stored):
        return set()
    return set(stored) & ROLE_CEILINGS[role] & PERMISSIONS


def save_role_policy(org_id: str, actor: str, role: str, permissions: Any) -> dict[str, Any]:
    org_id, actor = str(org_id).strip(), str(actor).strip()
    role = _role(role)
    if not org_id or not actor:
        raise ValueError("organization and actor are required")
    if not isinstance(permissions, list) or len(permissions) > len(PERMISSIONS):
        raise ValueError("permissions must be a bounded array")
    if any(not isinstance(item, str) for item in permissions):
        raise ValueError("each permission must be a string")
    requested = set(permissions)
    unknown = requested - PERMISSIONS
    if unknown:
        raise ValueError("unknown permissions: " + ", ".join(sorted(unknown)))
    excess = requested - ROLE_CEILINGS[role]
    if excess:
        raise ValueError("policy cannot grant permissions above the built-in role ceiling: " + ", ".join(sorted(excess)))
    timestamp = _now()
    with _db() as conn:
        conn.execute("""INSERT INTO access_policies(org_id,role,permissions_json,updated_by,updated_at)
            VALUES(?,?,?,?,?) ON CONFLICT(org_id,role) DO UPDATE SET
            permissions_json=excluded.permissions_json, updated_by=excluded.updated_by,
            updated_at=excluded.updated_at""",
            (org_id, role, json.dumps(sorted(requested)), actor[:320], timestamp))
    return {"organization_id": org_id, "role": role, "permissions": sorted(requested),
            "updated_by": actor, "updated_at": timestamp}


def list_role_policies(org_id: str) -> list[dict[str, Any]]:
    with _db() as conn:
        rows = conn.execute("SELECT role,permissions_json,updated_by,updated_at FROM access_policies WHERE org_id=? ORDER BY role",
                            (str(org_id),)).fetchall()
    saved = {row["role"]: row for row in rows}
    result = []
    for role in ("owner", "admin", "developer", "analyst", "viewer"):
        row = saved.get(role)
        result.append({"role": role,
                       "permissions": sorted(effective_permissions(org_id, role)),
                       "is_custom": row is not None,
                       "updated_by": row["updated_by"] if row else None,
                       "updated_at": row["updated_at"] if row else None})
    return result


def access_profile(org_id: str, identity: str, role: str) -> dict[str, Any]:
    role = _role(role)
    return {"organization_id": str(org_id), "identity": str(identity), "role": role,
            "permissions": sorted(effective_permissions(org_id, role))}


def authorize(org_id: str, role: str, permission: str) -> bool:
    if permission not in PERMISSIONS:
        return False
    return permission in effective_permissions(org_id, role)
