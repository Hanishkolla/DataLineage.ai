"""Milestone 31: reusable RBAC policy and privacy-conscious audit events."""
from __future__ import annotations
import json, os, sqlite3, time
from pathlib import Path
from typing import Any

ROLE_PERMISSIONS = {
    "owner": {"project:read","project:write","project:delete","member:manage","billing:manage","audit:read","integration:manage"},
    "admin": {"project:read","project:write","member:manage","audit:read","integration:manage"},
    "developer": {"project:read","project:write","integration:read"},
    "viewer": {"project:read"},
}
SENSITIVE_KEYS = {"password","token","secret","authorization","cookie","api_key","sql","query","connection_string"}

def permissions_for_role(role: str) -> set[str]:
    return set(ROLE_PERMISSIONS.get(str(role or "").lower(), set()))

def role_allows(role: str, permission: str) -> bool:
    return permission in permissions_for_role(role)

def require_permission(role: str, permission: str) -> None:
    if not role_allows(role, permission):
        raise PermissionError("Insufficient role permissions")

def _redact(value: Any, depth: int = 0) -> Any:
    if depth > 5: return "[truncated]"
    if isinstance(value, dict):
        return {str(k)[:80]: ("[REDACTED]" if str(k).lower() in SENSITIVE_KEYS or any(x in str(k).lower() for x in ("password","token","secret","credential")) else _redact(v, depth+1)) for k,v in list(value.items())[:100]}
    if isinstance(value, list): return [_redact(v,depth+1) for v in value[:100]]
    if isinstance(value, str): return value[:1000]
    if value is None or isinstance(value,(bool,int,float)): return value
    return str(value)[:300]

def _db_path() -> str:
    configured=os.getenv("DATALINEAGE_AUDIT_DB","").strip()
    return configured or str(Path(__file__).resolve().parents[1] / "data" / "audit.sqlite3")

def record_audit_event(actor: str, action: str, resource_type: str, resource_id: str = "", details: dict[str,Any] | None = None, db_path: str | None = None) -> int:
    path=db_path or _db_path()
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    payload=json.dumps(_redact(details or {}),separators=(",",":"),ensure_ascii=True)
    with sqlite3.connect(path,timeout=10) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, occurred_at REAL NOT NULL,
            actor TEXT NOT NULL, action TEXT NOT NULL, resource_type TEXT NOT NULL,
            resource_id TEXT NOT NULL, details_json TEXT NOT NULL)""")
        cur=conn.execute("INSERT INTO audit_events(occurred_at,actor,action,resource_type,resource_id,details_json) VALUES(?,?,?,?,?,?)",
            (time.time(),str(actor)[:255],str(action)[:120],str(resource_type)[:120],str(resource_id)[:255],payload))
        return int(cur.lastrowid)

def list_audit_events(limit: int = 100, db_path: str | None = None) -> list[dict[str,Any]]:
    if not isinstance(limit,int) or limit < 1 or limit > 500: raise ValueError("limit must be between 1 and 500")
    path=db_path or _db_path()
    if not Path(path).exists(): return []
    with sqlite3.connect(path,timeout=10) as conn:
        conn.row_factory=sqlite3.Row
        rows=conn.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [{"id":r["id"],"occurred_at":r["occurred_at"],"actor":r["actor"],"action":r["action"],"resource_type":r["resource_type"],"resource_id":r["resource_id"],"details":json.loads(r["details_json"])} for r in rows]
