"""M53 tenant-scoped hash-chained governance audit and approval workflows.

The chain is tamper-evident, not tamper-proof. Export/replicate it to an independently
controlled immutable archive before treating it as regulatory-grade evidence.
"""
from __future__ import annotations
import hashlib, hmac, json, uuid
from datetime import datetime, timezone
from .saas_store import db as _db
from .db_backend import configured_database_url

GENESIS = "0" * 64


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS governance_audit_events (
      event_id TEXT PRIMARY KEY, org_id TEXT NOT NULL, actor TEXT NOT NULL,
      action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL,
      payload_json TEXT NOT NULL, previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_gov_audit_org_created
      ON governance_audit_events(org_id,created_at DESC,event_id DESC);
    CREATE TABLE IF NOT EXISTS governance_approvals (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, resource_type TEXT NOT NULL,
      resource_id TEXT NOT NULL, action TEXT NOT NULL, reason TEXT NOT NULL,
      requested_by TEXT NOT NULL, status TEXT NOT NULL, decided_by TEXT,
      decision_note TEXT, created_at TEXT NOT NULL, decided_at TEXT
    );
    CREATE INDEX IF NOT EXISTS ix_gov_approval_org_status
      ON governance_approvals(org_id,status,created_at DESC,id DESC);
    """)


def append_event(org_id: str, actor: str, action: str, resource_type: str,
                 resource_id: str, payload: dict | None = None):
    if not org_id or not actor or len(actor) > 254:
        raise ValueError("organization and actor are required")
    if not action or len(action) > 100 or not resource_type or len(resource_type) > 100:
        raise ValueError("invalid audit action or resource type")
    if len(str(resource_id)) > 200:
        raise ValueError("resource id is too long")
    payload_json = _canonical(payload or {})
    if len(payload_json) > 12000:
        raise ValueError("audit payload exceeds 12000 characters")
    event_id = str(uuid.uuid4())
    with _db() as c:
        _schema(c)
        if configured_database_url():
            c.execute("SELECT pg_advisory_xact_lock(hashtext(?))", ("m53-audit:" + org_id,))
        else:
            c.execute("BEGIN IMMEDIATE")
        # Timestamp after acquiring the per-tenant serialization lock so chronological
        # verification order matches the actual append order.
        now = _now()
        previous = c.execute(
            "SELECT event_hash FROM governance_audit_events WHERE org_id=? ORDER BY created_at DESC,event_id DESC LIMIT 1",
            (org_id,)).fetchone()
        previous_hash = previous["event_hash"] if previous else GENESIS
        material = {"event_id":event_id,"org_id":org_id,"actor":actor,"action":action,
                    "resource_type":resource_type,"resource_id":str(resource_id),
                    "payload_json":payload_json,"previous_hash":previous_hash,"created_at":now}
        event_hash = hashlib.sha256(_canonical(material).encode("utf-8")).hexdigest()
        c.execute("INSERT INTO governance_audit_events VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (event_id,org_id,actor,action,resource_type,str(resource_id),payload_json,
                   previous_hash,event_hash,now))
    return {"event_id":event_id,"event_hash":event_hash,"created_at":now}


def list_events(org_id: str, limit: int = 100):
    limit = max(1, min(int(limit), 500))
    with _db() as c:
        _schema(c)
        rows = c.execute("SELECT * FROM governance_audit_events WHERE org_id=? ORDER BY created_at DESC,event_id DESC LIMIT ?",
                         (org_id,limit)).fetchall()
        result=[]
        for row in rows:
            item=dict(row); item["payload"] = json.loads(item.pop("payload_json")); result.append(item)
        return result


def verify_chain(org_id: str):
    with _db() as c:
        _schema(c)
        rows=c.execute("SELECT * FROM governance_audit_events WHERE org_id=? ORDER BY created_at ASC,event_id ASC",(org_id,)).fetchall()
    previous=GENESIS
    for index,row in enumerate(rows):
        item=dict(row)
        if item["previous_hash"] != previous:
            return {"valid":False,"events_checked":index,"broken_event_id":item["event_id"],"reason":"previous_hash_mismatch"}
        material={k:item[k] for k in ("event_id","org_id","actor","action","resource_type","resource_id","payload_json","previous_hash","created_at")}
        expected=hashlib.sha256(_canonical(material).encode("utf-8")).hexdigest()
        if not hmac.compare_digest(expected,item["event_hash"]):
            return {"valid":False,"events_checked":index,"broken_event_id":item["event_id"],"reason":"event_hash_mismatch"}
        previous=item["event_hash"]
    return {"valid":True,"events_checked":len(rows),"head_hash":previous}


def request_approval(org_id: str, requested_by: str, resource_type: str,
                     resource_id: str, action: str, reason: str):
    values=[resource_type,resource_id,action,reason]
    if not org_id or not requested_by or any(not str(v or "").strip() for v in values):
        raise ValueError("organization, requester, resource, action and reason are required")
    if any(len(str(v)) > n for v,n in zip(values,(100,200,100,2000))):
        raise ValueError("approval request field exceeds its length limit")
    approval_id=str(uuid.uuid4()); now=_now()
    with _db() as c:
        _schema(c)
        c.execute("INSERT INTO governance_approvals VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                  (approval_id,org_id,resource_type,str(resource_id),action,reason,requested_by,
                   "pending",None,None,now,None))
    append_event(org_id,requested_by,"approval.requested",resource_type,str(resource_id),
                 {"approval_id":approval_id,"action":action,"reason":reason})
    return {"id":approval_id,"status":"pending","created_at":now}


def list_approvals(org_id: str, status: str | None = None, limit: int = 100):
    if status and status not in {"pending","approved","rejected","cancelled"}:
        raise ValueError("invalid approval status")
    limit=max(1,min(int(limit),500))
    with _db() as c:
        _schema(c)
        if status:
            rows=c.execute("SELECT * FROM governance_approvals WHERE org_id=? AND status=? ORDER BY created_at DESC,id DESC LIMIT ?",(org_id,status,limit)).fetchall()
        else:
            rows=c.execute("SELECT * FROM governance_approvals WHERE org_id=? ORDER BY created_at DESC,id DESC LIMIT ?",(org_id,limit)).fetchall()
        return [dict(r) for r in rows]


def decide_approval(org_id: str, approval_id: str, decided_by: str,
                    decision: str, note: str = ""):
    if decision not in {"approved","rejected"}:
        raise ValueError("decision must be approved or rejected")
    if len(note)>2000:
        raise ValueError("decision note is too long")
    now=_now()
    with _db() as c:
        _schema(c)
        row=c.execute("SELECT * FROM governance_approvals WHERE org_id=? AND id=?",(org_id,approval_id)).fetchone()
        if not row: return None
        if row["status"] != "pending": raise ValueError("approval has already been decided")
        if row["requested_by"] == decided_by:
            raise ValueError("requester cannot approve or reject their own request")
        cur=c.execute("UPDATE governance_approvals SET status=?,decided_by=?,decision_note=?,decided_at=? WHERE org_id=? AND id=? AND status='pending'",
                      (decision,decided_by,note,now,org_id,approval_id))
        if cur.rowcount != 1: raise ValueError("approval was concurrently decided")
        updated=c.execute("SELECT * FROM governance_approvals WHERE org_id=? AND id=?",(org_id,approval_id)).fetchone()
        result=dict(updated)
    append_event(org_id,decided_by,"approval."+decision,result["resource_type"],result["resource_id"],
                 {"approval_id":approval_id,"decision_note":note})
    return result
