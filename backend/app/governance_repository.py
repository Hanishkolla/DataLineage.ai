"""M52 persistent tenant-scoped governance policies, scans and findings."""
from __future__ import annotations
import json, uuid
from datetime import datetime, timezone
from .saas_store import db as _db


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _schema(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS governance_policies (
      id TEXT NOT NULL, org_id TEXT NOT NULL, name TEXT NOT NULL, policy_json TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      PRIMARY KEY(org_id,id)
    );
    CREATE INDEX IF NOT EXISTS ix_gov_policy_org ON governance_policies(org_id,enabled);
    CREATE TABLE IF NOT EXISTS governance_scans (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, provider TEXT NOT NULL, risk_score INTEGER NOT NULL,
      risk_level TEXT NOT NULL, finding_count INTEGER NOT NULL, summary_json TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_gov_scan_org_created ON governance_scans(org_id,created_at DESC,id DESC);
    CREATE TABLE IF NOT EXISTS governance_findings (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, scan_id TEXT NOT NULL, code TEXT NOT NULL,
      title TEXT NOT NULL, object_name TEXT NOT NULL, severity TEXT NOT NULL, evidence TEXT NOT NULL,
      remediation TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', owner TEXT,
      due_date TEXT, resolution_note TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      UNIQUE(org_id,scan_id,code,object_name)
    );
    CREATE INDEX IF NOT EXISTS ix_gov_findings_org_status ON governance_findings(org_id,status,severity);
    CREATE INDEX IF NOT EXISTS ix_gov_findings_org_created ON governance_findings(org_id,created_at DESC,id DESC);
    """)


def save_scan(org_id: str, result: dict):
    if not org_id or not isinstance(result, dict):
        raise ValueError("organization and assessment result are required")
    scan_id=str(uuid.uuid4()); now=_now()
    with _db() as c:
        _schema(c)
        c.execute("INSERT INTO governance_scans VALUES(?,?,?,?,?,?,?,?)",(
            scan_id,org_id,str(result.get("provider","unknown")),int(result.get("risk_score",0)),
            str(result.get("risk_level","unknown")),int(result.get("finding_count",0)),
            json.dumps(result.get("summary",{}),separators=(",",":")),now))
        for f in result.get("findings",[]):
            fid=str(uuid.uuid4())
            c.execute("INSERT INTO governance_findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(
                fid,org_id,scan_id,str(f.get("code","UNKNOWN")),str(f.get("title","Finding")),
                str(f.get("object","")),str(f.get("severity","medium")),str(f.get("evidence","")),
                str(f.get("remediation","")),str(f.get("status","open")),None,None,None,now,now))
    return {"scan_id":scan_id,"finding_count":int(result.get("finding_count",0)),"created_at":now}


def list_scans(org_id: str, limit: int=50):
    limit=max(1,min(int(limit),200))
    with _db() as c:
        _schema(c)
        rows=c.execute("SELECT * FROM governance_scans WHERE org_id=? ORDER BY created_at DESC,id DESC LIMIT ?",(org_id,limit)).fetchall()
        out=[]
        for r in rows:
            d=dict(r); d["summary"]=json.loads(d.pop("summary_json") or "{}")
            out.append(d)
        return out


def list_findings(org_id: str, status: str|None=None, severity: str|None=None, limit: int=100):
    limit=max(1,min(int(limit),500)); clauses=["org_id=?"]; args=[org_id]
    if status:
        if status not in {"open","in_progress","resolved","accepted_risk"}: raise ValueError("invalid finding status")
        clauses.append("status=?"); args.append(status)
    if severity:
        if severity not in {"low","medium","high","critical"}: raise ValueError("invalid severity")
        clauses.append("severity=?"); args.append(severity)
    args.append(limit)
    with _db() as c:
        _schema(c)
        rows=c.execute("SELECT * FROM governance_findings WHERE "+" AND ".join(clauses)+" ORDER BY created_at DESC,id DESC LIMIT ?",tuple(args)).fetchall()
        return [dict(r) for r in rows]


def update_finding(org_id: str, finding_id: str, *, status: str|None=None, owner: str|None=None,
                   due_date: str|None=None, resolution_note: str|None=None):
    allowed={"open","in_progress","resolved","accepted_risk"}
    if status is not None and status not in allowed: raise ValueError("invalid finding status")
    if owner is not None and len(owner)>200: raise ValueError("owner is too long")
    if due_date is not None and len(due_date)>30: raise ValueError("due_date is too long")
    if resolution_note is not None and len(resolution_note)>4000: raise ValueError("resolution_note is too long")
    fields=[]; vals=[]
    for key,value in (("status",status),("owner",owner),("due_date",due_date),("resolution_note",resolution_note)):
        if value is not None: fields.append(key+"=?"); vals.append(value)
    if not fields: raise ValueError("at least one finding field must be updated")
    fields.append("updated_at=?"); vals.append(_now()); vals.extend([org_id,finding_id])
    with _db() as c:
        _schema(c)
        cur=c.execute("UPDATE governance_findings SET "+", ".join(fields)+" WHERE org_id=? AND id=?",tuple(vals))
        if cur.rowcount != 1: return None
        row=c.execute("SELECT * FROM governance_findings WHERE org_id=? AND id=?",(org_id,finding_id)).fetchone()
        return dict(row)


def summary(org_id: str):
    with _db() as c:
        _schema(c)
        scans=c.execute("SELECT COUNT(*) AS n FROM governance_scans WHERE org_id=?",(org_id,)).fetchone()["n"]
        findings=c.execute("SELECT status,severity,COUNT(*) AS n FROM governance_findings WHERE org_id=? GROUP BY status,severity",(org_id,)).fetchall()
        by_status={}; by_severity={}
        for r in findings:
            by_status[r["status"]]=by_status.get(r["status"],0)+r["n"]
            by_severity[r["severity"]]=by_severity.get(r["severity"],0)+r["n"]
        return {"scan_count":scans,"finding_count":sum(by_status.values()),"by_status":by_status,"by_severity":by_severity}


def save_policy(org_id: str, policy: dict):
    pid=str(policy.get("id") or "").strip(); name=str(policy.get("name") or "").strip()
    if not pid or len(pid)>100 or not name or len(name)>200: raise ValueError("policy id and name are required")
    encoded=json.dumps(policy,separators=(",",":")); now=_now()
    with _db() as c:
        _schema(c)
        c.execute("INSERT INTO governance_policies(id,org_id,name,policy_json,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(org_id,id) DO UPDATE SET name=excluded.name,policy_json=excluded.policy_json,enabled=excluded.enabled,updated_at=excluded.updated_at",
                  (pid,org_id,name,encoded,1 if policy.get("enabled",True) else 0,now,now))
    return {"id":pid,"name":name,"enabled":bool(policy.get("enabled",True)),"updated_at":now}


def list_policies(org_id: str):
    with _db() as c:
        _schema(c)
        rows=c.execute("SELECT * FROM governance_policies WHERE org_id=? ORDER BY name,id",(org_id,)).fetchall()
        return [{"id":r["id"],"name":r["name"],"policy":json.loads(r["policy_json"]),"enabled":bool(r["enabled"]),"created_at":r["created_at"],"updated_at":r["updated_at"]} for r in rows]
