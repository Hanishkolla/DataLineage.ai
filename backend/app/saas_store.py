"""Transactional organization, subscription, invitation and usage store.

SQLite remains the default; PostgreSQL is selected with DATALINEAGE_DATABASE_URL.
This module is additive: legacy authentication and analysis stores remain intact.
"""
from __future__ import annotations
import hashlib, hmac, os, secrets, sqlite3, time, uuid
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime, timezone
from .db_backend import configured_database_url, connect_postgres, lock_org

PLANS = {
 'free': {'name':'Free','price_inr':0,'members':1,'projects':2,'analyses':50},
 'starter': {'name':'Starter','price_inr':1999,'members':3,'projects':10,'analyses':500},
 'professional': {'name':'Professional','price_inr':7999,'members':10,'projects':50,'analyses':3000},
 'business': {'name':'Business','price_inr':19999,'members':25,'projects':150,'analyses':10000},
 'enterprise': {'name':'Enterprise','price_inr':None,'members':None,'projects':None,'analyses':None},
}
ROLES={'owner','admin','developer','viewer'}

def _path():
    p=os.getenv('DATALINEAGE_SAAS_DB_PATH','').strip()
    return Path(p).expanduser().resolve() if p else Path(__file__).resolve().parents[1]/'data'/'saas.sqlite3'

@contextmanager
def db():
    database_url = configured_database_url()
    if database_url:
        c = connect_postgres(database_url)
        try:
            _schema(c)
            c.commit()
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()
        return
    p=_path(); p.parent.mkdir(parents=True,exist_ok=True)
    c=sqlite3.connect(p,timeout=20,isolation_level=None); c.row_factory=sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON'); c.execute('PRAGMA busy_timeout=20000')
    try:
        _schema(c); yield c
        if c.in_transaction: c.commit()
    except Exception:
        if c.in_transaction: c.rollback()
        raise
    finally: c.close()

def _schema(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS organizations(id TEXT PRIMARY KEY,name TEXT NOT NULL,slug TEXT NOT NULL UNIQUE,created_by TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS memberships(org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,email TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','admin','developer','viewer')),created_at TEXT NOT NULL,PRIMARY KEY(org_id,email));
    CREATE INDEX IF NOT EXISTS ix_membership_email ON memberships(email);
    CREATE TABLE IF NOT EXISTS invitations(id TEXT PRIMARY KEY,org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,email TEXT NOT NULL,role TEXT NOT NULL,token_hash TEXT NOT NULL UNIQUE,expires_at INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_by TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS ix_invite_pending ON invitations(org_id,email) WHERE status='pending';
    CREATE TABLE IF NOT EXISTS subscriptions(id TEXT PRIMARY KEY,org_id TEXT NOT NULL REFERENCES organizations(id),plan TEXT NOT NULL,status TEXT NOT NULL,period_start TEXT NOT NULL,period_end TEXT NOT NULL,grace_until TEXT,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS usage_events(id TEXT PRIMARY KEY,org_id TEXT NOT NULL REFERENCES organizations(id),metric TEXT NOT NULL,quantity INTEGER NOT NULL,period TEXT NOT NULL,idempotency_key TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(org_id,idempotency_key));
    CREATE INDEX IF NOT EXISTS ix_usage_org_period ON usage_events(org_id,period,metric);
    CREATE TABLE IF NOT EXISTS billing_events(id TEXT PRIMARY KEY,org_id TEXT NOT NULL REFERENCES organizations(id),provider TEXT NOT NULL,event_id TEXT NOT NULL,status TEXT NOT NULL,payload_json TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(provider,event_id));
    CREATE TABLE IF NOT EXISTS audit_events(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,actor TEXT NOT NULL,action TEXT NOT NULL,details TEXT NOT NULL,created_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS github_connections(org_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,provider TEXT NOT NULL,account_name TEXT NOT NULL,credential_ref TEXT,connected_by TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS usage_reservations(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,metric TEXT NOT NULL,quantity INTEGER NOT NULL,period TEXT NOT NULL,idempotency_key TEXT NOT NULL,created_at TEXT NOT NULL,UNIQUE(org_id,idempotency_key));
    CREATE TABLE IF NOT EXISTS trial_activations(org_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,activated_at TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS razorpay_subscriptions(razorpay_subscription_id TEXT PRIMARY KEY,org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,plan TEXT NOT NULL,currency TEXT NOT NULL,amount INTEGER NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS ix_razorpay_subscriptions_org ON razorpay_subscriptions(org_id,created_at);
    ''')

def _now(): return datetime.now(timezone.utc).isoformat(timespec='microseconds')
def _period(): return datetime.now(timezone.utc).strftime('%Y-%m')
def _slug(s):
    import re
    v=re.sub(r'[^a-z0-9]+','-',s.lower()).strip('-')[:48]
    return v or 'workspace'

def create_org(email,name):
    name=' '.join(name.strip().split())
    if not name or len(name)>100: raise ValueError('Organization name must contain 1 to 100 characters')
    oid=str(uuid.uuid4()); slug=_slug(name)+'-'+oid[:8]; now=_now()
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        c.execute('INSERT INTO organizations VALUES(?,?,?,?,?)',(oid,name,slug,email,now))
        c.execute('INSERT INTO memberships VALUES(?,?,?,?)',(oid,email,'owner',now))
        start=datetime.now(timezone.utc); end=start.replace(day=28)
        from calendar import monthrange
        end=start.replace(day=monthrange(start.year,start.month)[1])
        end=end.replace(hour=23,minute=59,second=59,microsecond=0)
        c.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)',(str(uuid.uuid4()),oid,'free','active',start.isoformat(),end.isoformat(),None,now))
        c.execute('INSERT INTO audit_events VALUES(?,?,?,?,?,?)',(str(uuid.uuid4()),oid,email,'organization.created','{}',now))
    return get_org(email,oid)

def memberships(email):
    with db() as c:
        return [dict(r) for r in c.execute('SELECT o.id,o.name,o.slug,m.role FROM organizations o JOIN memberships m ON m.org_id=o.id WHERE m.email=? ORDER BY o.created_at',(email,))]

def get_org(email,oid):
    with db() as c:
        r=c.execute('SELECT o.id,o.name,o.slug,m.role FROM organizations o JOIN memberships m ON m.org_id=o.id WHERE o.id=? AND m.email=?',(oid,email)).fetchone()
    return dict(r) if r else None

def require_role(email,oid,allowed):
    org=get_org(email,oid)
    if not org: raise PermissionError('Organization not found')
    if org['role'] not in allowed: raise PermissionError('Your organization role does not permit this action')
    return org

def rename_org(email,oid,name):
    require_role(email,oid,{'owner','admin'}); name=' '.join(name.strip().split())
    if not name or len(name)>100: raise ValueError('Invalid organization name')
    with db() as c: c.execute('UPDATE organizations SET name=? WHERE id=?',(name,oid))
    return get_org(email,oid)

def members(email,oid):
    require_role(email,oid,{'owner','admin','developer','viewer'})
    with db() as c: return [dict(r) for r in c.execute('SELECT email,role,created_at FROM memberships WHERE org_id=? ORDER BY created_at',(oid,))]

def invite(email,oid,target,role,ttl=604800):
    require_role(email,oid,{'owner','admin'})
    target=target.strip().lower()
    if '@' not in target or len(target)>254: raise ValueError('Enter a valid invitation email')
    if role not in {'admin','developer','viewer'}: raise ValueError('Only Admin, Developer or Viewer can be invited')
    if get_org(target,oid): raise ValueError('User is already a member')
    raw=secrets.token_urlsafe(32); now=_now()
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        lock_org(c, oid)
        if c.execute('SELECT 1 FROM memberships WHERE org_id=? AND email=?',(oid,target)).fetchone():
            raise ValueError('User is already a member')
        plan=c.execute('SELECT plan FROM subscriptions WHERE org_id=? ORDER BY created_at DESC, id DESC LIMIT 1',(oid,)).fetchone()['plan']
        cap=PLANS[plan]['members']; count=c.execute('SELECT COUNT(*) n FROM memberships WHERE org_id=?',(oid,)).fetchone()['n']
        pending=c.execute("SELECT COUNT(*) n FROM invitations WHERE org_id=? AND status='pending' AND expires_at>?",(oid,int(time.time()))).fetchone()['n']
        if cap is not None and count+pending>=cap: raise OverflowError('Member limit reached for the current plan')
        inserted = c.execute(
            'INSERT INTO invitations VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING',
            (str(uuid.uuid4()),oid,target,role,hashlib.sha256(raw.encode()).hexdigest(),int(time.time())+ttl,'pending',email,now)
        ).rowcount
        if inserted != 1:
            raise ValueError('An active invitation already exists for this email')
        c.execute('INSERT INTO audit_events VALUES(?,?,?,?,?,?)',(str(uuid.uuid4()),oid,email,'invitation.created','{}',now))
    return {'status':'pending','email':target,'role':role,'token':raw,'expires_in_seconds':ttl}

def accept_invite(email,raw):
    if not raw or len(raw)>256: raise ValueError('Invalid invitation')
    digest=hashlib.sha256(raw.encode()).hexdigest(); now=int(time.time())
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        r=c.execute("SELECT * FROM invitations WHERE token_hash=? AND status='pending' AND expires_at>?",(digest,now)).fetchone()
        if not r or r['email'].lower()!=email.lower(): raise PermissionError('Invitation is invalid, expired or addressed to another account')
        lock_org(c, r['org_id'])
        r=c.execute("SELECT * FROM invitations WHERE token_hash=? AND status='pending' AND expires_at>?",(digest,now)).fetchone()
        if not r or r['email'].lower()!=email.lower(): raise PermissionError('Invitation is invalid, expired or addressed to another account')
        already=c.execute('SELECT 1 FROM memberships WHERE org_id=? AND email=?',(r['org_id'],email)).fetchone()
        if already: raise ValueError('User is already a member')
        sub=c.execute('SELECT plan FROM subscriptions WHERE org_id=? ORDER BY created_at DESC, id DESC LIMIT 1',(r['org_id'],)).fetchone()
        cap=PLANS[sub['plan']]['members'] if sub else 1
        count=c.execute('SELECT COUNT(*) n FROM memberships WHERE org_id=?',(r['org_id'],)).fetchone()['n']
        if cap is not None and count>=cap: raise OverflowError('Member limit reached for the current plan')
        c.execute('INSERT INTO memberships VALUES(?,?,?,?)',(r['org_id'],email,r['role'],_now()))
        c.execute("UPDATE invitations SET status='accepted' WHERE id=?",(r['id'],))
    return get_org(email,r['org_id'])

def revoke_invite(email,oid,iid):
    require_role(email,oid,{'owner','admin'})
    with db() as c: return c.execute("UPDATE invitations SET status='revoked' WHERE id=? AND org_id=? AND status='pending'",(iid,oid)).rowcount==1

def summary(email,oid):
    require_role(email,oid,{'owner','admin','developer','viewer'})
    with db() as c:
        sub=c.execute('SELECT * FROM subscriptions WHERE org_id=? ORDER BY created_at DESC, id DESC LIMIT 1',(oid,)).fetchone()
        counts={r['metric']:r['n'] for r in c.execute('SELECT metric,SUM(quantity) n FROM usage_events WHERE org_id=? AND period=? GROUP BY metric',(oid,_period()))}
        members_n=c.execute('SELECT COUNT(*) n FROM memberships WHERE org_id=?',(oid,)).fetchone()['n']
    from .run_store import list_projects
    project_n=len(list_projects(oid))
    plan=PLANS[sub['plan']]
    limits={'members':plan['members'],'projects':plan['projects'],'analyses':plan['analyses']}
    warnings=[]
    if limits['analyses'] and counts.get('analyses',0)>=limits['analyses']*0.8: warnings.append('Monthly analysis usage has reached at least 80% of the plan limit')
    if limits['members'] and members_n>=limits['members']*0.8: warnings.append('Organization membership is approaching the plan limit')
    if limits['projects'] and project_n>=limits['projects']*0.8: warnings.append('Project count is approaching the plan limit')
    return {'plan':dict(plan, id=sub['plan']),'subscription':dict(sub),'period':_period(),'usage':counts,'members':members_n,'projects':project_n,'limits':limits,'warnings':warnings}

def record_usage(email,oid,metric,quantity=1,idempotency_key=None):
    require_role(email,oid,{'owner','admin','developer'})
    if metric not in {'analyses','sql_files','pr_analyses','github_calls','report_downloads'} or not isinstance(quantity,int) or quantity<1: raise ValueError('Invalid usage event')
    key=idempotency_key or str(uuid.uuid4()); period=_period()
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        lock_org(c, oid)
        sub=c.execute('SELECT plan,status FROM subscriptions WHERE org_id=? ORDER BY created_at DESC, id DESC LIMIT 1',(oid,)).fetchone()
        if sub['status'] not in {'active','trial'}: raise PermissionError('Subscription is not active')
        limit=PLANS[sub['plan']]['analyses'] if metric=='analyses' else None
        duplicate=c.execute('SELECT 1 FROM usage_events WHERE org_id=? AND idempotency_key=?',(oid,key)).fetchone()
        current=c.execute('SELECT COALESCE(SUM(quantity),0) n FROM usage_events WHERE org_id=? AND metric=? AND period=?',(oid,metric,period)).fetchone()['n']
        pending=0
        if metric == 'analyses':
            pending=c.execute('SELECT COALESCE(SUM(quantity),0) n FROM usage_reservations WHERE org_id=? AND metric=? AND period=?',(oid,metric,period)).fetchone()['n']
        if duplicate: return {'recorded':False,'metric':metric,'used':current,'limit':limit,'period':period}
        if limit is not None and current+pending+quantity>limit: raise OverflowError('Monthly analysis limit reached for the current plan')
        inserted = c.execute(
            'INSERT INTO usage_events VALUES(?,?,?,?,?,?,?) ON CONFLICT(org_id,idempotency_key) DO NOTHING',
            (str(uuid.uuid4()),oid,metric,quantity,period,key,_now())
        ).rowcount == 1
        return {'recorded':inserted,'metric':metric,'used':current+(quantity if inserted else 0),'limit':limit,'period':period}

def change_plan(email,oid,plan):
    require_role(email,oid,{'owner'})
    if plan not in PLANS: raise ValueError('Unknown plan')
    now=datetime.now(timezone.utc); end=now.replace(day=28)
    from calendar import monthrange
    end=now.replace(day=monthrange(now.year,now.month)[1],hour=23,minute=59,second=59,microsecond=0)
    with db() as c:
        c.execute('BEGIN IMMEDIATE')
        lock_org(c, oid)
        c.execute('INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)',(str(uuid.uuid4()),oid,plan,'active',now.isoformat(),end.isoformat(),None,_now()))
        c.execute('INSERT INTO audit_events VALUES(?,?,?,?,?,?)',(str(uuid.uuid4()),oid,email,'subscription.plan_changed','{"plan":"'+plan+'"}',_now()))
    return summary(email,oid)

def billing_events(email,oid):
    require_role(email,oid,{'owner'})
    with db() as c: return [dict(r) for r in c.execute('SELECT provider,event_id,status,created_at FROM billing_events WHERE org_id=? ORDER BY created_at DESC',(oid,))]

def process_mock_event(email,oid,provider,event_id,status,payload_json='{}'):
    require_role(email,oid,{'owner'})
    if provider not in {'razorpay','stripe','mock'}: raise ValueError('Unsupported billing provider')
    with db() as c:
        inserted = c.execute(
            'INSERT INTO billing_events VALUES(?,?,?,?,?,?,?) ON CONFLICT(provider,event_id) DO NOTHING',
            (str(uuid.uuid4()),oid,provider,event_id,status,payload_json,_now())
        ).rowcount
        if inserted != 1:
            return {'processed':False,'reason':'duplicate'}
    return {'processed':True,'status':status}

def verify_webhook_signature(secret,body,signature):
    if not secret or not signature: return False
    expected=hmac.new(secret.encode(),body,hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,signature)


def ensure_personal_org(email: str) -> dict:
    """Return the user's only workspace or create a personal workspace for legacy accounts."""
    current = memberships(email)
    if current:
        if len(current) > 1:
            return {"requires_selection": True, "organizations": current}
        return current[0]
    return create_org(email, "Personal workspace")

def set_member_role(actor: str, oid: str, target: str, role: str) -> bool:
    require_role(actor, oid, {"owner"})
    target = target.strip().lower()
    if role not in {"admin", "developer", "viewer"}:
        raise ValueError("Only Admin, Developer or Viewer roles can be assigned")
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT role FROM memberships WHERE org_id=? AND email=?", (oid, target)).fetchone()
        if not row:
            raise ValueError("Organization member not found")
        if row["role"] == "owner":
            raise PermissionError("The owner role cannot be changed through member role management")
        c.execute("UPDATE memberships SET role=? WHERE org_id=? AND email=?", (role, oid, target))
        c.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?)", (str(uuid.uuid4()), oid, actor, "member.role_changed", "{}", _now()))
    return True

def remove_member(actor: str, oid: str, target: str) -> bool:
    require_role(actor, oid, {"owner"})
    target = target.strip().lower()
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT role FROM memberships WHERE org_id=? AND email=?", (oid, target)).fetchone()
        if not row:
            return False
        if row["role"] == "owner":
            owners = c.execute("SELECT COUNT(*) n FROM memberships WHERE org_id=? AND role='owner'", (oid,)).fetchone()["n"]
            if owners <= 1:
                raise PermissionError("The last organization owner cannot be removed")
        c.execute("DELETE FROM memberships WHERE org_id=? AND email=?", (oid, target))
        c.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?)", (str(uuid.uuid4()), oid, actor, "member.removed", "{}", _now()))
    return True

def pending_invitations(email: str, oid: str) -> list[dict]:
    require_role(email, oid, {"owner", "admin"})
    with db() as c:
        rows = c.execute("SELECT id,email,role,expires_at,status,created_at FROM invitations WHERE org_id=? AND status='pending' ORDER BY created_at DESC, id DESC", (oid,)).fetchall()
    return [dict(row) for row in rows]

def change_subscription_status(email: str, oid: str, status: str, grace_until: str | None = None) -> dict:
    require_role(email, oid, {"owner"})
    transitions = {
        "trial": {"active", "past_due", "cancelled", "expired", "suspended"},
        "active": {"past_due", "cancelled", "suspended"},
        "past_due": {"active", "cancelled", "expired", "suspended"},
        "cancelled": {"active", "expired"},
        "expired": {"active"},
        "suspended": {"active", "cancelled"},
    }
    if status not in transitions:
        raise ValueError("Invalid subscription status")
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT id,status FROM subscriptions WHERE org_id=? ORDER BY created_at DESC, id DESC LIMIT 1", (oid,)).fetchone()
        if not row:
            raise ValueError("Subscription not found")
        if status != row["status"] and status not in transitions[row["status"]]:
            raise ValueError("Unsupported subscription status transition")
        c.execute("UPDATE subscriptions SET status=?,grace_until=? WHERE id=?", (status, grace_until, row["id"]))
        c.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?)", (str(uuid.uuid4()), oid, email, "subscription.status_changed", "{}", _now()))
    return summary(email, oid)

def save_github_connection(email: str, oid: str, account_name: str, access_token: str) -> dict:
    require_role(email, oid, {"owner", "admin"})
    account_name = account_name.strip()
    if not account_name or len(account_name) > 100:
        raise ValueError("Invalid GitHub account name")
    if not isinstance(access_token, str) or len(access_token) < 20 or len(access_token) > 500:
        raise ValueError("A valid GitHub access token is required")
    encrypted = _encrypt_github_token(access_token)
    now = _now()
    with db() as c:
        c.execute("INSERT INTO github_connections(org_id,provider,account_name,credential_ref,connected_by,created_at,updated_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(org_id) DO UPDATE SET account_name=excluded.account_name,credential_ref=excluded.credential_ref,connected_by=excluded.connected_by,updated_at=excluded.updated_at", (oid, "github", account_name, encrypted, email, now, now))
        c.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?)", (str(uuid.uuid4()), oid, email, "github.connection_updated", "{}", now))
    return {"connected": True, "provider": "github", "account_name": account_name}

def get_github_connection(email: str, oid: str) -> dict | None:
    require_role(email, oid, {"owner", "admin", "developer", "viewer"})
    with db() as c:
        row = c.execute("SELECT provider,account_name,connected_by,created_at,updated_at FROM github_connections WHERE org_id=?", (oid,)).fetchone()
    return dict(row) if row else None


def _encrypt_github_token(token: str) -> str:
    key = os.getenv("DATALINEAGE_GITHUB_CREDENTIAL_KEY", "").strip()
    if not key:
        raise ValueError("Organization GitHub credential encryption is not configured")
    try:
        from cryptography.fernet import Fernet
        return Fernet(key.encode("ascii")).encrypt(token.encode("utf-8")).decode("ascii")
    except Exception as exc:
        raise ValueError("GitHub credential encryption key is invalid") from exc

def get_github_token(email: str, oid: str) -> str | None:
    require_role(email, oid, {"owner", "admin", "developer", "viewer"})
    with db() as c:
        row = c.execute("SELECT credential_ref FROM github_connections WHERE org_id=?", (oid,)).fetchone()
    if not row or not row["credential_ref"]:
        return None
    key = os.getenv("DATALINEAGE_GITHUB_CREDENTIAL_KEY", "").strip()
    if not key:
        raise ValueError("Organization GitHub credential encryption is not configured")
    try:
        from cryptography.fernet import Fernet
        return Fernet(key.encode("ascii")).decrypt(row["credential_ref"].encode("ascii")).decode("utf-8")
    except Exception as exc:
        raise ValueError("Stored GitHub credential cannot be decrypted") from exc


def reserve_analysis(email: str, oid: str, quantity: int, idempotency_key: str) -> str:
    require_role(email, oid, {"owner", "admin", "developer"})
    if not isinstance(quantity, int) or quantity < 1 or not idempotency_key or len(idempotency_key) > 200:
        raise ValueError("Invalid analysis reservation")
    period = _period(); reservation_id = str(uuid.uuid4())
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        lock_org(c, oid)
        sub = c.execute("SELECT plan,status FROM subscriptions WHERE org_id=? ORDER BY created_at DESC, id DESC LIMIT 1", (oid,)).fetchone()
        if not sub or sub["status"] not in {"active", "trial"}:
            raise PermissionError("Subscription is not active")
        if c.execute("SELECT 1 FROM usage_events WHERE org_id=? AND idempotency_key=?", (oid, idempotency_key)).fetchone():
            return "duplicate"
        if c.execute("SELECT 1 FROM usage_reservations WHERE org_id=? AND idempotency_key=?", (oid, idempotency_key)).fetchone():
            return "duplicate"
        limit = PLANS[sub["plan"]]["analyses"]
        used = c.execute("SELECT COALESCE(SUM(quantity),0) n FROM usage_events WHERE org_id=? AND metric='analyses' AND period=?", (oid, period)).fetchone()["n"]
        pending = c.execute("SELECT COALESCE(SUM(quantity),0) n FROM usage_reservations WHERE org_id=? AND metric='analyses' AND period=?", (oid, period)).fetchone()["n"]
        if limit is not None and used + pending + quantity > limit:
            raise OverflowError("Monthly analysis limit reached for the current plan")
        c.execute("INSERT INTO usage_reservations VALUES(?,?,?,?,?,?,?)", (reservation_id, oid, "analyses", quantity, period, idempotency_key, _now()))
    return reservation_id

def complete_analysis_reservation(reservation_id: str, file_quantity: int = 0) -> None:
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT * FROM usage_reservations WHERE id=?", (reservation_id,)).fetchone()
        if row:
            lock_org(c, row["org_id"])
            row = c.execute("SELECT * FROM usage_reservations WHERE id=?", (reservation_id,)).fetchone()
        if not row:
            return
        c.execute("INSERT INTO usage_events VALUES(?,?,?,?,?,?,?) ON CONFLICT(org_id,idempotency_key) DO NOTHING", (str(uuid.uuid4()), row["org_id"], "analyses", row["quantity"], row["period"], row["idempotency_key"], _now()))
        if file_quantity > 0:
            c.execute("INSERT INTO usage_events VALUES(?,?,?,?,?,?,?) ON CONFLICT(org_id,idempotency_key) DO NOTHING", (str(uuid.uuid4()), row["org_id"], "sql_files", file_quantity, row["period"], row["idempotency_key"] + ":files", _now()))
        c.execute("DELETE FROM usage_reservations WHERE id=?", (reservation_id,))

def release_analysis_reservation(reservation_id: str) -> None:
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        row = c.execute("SELECT org_id FROM usage_reservations WHERE id=?", (reservation_id,)).fetchone()
        if row:
            lock_org(c, row["org_id"])
            c.execute("DELETE FROM usage_reservations WHERE id=?", (reservation_id,))


def subscription_history(email: str, oid: str) -> list[dict]:
    require_role(email, oid, {"owner"})
    with db() as c:
        rows = c.execute("SELECT id,plan,status,period_start,period_end,grace_until,created_at FROM subscriptions WHERE org_id=? ORDER BY created_at DESC, id DESC", (oid,)).fetchall()
    return [dict(row) for row in rows]


def usage_history(email: str, oid: str) -> list[dict]:
    require_role(email, oid, {"owner", "admin", "developer", "viewer"})
    with db() as c:
        rows = c.execute("SELECT period,metric,SUM(quantity) quantity FROM usage_events WHERE org_id=? GROUP BY period,metric ORDER BY period DESC,metric", (oid,)).fetchall()
    return [dict(row) for row in rows]


def start_trial(email: str, oid: str, plan: str = "starter", days: int = 14) -> dict:
    require_role(email, oid, {"owner"})
    if plan not in PLANS or plan in {"free", "enterprise"} or not isinstance(days, int) or days < 1 or days > 30:
        raise ValueError("Trial plan or duration is invalid")
    now = datetime.now(timezone.utc)
    end = now + __import__("datetime").timedelta(days=days)
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        lock_org(c, oid)
        if c.execute("SELECT 1 FROM trial_activations WHERE org_id=?", (oid,)).fetchone():
            raise ValueError("This organization has already used its trial")
        c.execute("INSERT INTO trial_activations VALUES(?,?)", (oid, now.isoformat()))
        c.execute("INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)", (str(uuid.uuid4()), oid, plan, "trial", now.isoformat(), end.isoformat(), None, _now()))
        c.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?)", (str(uuid.uuid4()), oid, email, "subscription.trial_started", "{}", _now()))
    return summary(email, oid)


def save_razorpay_subscription(email: str, oid: str, data: dict) -> dict:
    require_role(email, oid, {"owner"})
    now = _now()
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        lock_org(c, oid)
        c.execute("INSERT INTO razorpay_subscriptions VALUES(?,?,?,?,?,?,?,?)", (data["subscription_id"], oid, data["plan"], data["currency"], int(data["amount"]), data.get("status", "created"), now, now))
        c.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?)", (str(uuid.uuid4()), oid, email, "billing.checkout_created", "{}", now))
    return {"saved": True, "subscription_id": data["subscription_id"]}


def apply_razorpay_webhook(event_id: str, event_type: str, payload_json: str, subscription_id: str, provider_status: str, period_start: str | None = None, period_end: str | None = None) -> dict:
    """Idempotently record a verified webhook and update only its mapped tenant."""
    import json
    now = _now()
    with db() as c:
        c.execute("BEGIN IMMEDIATE")
        mapping = c.execute("SELECT * FROM razorpay_subscriptions WHERE razorpay_subscription_id=?", (subscription_id,)).fetchone()
        if not mapping:
            raise ValueError("Razorpay subscription is not mapped to a DataLineage AI organization")
        lock_org(c, mapping["org_id"])
        inserted = c.execute(
            "INSERT INTO billing_events VALUES(?,?,?,?,?,?,?) ON CONFLICT(provider,event_id) DO NOTHING",
            (str(uuid.uuid4()), mapping["org_id"], "razorpay", event_id, event_type, payload_json[:20000], now),
        ).rowcount
        if inserted != 1:
            return {"processed": False, "reason": "duplicate"}
        c.execute("UPDATE razorpay_subscriptions SET status=?,updated_at=? WHERE razorpay_subscription_id=?", (provider_status, now, subscription_id))
        if event_type in {"subscription.activated", "subscription.charged"} and provider_status in {"active", "authenticated"}:
            start = period_start or datetime.now(timezone.utc).isoformat()
            if period_end is None:
                from datetime import timedelta
                period_end = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
            c.execute("INSERT INTO subscriptions VALUES(?,?,?,?,?,?,?,?)", (str(uuid.uuid4()), mapping["org_id"], mapping["plan"], "active", start, period_end, None, now))
        elif event_type in {"subscription.halted", "subscription.cancelled", "subscription.completed"}:
            target = "past_due" if event_type == "subscription.halted" else ("cancelled" if event_type == "subscription.cancelled" else "expired")
            latest = c.execute("SELECT id FROM subscriptions WHERE org_id=? ORDER BY created_at DESC, id DESC LIMIT 1", (mapping["org_id"],)).fetchone()
            if latest:
                c.execute("UPDATE subscriptions SET status=? WHERE id=?", (target, latest["id"]))
        c.execute("INSERT INTO audit_events VALUES(?,?,?,?,?,?)", (str(uuid.uuid4()), mapping["org_id"], "razorpay-webhook", "billing." + event_type, json.dumps({"subscription_id": subscription_id}), now))
    return {"processed": True, "status": provider_status}
