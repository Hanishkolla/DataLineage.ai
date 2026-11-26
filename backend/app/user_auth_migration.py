"""M45 migration of SQLite users/auth tokens to PostgreSQL."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Any
from .db_backend import connect_postgres
USER_COLUMNS=("email","password_hash","created_at","email_verified","session_version")
TOKEN_COLUMNS=("token_hash","email","purpose","expires_at","used_at","created_at")
def _exists(conn, table):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() is not None
def _source(path):
    p=Path(path).expanduser().resolve()
    if not p.is_file(): raise FileNotFoundError(f"SQLite users database not found: {p}")
    c=sqlite3.connect(str(p),timeout=15); c.row_factory=sqlite3.Row
    integrity=c.execute("PRAGMA integrity_check").fetchone()[0]
    if integrity!="ok": c.close(); raise RuntimeError(f"SQLite integrity_check failed: {integrity}")
    if not _exists(c,"users"): c.close(); raise RuntimeError("SQLite source has no users table")
    return c
def _select_rows(conn,table,columns):
    present={r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    defaults={"email_verified":"1","session_version":"0"}
    expr=[]
    for col in columns:
        if col in present: expr.append(col)
        elif col in defaults: expr.append(f"{defaults[col]} AS {col}")
        else: raise RuntimeError(f"SQLite {table} is missing required column: {col}")
    return conn.execute(f"SELECT {','.join(expr)} FROM {table}")
def sqlite_auth_summary(path):
    c=_source(path)
    try:
        tokens=c.execute("SELECT COUNT(*) FROM auth_tokens").fetchone()[0] if _exists(c,"auth_tokens") else 0
        return {"integrity":"ok","users":int(c.execute("SELECT COUNT(*) FROM users").fetchone()[0]),"auth_tokens":int(tokens)}
    finally: c.close()
def migrate_sqlite_auth_to_postgres(source_path,database_url,*,dry_run=False,batch_size=500):
    if not database_url.startswith(("postgresql://","postgres://")): raise ValueError("Target URL must use postgresql:// or postgres://")
    if not isinstance(batch_size,int) or isinstance(batch_size,bool) or not 1<=batch_size<=5000: raise ValueError("batch_size must be between 1 and 5000")
    source=_source(source_path)
    try:
        summary=sqlite_auth_summary(source_path)
        if dry_run: return {**summary,"mode":"dry_run","target_changed":False}
        target=connect_postgres(database_url)
        try:
            target.execute("""CREATE TABLE IF NOT EXISTS users(email TEXT PRIMARY KEY,password_hash TEXT NOT NULL,created_at TEXT NOT NULL,email_verified INTEGER NOT NULL DEFAULT 1,session_version INTEGER NOT NULL DEFAULT 0)""")
            target.execute("""CREATE TABLE IF NOT EXISTS auth_tokens(token_hash TEXT PRIMARY KEY,email TEXT NOT NULL,purpose TEXT NOT NULL CHECK(purpose IN ('verify_email','password_reset')),expires_at BIGINT NOT NULL,used_at BIGINT,created_at BIGINT NOT NULL)""")
            target.execute("CREATE INDEX IF NOT EXISTS idx_auth_tokens_email_purpose ON auth_tokens(email,purpose)")
            inserts={"users":"INSERT INTO users ("+','.join(USER_COLUMNS)+") VALUES ("+','.join(['%s']*len(USER_COLUMNS))+") ON CONFLICT DO NOTHING","auth_tokens":"INSERT INTO auth_tokens ("+','.join(TOKEN_COLUMNS)+") VALUES ("+','.join(['%s']*len(TOKEN_COLUMNS))+") ON CONFLICT DO NOTHING"}
            for table,cols in (("users",USER_COLUMNS),("auth_tokens",TOKEN_COLUMNS)):
                if table=="auth_tokens" and not _exists(source,table): continue
                cur=_select_rows(source,table,cols)
                with target._connection.cursor() as dest:
                    while True:
                        batch=cur.fetchmany(batch_size)
                        if not batch: break
                        dest.executemany(inserts[table],[tuple(row[c] for c in cols) for row in batch])
            missing={"users":0,"auth_tokens":0}; mismatches={"users":0,"auth_tokens":0}
            for table,cols in (("users",USER_COLUMNS),("auth_tokens",TOKEN_COLUMNS)):
                if table=="auth_tokens" and not _exists(source,table): continue
                cur=_select_rows(source,table,cols)
                while True:
                    batch=cur.fetchmany(batch_size)
                    if not batch: break
                    for row in batch:
                        found=target.execute(f"SELECT {','.join(cols)} FROM {table} WHERE {cols[0]}=?",(row[cols[0]],)).fetchone()
                        if found is None: missing[table]+=1
                        elif any(found[c]!=row[c] for c in cols): mismatches[table]+=1
            if any(missing.values()) or any(mismatches.values()):
                target.rollback(); raise RuntimeError(f"Migration verification failed: missing={missing}, mismatches={mismatches}")
            target.commit()
            return {**summary,"mode":"applied","verified":True,"missing":missing,"mismatches":mismatches,"destination_overwrites":0}
        except Exception:
            target.rollback(); raise
        finally: target.close()
    finally: source.close()
