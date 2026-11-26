from __future__ import annotations
import sqlite3
import pytest
from app import api_key_security as security
from app.security_data_migration import migrate_sqlite_security_to_postgres, sqlite_security_summary


def test_security_store_sqlite_mode_still_creates_and_verifies_keys(tmp_path, monkeypatch):
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATALINEAGE_SECURITY_DB", str(tmp_path / "security.sqlite3"))
    created = security.create_api_key("org-1", "owner@example.com", "CI key", "developer")
    assert created["api_key"].startswith("dla_live_")
    verified = security.verify_api_key(created["api_key"])
    assert verified["tenant_key"] == "org-1" and verified["role"] == "developer"
    audit = security.record_audit("org-1", "owner@example.com", "test", "api")
    assert audit["recorded"] and security.list_audit("org-1")[0]["sequence"] == audit["sequence"]


def test_security_store_listing_never_exposes_raw_key(tmp_path, monkeypatch):
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATALINEAGE_SECURITY_DB", str(tmp_path / "security.sqlite3"))
    created = security.create_api_key("org-1", "owner@example.com", "CI key", "viewer")
    listed = security.list_api_keys("org-1")
    assert "api_key" not in listed[0] and created["api_key"] not in repr(listed)


def _source(path):
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE api_keys(key_id TEXT PRIMARY KEY,tenant_key TEXT NOT NULL,
        owner_identity TEXT NOT NULL,label TEXT NOT NULL,key_hash TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT,revoked_at TEXT)""")
    conn.execute("""CREATE TABLE security_audit(sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE,tenant_key TEXT NOT NULL,actor TEXT NOT NULL,
        action TEXT NOT NULL,resource_type TEXT NOT NULL,resource_id TEXT,outcome TEXT NOT NULL,
        occurred_at TEXT NOT NULL,details_json TEXT NOT NULL)""")
    conn.execute("INSERT INTO api_keys VALUES(?,?,?,?,?,?,?,?,?)",
                 ("key-1","org-1","owner@example.com","CI","hash-only","viewer","now",None,None))
    conn.execute("INSERT INTO security_audit VALUES(?,?,?,?,?,?,?,?,?,?)",
                 (9,"event-1","org-1","owner@example.com","created","api_key","key-1","success","now","{}"))
    conn.commit(); conn.close()


def test_security_migration_dry_run_does_not_connect(tmp_path):
    source = tmp_path / "security.sqlite3"; _source(source)
    assert sqlite_security_summary(source) == {"integrity":"ok","api_keys":1,"security_audit":1}
    result = migrate_sqlite_security_to_postgres(source, "postgresql://unused:unused@localhost/unused", dry_run=True)
    assert result["mode"] == "dry_run" and result["target_changed"] is False


def test_security_migration_rejects_bad_target_and_batch_size(tmp_path):
    source = tmp_path / "security.sqlite3"; _source(source)
    with pytest.raises(ValueError):
        migrate_sqlite_security_to_postgres(source, "sqlite:///bad", dry_run=True)
    with pytest.raises(ValueError):
        migrate_sqlite_security_to_postgres(source, "postgresql://unused:unused@localhost/unused", dry_run=True, batch_size=0)


def test_security_migration_rejects_missing_tables(tmp_path):
    source = tmp_path / "empty.sqlite3"; sqlite3.connect(source).close()
    with pytest.raises(RuntimeError, match="api_keys and security_audit"):
        sqlite_security_summary(source)
