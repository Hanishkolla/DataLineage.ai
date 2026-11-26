from __future__ import annotations
import sqlite3
from app import saas_store as s
from app.db_backend import qmark_to_pyformat


def test_saas_store_sqlite_regression_for_org_usage_and_billing(tmp_path, monkeypatch):
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    monkeypatch.setattr(s, "_path", lambda: tmp_path / "saas.sqlite3")
    org = s.create_org("owner@example.com", "M47 Acme")
    first = s.record_usage("owner@example.com", org["id"], "analyses", 2, "id-1")
    second = s.record_usage("owner@example.com", org["id"], "analyses", 2, "id-1")
    assert first["recorded"] is True
    assert second["recorded"] is False
    assert s.process_mock_event("owner@example.com", org["id"], "mock", "evt-47", "paid")["processed"] is True
    assert s.process_mock_event("owner@example.com", org["id"], "mock", "evt-47", "paid")["processed"] is False


def test_saas_sqlite_idempotency_sql_uses_postgres_compatible_conflict_clause():
    source = open(s.__file__, encoding="utf-8").read()
    assert "INSERT OR IGNORE" not in source
    assert "SELECT changes()" not in source
    assert "ON CONFLICT(org_id,idempotency_key) DO NOTHING" in source
    assert "ORDER BY rowid" not in source


def test_qmark_translation_preserves_literals_for_postgres():
    sql = "INSERT INTO t(a,b) VALUES(?, '?') -- ? comment"
    assert qmark_to_pyformat(sql) == "INSERT INTO t(a,b) VALUES(%s, '?') -- ? comment"


def test_saas_migration_dry_run_counts_all_store_tables(tmp_path, monkeypatch):
    from app.organization_data_migration import migrate_sqlite_saas_to_postgres
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    source = tmp_path / "saas.sqlite3"
    monkeypatch.setattr(s, "_path", lambda: source)
    org = s.create_org("migration@example.com", "Migration Org")
    s.change_plan("migration@example.com", org["id"], "starter")
    result = migrate_sqlite_saas_to_postgres(
        source, "postgresql://unused:unused@localhost/unused", dry_run=True
    )
    assert result["mode"] == "dry_run"
    assert result["target_changed"] is False
    assert result["tables"]["organizations"] == 1
    assert result["tables"]["memberships"] == 1
    assert result["tables"]["subscriptions"] == 2
