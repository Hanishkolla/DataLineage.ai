from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from app.db_backend import configured_database_url, qmark_to_pyformat, backend_name
from app import run_store
from app.run_history_migration import sqlite_source_summary, migrate_sqlite_runs_to_postgres
from app.api_key_authentication import api_key_path_allowed


def test_postgres_qmark_translation_ignores_quoted_literals_and_comments():
    sql = "SELECT ?, '?' AS literal, \"?\" AS ident -- ?\nWHERE id = ? /* ? */"
    assert qmark_to_pyformat(sql) == "SELECT %s, '?' AS literal, \"?\" AS ident -- ?\nWHERE id = %s /* ? */"


def test_backend_name_tracks_configured_database_without_opening_a_connection(monkeypatch):
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    assert backend_name() == "sqlite"
    monkeypatch.setenv("DATALINEAGE_DATABASE_URL", "postgresql://user:pass@localhost/app")
    assert backend_name() == "postgresql"


def test_database_url_requires_postgres_scheme(monkeypatch):
    monkeypatch.setenv("DATALINEAGE_DATABASE_URL", "")
    assert configured_database_url() is None
    monkeypatch.setenv("DATALINEAGE_DATABASE_URL", "postgresql://user:pass@localhost/app")
    assert configured_database_url().startswith("postgresql://")
    monkeypatch.setenv("DATALINEAGE_DATABASE_URL", "mysql://localhost/app")
    with pytest.raises(ValueError):
        configured_database_url()


def test_sqlite_analysis_run_store_remains_default_and_operational(tmp_path, monkeypatch):
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    monkeypatch.setenv("DATALINEAGE_DB_PATH", str(tmp_path / "runs.sqlite3"))
    assert run_store.database_backend() == "sqlite"
    saved = run_store.save_analysis_run("project-a", {"tables": ["dbo.a"]}, owner_email="a@example.test", organization_id="org-a")
    rows = run_store.list_analysis_runs("project-a", owner_email="x@example.test", organization_id="org-a")
    assert len(rows) == 1 and rows[0]["run_id"] == saved["run_id"]
    assert run_store.get_analysis_run(saved["run_id"], organization_id="org-a")["result"]["tables"] == ["dbo.a"]


def test_sqlite_to_postgres_dry_run_validates_source_without_network(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE analysis_runs (run_id TEXT PRIMARY KEY, project_name TEXT NOT NULL, created_at TEXT NOT NULL, files_scanned INTEGER NOT NULL, files_with_errors INTEGER NOT NULL, tables_json TEXT NOT NULL, result_json TEXT NOT NULL)")
    db.execute("INSERT INTO analysis_runs VALUES ('r1','p','2026-01-01T00:00:00+00:00',1,0,'[]','{}')")
    db.commit()
    db.close()
    assert sqlite_source_summary(path) == {"integrity": "ok", "analysis_runs": 1, "organization_projects": 0}
    result = migrate_sqlite_runs_to_postgres(path, "postgresql://unused:unused@localhost/unused", dry_run=True)
    assert result["mode"] == "dry_run"
    assert result["target_changed"] is False
    with pytest.raises(ValueError):
        migrate_sqlite_runs_to_postgres(path, "mysql://localhost/db", dry_run=True)
    with pytest.raises(ValueError):
        migrate_sqlite_runs_to_postgres(path, "postgresql://unused:unused@localhost/db", dry_run=True, batch_size=0)


def test_m43_api_keys_remain_restricted_to_two_tenant_aware_routes():
    assert api_key_path_allowed("/api/v1/enterprise/operations/incidents", "GET", "viewer")
    assert api_key_path_allowed("/api/v1/enterprise/operations/runs/ingest", "POST", "developer")
    assert not api_key_path_allowed("/api/v1/enterprise/intelligence/copilot", "POST", "developer")
    assert not api_key_path_allowed("/api/v1/enterprise/operations/incidents/", "GET", "viewer")
    assert not api_key_path_allowed("/api/v1/enterprise/operations/incidents", "POST", "developer")
    assert not api_key_path_allowed("/api/v1/enterprise/operations/runs/ingest", "GET", "developer")
    assert not api_key_path_allowed("/api/v1/enterprise/security/audit", "GET", "developer")
