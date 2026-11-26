from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
import sys
import threading
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from app.staging_health_checks import build_service_report, probe_postgres, probe_redis

ROOT = Path(__file__).resolve().parents[2]


def test_service_probes_report_unconfigured_without_attempting_connections():
    assert probe_postgres("") == {"backend": "postgresql", "configured": False, "status": "not_configured"}
    assert probe_redis("") == {"backend": "redis", "configured": False, "status": "not_configured"}


def test_postgres_probe_uses_read_only_select_and_closes_connection(monkeypatch):
    state = {"sql": None, "closed": False}

    class Cursor:
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False
        def execute(self, statement):
            state["sql"] = statement
        def fetchone(self):
            return (1,)

    class Connection:
        def cursor(self):
            return Cursor()
        def close(self):
            state["closed"] = True

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=lambda *a, **k: Connection()))
    result = probe_postgres("postgresql://private:secret@db/app")
    assert result["status"] == "connected"
    assert state["sql"] == "SELECT 1"
    assert state["closed"] is True
    assert "private" not in json.dumps(result) and "secret" not in json.dumps(result)


def test_redis_probe_sends_ping_and_closes_client(monkeypatch):
    state = {"pinged": False, "closed": False, "options": None}

    class Client:
        def ping(self):
            state["pinged"] = True
            return True
        def close(self):
            state["closed"] = True

    class RedisFactory:
        @staticmethod
        def from_url(url, **kwargs):
            state["options"] = kwargs
            return Client()

    monkeypatch.setitem(sys.modules, "redis", SimpleNamespace(Redis=RedisFactory))
    result = probe_redis("rediss://:private-secret@cache/0")
    assert result["status"] == "connected"
    assert state["pinged"] and state["closed"]
    assert state["options"]["socket_connect_timeout"] <= 20
    assert "private-secret" not in json.dumps(result)


def test_service_report_blocks_missing_required_services_and_never_leaks_urls():
    pg = "postgresql://private-user:super-secret@db.internal:5432/prod"
    redis = "rediss://:redis-secret@cache.internal:6380/0"
    report = build_service_report(
        {"DATALINEAGE_DATABASE_URL": pg, "DATALINEAGE_REDIS_URL": redis},
        require_postgres=True, require_redis=True,
        postgres_probe=lambda url, timeout: {"backend": "postgresql", "configured": True,
                            "status": "unavailable", "error_type": "OperationalError"},
        redis_probe=lambda url, timeout: {"backend": "redis", "configured": True,
                            "status": "driver_missing", "error_type": "ImportError"},
    )
    serialized = json.dumps(report)
    assert report["status"] == "blocked"
    assert len(report["blockers"]) == 2
    assert "private-user" not in serialized and "super-secret" not in serialized
    assert "redis-secret" not in serialized and "db.internal" not in serialized


def test_service_report_warns_when_optional_services_are_not_configured():
    report = build_service_report({}, require_postgres=False, require_redis=False)
    assert report["status"] == "ready_with_warnings"
    assert len(report["warnings"]) == 2
    assert report["blockers"] == []


def test_service_report_passes_when_required_probes_connect():
    report = build_service_report(
        {"DATALINEAGE_DATABASE_URL": "postgresql://user:pw@db/app", "DATALINEAGE_REDIS_URL": "redis://cache/0"},
        require_postgres=True, require_redis=True,
        postgres_probe=lambda url, timeout: {"backend": "postgresql", "configured": True, "status": "connected", "latency_ms": 1.2, "check": "SELECT 1"},
        redis_probe=lambda url, timeout: {"backend": "redis", "configured": True, "status": "connected", "latency_ms": 0.8, "check": "PING"},
    )
    assert report["status"] == "ready"
    assert report["blockers"] == [] and report["warnings"] == []


class StagingHandler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def _write(self, status, payload, headers=None):
        raw = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/health/live":
            return self._write(200, {"status": "alive"})
        if self.path == "/health/ready":
            return self._write(200, {"status": "ready"})
        if self.path == "/auth/status":
            return self._write(200, {"enabled": True, "authenticated": False})
        if self.path == "/api/v1/enterprise/lineage/sql":
            return self._write(401 if "datalineage_session=sess" not in self.headers.get("Cookie", "") else 405,
                               {"detail": "Authentication required"})
        return self._write(404, {"detail": "not found"})

    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        payload = json.loads(raw.decode("utf-8")) if raw else {}
        authed = "datalineage_session=sess" in self.headers.get("Cookie", "")
        if self.path == "/auth/login":
            return self._write(200, {"status": "authenticated"}, {
                "Set-Cookie": "datalineage_session=sess; Path=/; HttpOnly; SameSite=Strict"
            })
        if self.path == "/auth/logout":
            return self._write(200, {"status": "logged_out"}, {
                "Set-Cookie": "datalineage_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"
            })
        if self.path == "/api/v1/enterprise/lineage/sql":
            if not authed:
                return self._write(401, {"detail": "Authentication required"})
            if payload.get("dialect") not in {"generic", "postgres"}:
                return self._write(422, {"detail": "unsupported test dialect"})
            return self._write(200, {"analysis_mode": "static_sql_ast", "executed_sql": False,
                                     "node_count": 2, "table_edge_count": 1})
        return self._write(404, {"detail": "not found"})


@pytest.fixture
def staging_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), StagingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def _load_staging_smoke():
    path = ROOT / "scripts" / "staging_smoke.py"
    spec = importlib.util.spec_from_file_location("m63_staging_smoke_test_module", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_staging_http_smoke_checks_auth_sql_lineage_and_logout(staging_server):
    module = _load_staging_smoke()
    report = module.run_smoke_test(
        staging_server, username="pilot-admin", password="not-written-to-report",
        allow_http=True, dialects=("generic", "postgres"),
    )
    assert report["status"] == "passed"
    assert report["summary"] == {"passed": 10, "failed": 0}
    serialized = json.dumps(report)
    assert "pilot-admin" not in serialized
    assert "not-written-to-report" not in serialized


def test_staging_http_smoke_rejects_non_https_remote_urls():
    module = _load_staging_smoke()
    with pytest.raises(ValueError, match="HTTPS is required"):
        module.run_smoke_test("http://staging.customer.test", username="u", password="p")


def test_staging_http_smoke_requires_loopback_opt_in_for_http():
    module = _load_staging_smoke()
    with pytest.raises(ValueError, match="HTTPS is required"):
        module.run_smoke_test("http://127.0.0.1:8000", username="u", password="p")
    report = module.run_smoke_test(
        "http://127.0.0.1:1", username="u", password="p", allow_http=True, timeout=1,
    )
    assert report["status"] == "failed"


def _load_recovery_drill():
    path = ROOT / "scripts" / "m63_recovery_drill.py"
    spec = importlib.util.spec_from_file_location("m63_recovery_drill_test_module", path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_sqlite_recovery_drill_restores_to_temporary_folder_without_touching_live_db(tmp_path):
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    db_path = backup_dir / "analysis_runs.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute("CREATE TABLE sample(value TEXT)")
        connection.execute("INSERT INTO sample VALUES('retained')")
    manifest = {"format": "datalineage-sqlite-backup-v1", "databases": [{
        "filename": db_path.name, "bytes": db_path.stat().st_size,
        "sha256": hashlib.sha256(db_path.read_bytes()).hexdigest(),
    }]}
    (backup_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    report = _load_recovery_drill().run_sqlite_restore_drill(backup_dir)
    assert report["status"] == "passed"
    assert report["restored_database_count"] == 1
    assert report["live_data_modified"] is False
    assert report["databases"][0]["integrity"] == "ok"


def test_recovery_drill_rejects_modified_backup(tmp_path):
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    db_path = backup_dir / "analysis_runs.sqlite3"
    with sqlite3.connect(db_path) as connection:
        connection.execute("CREATE TABLE sample(value TEXT)")
    manifest = {"format": "datalineage-sqlite-backup-v1", "databases": [{
        "filename": db_path.name, "bytes": db_path.stat().st_size, "sha256": "incorrect",
    }]}
    (backup_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="checksum mismatch"):
        _load_recovery_drill().run_sqlite_restore_drill(backup_dir)


def test_m63_scripts_compile():
    for path in (ROOT / "scripts" / "staging_services.py", ROOT / "scripts" / "staging_smoke.py",
                 ROOT / "scripts" / "m63_recovery_drill.py"):
        spec = importlib.util.spec_from_file_location(f"m63_compile_{path.stem}", path)
        assert spec and spec.loader and path.is_file()
