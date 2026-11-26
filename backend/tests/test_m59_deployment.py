from __future__ import annotations
import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts"


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def valid_env(monkeypatch):
    values = {
        "DATALINEAGE_ENVIRONMENT": "production",
        "DATALINEAGE_AUTH_ENABLED": "true",
        "DATALINEAGE_AUTH_USERNAME": "deployment-admin",
        "DATALINEAGE_EMAIL_DEV_MODE": "false",
        "DATALINEAGE_AUTH_PASSWORD": "A-Long-Unique-Password-2026!",
        "DATALINEAGE_SESSION_SECRET": "s" * 48,
        "DATALINEAGE_SECURE_COOKIE": "true",
        "DATALINEAGE_PUBLIC_BASE_URL": "https://app.customer.test",
        "DATALINEAGE_CORS_ORIGINS": "https://app.customer.test",
        "DATALINEAGE_SMTP_HOST": "smtp.customer.test",
        "DATALINEAGE_SMTP_FROM_EMAIL": "noreply@customer.test",
        "DATALINEAGE_SMTP_SSL": "true",
        "DATALINEAGE_SMTP_STARTTLS": "false",
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)


def test_preflight_passes_valid_single_replica_environment(monkeypatch):
    module = load_script("deployment_preflight")
    valid_env(monkeypatch)
    errors, warnings = module.inspect_environment(replicas=1)
    assert errors == []
    assert any("SQLite" in warning for warning in warnings)


def test_preflight_blocks_multi_replica(monkeypatch):
    module = load_script("deployment_preflight")
    valid_env(monkeypatch)
    errors, _ = module.inspect_environment(replicas=2)
    assert any("replicas > 1" in item for item in errors)


def test_preflight_blocks_missing_production_security(monkeypatch):
    module = load_script("deployment_preflight")
    for key in list(os.environ):
        if key.startswith("DATALINEAGE_"):
            monkeypatch.delenv(key, raising=False)
    errors, _ = module.inspect_environment()
    assert len(errors) >= 6


def test_sqlite_backup_manifest_and_restore(tmp_path):
    backup = load_script("backup_sqlite")
    restore = load_script("restore_sqlite_backup")
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    target_dir = tmp_path / "restore"
    data_dir.mkdir()
    db = sqlite3.connect(data_dir / "analysis_runs.sqlite3")
    db.execute("CREATE TABLE sample(value TEXT)")
    db.execute("INSERT INTO sample VALUES('preserved')")
    db.commit()
    db.close()

    result = backup.backup_one(data_dir / "analysis_runs.sqlite3", backup_dir / "run1" / "analysis_runs.sqlite3")
    assert result["status"] == "backed_up"
    import hashlib
    backup_file = backup_dir / "run1" / "analysis_runs.sqlite3"
    manifest = {"format": "datalineage-sqlite-backup-v1", "databases": [{
        "filename": backup_file.name,
        "bytes": backup_file.stat().st_size,
        "sha256": hashlib.sha256(backup_file.read_bytes()).hexdigest(),
    }]}
    (backup_dir / "run1" / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    restored = restore.restore(backup_dir / "run1", target_dir)
    assert restored == ["analysis_runs.sqlite3"]
    check = sqlite3.connect(target_dir / "analysis_runs.sqlite3")
    assert check.execute("SELECT value FROM sample").fetchone()[0] == "preserved"
    check.close()


def test_restore_refuses_overwrite_by_default(tmp_path):
    restore = load_script("restore_sqlite_backup")
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    source = backup_dir / "users.sqlite3"
    db = sqlite3.connect(source)
    db.execute("CREATE TABLE t(x)")
    db.commit(); db.close()
    import hashlib
    (backup_dir / "manifest.json").write_text(json.dumps({
        "format": "datalineage-sqlite-backup-v1",
        "databases": [{"filename": source.name, "sha256": hashlib.sha256(source.read_bytes()).hexdigest()}]
    }), encoding="utf-8")
    target = tmp_path / "target"
    target.mkdir()
    (target / source.name).write_text("existing")
    try:
        restore.restore(backup_dir, target)
    except FileExistsError:
        pass
    else:
        raise AssertionError("restore should refuse overwrite")


def test_docker_image_copies_worker_entrypoints():
    dockerfile = (ROOT / "Dockerfile").read_text()
    assert "COPY backend/scripts_m50_worker.py" in dockerfile
    assert "COPY backend/scripts_m54_monitor_worker.py" in dockerfile


def test_kubernetes_keeps_single_replica_and_m59_image():
    deployment = (ROOT / "deploy/kubernetes/deployment.yaml").read_text()
    hpa = (ROOT / "deploy/kubernetes/hpa.yaml").read_text()
    assert "replicas: 1" in deployment
    assert "datalineage-ai:m59" in deployment
    assert "maxReplicas: 1" in hpa
