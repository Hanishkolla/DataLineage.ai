from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

def test_cors_allows_api_key_revocation_and_authorization_header():
    source = (ROOT / "backend" / "app" / "main.py").read_text()
    assert '"DELETE"' in source
    assert '"Authorization"' in source

def test_liveness_bypasses_production_configuration_gate():
    source = (ROOT / "backend" / "app" / "main.py").read_text()
    assert 'request.url.path not in {"/health", "/health/live"}' in source

def test_duplicate_password_reset_setting_removed():
    source = (ROOT / "backend" / "app" / "config.py").read_text()
    assert source.count("password_reset_ttl_seconds:") == 1

def test_dockerfile_runs_non_root_and_has_healthcheck():
    source = (ROOT / "backend" / "Dockerfile").read_text()
    assert "USER appuser" in source
    assert "HEALTHCHECK" in source

def test_kubernetes_is_single_replica_until_shared_state_exists():
    source = (ROOT / "deploy" / "kubernetes" / "deployment.yaml").read_text()
    assert "replicas: 1" in source
    assert "runAsNonRoot: true" in source
    assert "readOnlyRootFilesystem: true" in source

def test_backup_scripts_exist():
    assert (ROOT / "scripts" / "backup_sqlite.py").is_file()
    assert (ROOT / "scripts" / "verify_sqlite_backup.py").is_file()
