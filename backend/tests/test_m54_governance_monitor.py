import json
from datetime import datetime, timezone, timedelta
import pytest
from app import governance_monitoring as monitor


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SAAS_DB_PATH", str(tmp_path / "saas.sqlite3"))
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)


def payload(interval=15):
    return {"name": "Daily governance scan", "interval_minutes": interval,
            "metadata": {"provider": "azure", "tables": [
                {"name": "customers", "schema": "dbo", "columns": [
                    {"name": "email", "data_type": "varchar"}], "tags": []}]},
            "edges": [], "policies": None}


def test_create_schedule_is_tenant_scoped_and_audited(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    schedule = monitor.create_schedule("org-a", "admin@example.com", payload())
    assert schedule["enabled"] is True
    assert schedule["interval_minutes"] == 15
    assert monitor.list_schedules("org-b") == []
    assert monitor.audit_approvals.verify_chain("org-a")["valid"] is True


def test_interval_and_snapshot_validation(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    with pytest.raises(ValueError):
        monitor.create_schedule("org-a", "admin", payload(5))
    bad = payload(); bad["metadata"] = []
    with pytest.raises(ValueError):
        monitor.create_schedule("org-a", "admin", bad)
    huge = payload(); huge["metadata"] = {"blob": "x" * (monitor.MAX_SNAPSHOT_BYTES + 1)}
    with pytest.raises(ValueError):
        monitor.create_schedule("org-a", "admin", huge)


def test_due_schedule_runs_and_persists_scan_and_run_history(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    schedule = monitor.create_schedule("org-a", "admin", payload())
    with monitor._db() as c:
        monitor._schema(c)
        c.execute("UPDATE governance_monitor_schedules SET next_run_at=? WHERE id=?",
                  ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), schedule["id"]))
    result = monitor.run_once()
    assert result == {"claimed": 1, "completed": 1, "failed": 0}
    runs = monitor.list_runs("org-a", schedule["id"])
    assert len(runs) == 1 and runs[0]["status"] == "completed"
    assert runs[0]["scan_id"]
    assert monitor.m52_governance.list_scans("org-a")


def test_schedule_can_be_disabled_and_is_not_claimed(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    schedule = monitor.create_schedule("org-a", "admin", payload())
    disabled = monitor.set_enabled("org-a", schedule["id"], False, "admin")
    assert disabled["enabled"] is False
    with monitor._db() as c:
        monitor._schema(c)
        c.execute("UPDATE governance_monitor_schedules SET next_run_at=? WHERE id=?",
                  ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), schedule["id"]))
    assert monitor.run_once()["claimed"] == 0
    assert monitor.list_runs("org-a") == []


def test_claims_are_not_repeated_after_first_claim(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    schedule = monitor.create_schedule("org-a", "admin", payload())
    with monitor._db() as c:
        monitor._schema(c)
        c.execute("UPDATE governance_monitor_schedules SET next_run_at=? WHERE id=?",
                  ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), schedule["id"]))
    first = monitor._claim_due(datetime.now(timezone.utc))
    second = monitor._claim_due(datetime.now(timezone.utc))
    assert len(first) == 1
    assert second == []
