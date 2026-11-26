import pytest
from app import data_operations as ops


def test_run_failure_triage_classifies_and_recommends():
    result = ops.analyze_runs([
        {"status": "failed", "pipeline": "daily_load", "run_id": "r-1", "message": "Access denied to storage"},
        {"status": "succeeded", "pipeline": "ok"},
        {"status": "timed_out", "pipeline": "slow", "message": "connection timed out"},
    ])
    assert result["failure_count"] == 2
    assert result["incidents"][0]["cause_code"] == "identity_or_permission"
    assert result["incidents"][1]["cause_code"] == "connectivity_or_timeout"
    assert result["incidents"][0]["confidence"] == "heuristic"


def test_run_input_limits_and_types():
    with pytest.raises(ValueError): ops.analyze_runs(["not-an-event"])
    with pytest.raises(ValueError): ops.analyze_runs([{}] * (ops.MAX_EVENTS + 1))


def test_schema_drift_detects_removed_added_and_type_change():
    before = {"tables": [{"schema": "raw", "name": "orders", "columns": [
        {"name": "id", "type": "int"}, {"name": "old_col", "type": "string"}]}]}
    after = {"tables": [{"schema": "raw", "name": "orders", "columns": [
        {"name": "id", "type": "bigint"}, {"name": "new_col", "type": "string"}]},
        {"schema": "raw", "name": "customers", "columns": []}]}
    result = ops.detect_schema_drift(before, after)
    kinds = {x["change"] for x in result["changes"]}
    assert kinds == {"column_removed", "column_added", "column_type_changed", "table_added"}
    assert result["status"] == "drift_detected"


def test_schema_drift_rejects_invalid_snapshot():
    with pytest.raises(ValueError): ops.detect_schema_drift({"tables": "bad"}, {"tables": []})


def test_quality_thresholds_flag_null_duplicate_and_freshness():
    result = ops.evaluate_quality([{"dataset": "orders", "null_rate": .2,
                                    "duplicate_rate": .03, "freshness_lag_seconds": 90000}])
    assert result["finding_count"] == 3
    assert result["status"] == "needs_attention"


def test_quality_rejects_invalid_metrics():
    with pytest.raises(ValueError): ops.evaluate_quality([{"null_rate": -0.1}])
    with pytest.raises(ValueError): ops.evaluate_quality([], {"null_rate_max": -1})


def test_incident_store_is_idempotent_and_tenant_scoped(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_OPERATIONS_DB", str(tmp_path / "ops.sqlite3"))
    incident = {"incident_id": "i1", "event_id": "event-1", "pipeline": "daily", "status": "failed"}
    assert ops.persist_incidents("tenant-a", [incident])["inserted"] == 1
    second = ops.persist_incidents("tenant-a", [incident])
    assert second["duplicates_ignored"] == 1
    ops.persist_incidents("tenant-b", [incident])
    assert len(ops.list_incidents("tenant-a")) == 1
    assert len(ops.list_incidents("tenant-b")) == 1
    assert ops.list_incidents("tenant-a")[0]["pipeline"] == "daily"
