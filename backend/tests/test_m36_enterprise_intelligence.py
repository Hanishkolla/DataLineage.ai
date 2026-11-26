from app.metadata_governance import (
    normalize_metadata, build_unified_lineage, analyze_pipeline_events,
    classify_metadata, evaluate_governance, simulate_impact, copilot_answer,
)
import pytest

SAMPLE = {"provider": "snowflake", "tables": [{"name": "customers", "schema": "raw", "columns": [
    {"name": "email_address", "type": "varchar"}, {"name": "customer_id", "type": "number"}], "tags": [], "owner": ""}]}

def test_normalize_metadata_and_deduplicate():
    result = normalize_metadata({"tables": SAMPLE["tables"] * 2}, "snowflake")
    assert result["table_count"] == 1 and result["column_count"] == 2
    assert result["live_connection"] is False

def test_reject_unknown_provider_and_oversized_metadata():
    with pytest.raises(ValueError): normalize_metadata({}, "unknown-cloud")
    with pytest.raises(ValueError): normalize_metadata({"tables": "not-a-list"}, "aws")

def test_unified_lineage_keeps_explicit_edges():
    result = build_unified_lineage([{"provider": "snowflake", "metadata": SAMPLE,
        "edges": [{"source": "snowflake:raw.orders", "target": "snowflake:raw.customers"}]}])
    assert result["node_count"] == 1 and result["edge_count"] == 1

def test_pipeline_failure_triage():
    result = analyze_pipeline_events([{"status": "failed", "pipeline": "daily", "message": "permission denied"}])
    assert result["failure_count"] == 1
    assert result["failures"][0]["probable_cause"] == "Permission or identity failure"

def test_sensitive_classification_and_governance():
    classified = classify_metadata(SAMPLE)
    assert classified["finding_count"] == 1
    governance = evaluate_governance(SAMPLE, [{"name": "owner-tag", "required_tag": "pii", "require_owner": True}])
    assert governance["status"] == "needs_attention" and governance["finding_count"] == 2

def test_impact_simulation_transitive():
    result = simulate_impact("a", [{"source": "a", "target": "b"}, {"source": "b", "target": "c"}])
    assert result["downstream_objects"] == ["b", "c"]

def test_copilot_returns_grounded_metadata_evidence():
    result = copilot_answer("find customer email", SAMPLE)
    assert result["mode"] == "deterministic_metadata_retrieval"
    assert result["evidence"][0]["table"] == "customers"
