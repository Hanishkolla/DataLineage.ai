import pytest
from app import ai_copilot as ai


def test_copilot_returns_grounded_metadata_and_lineage_only():
    result = ai.copilot_query(
        "where is customer email stored?",
        {"tables": [{"schema": "crm", "name": "customers",
                     "columns": [{"name": "customer_id"}, {"name": "email"}]},
                    {"schema": "sales", "name": "orders", "columns": [{"name": "order_id"}]}]},
        [{"source": "crm.customers.email", "target": "mart.customer_email"}])
    assert result["matched_object_count"] == 1
    assert result["evidence"][0]["table"] == "customers"
    assert result["lineage_evidence"][0]["target"] == "mart.customer_email"
    assert result["analysis_mode"] == "evidence_grounded_retrieval"


def test_copilot_rejects_empty_question_and_bad_metadata():
    with pytest.raises(ValueError):
        ai.copilot_query("", {"tables": []})
    with pytest.raises(ValueError):
        ai.copilot_query("orders", {"tables": "bad"})


def test_impact_explanation_traverses_downstream_graph():
    result = ai.explain_impact("raw.orders", [
        {"source": "raw.orders", "target": "staging.orders"},
        {"source": "staging.orders", "target": "mart.orders"},
        {"source": "other.table", "target": "unrelated"},
    ])
    assert result["downstream_objects"] == ["mart.orders", "staging.orders"]
    assert result["risk"] == "medium"


def test_incident_summary_groups_causes_and_pipelines():
    result = ai.summarize_incidents([
        {"cause_code": "timeout", "severity": "medium", "pipeline": "daily", "recommendation": "Check network"},
        {"cause_code": "timeout", "severity": "high", "pipeline": "daily", "recommendation": "Check network"},
        {"cause_code": "schema", "severity": "high", "pipeline": "hourly"},
    ])
    assert result["incident_count"] == 3
    assert result["cause_distribution"]["timeout"] == 2
    assert result["most_affected_pipelines"][0] == {"pipeline": "daily", "count": 2}


def test_data_risk_score_is_transparent_and_bounded():
    result = ai.assess_data_risk(
        schema_changes=[{"risk": "high"}],
        quality_findings=[{"severity": "high"}],
        incidents=[{"severity": "high"}])
    assert result["risk_score"] == 24
    assert result["risk_level"] == "medium"
    assert result["scoring_method"] == "transparent_weighted_heuristic_v1"


def test_data_risk_rejects_invalid_inputs():
    with pytest.raises(ValueError):
        ai.assess_data_risk(schema_changes="not-a-list")
