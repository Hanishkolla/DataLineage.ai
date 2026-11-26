import pytest
from app.quality_intelligence import analyze_quality_intelligence


def test_numeric_range_rule_finds_invalid_values_and_traces_upstream():
    result = analyze_quality_intelligence(
        [{"net_amount": 10}, {"net_amount": -4}, {"net_amount": 20}],
        rules=[{"id": "amount-positive", "column": "net_amount", "type": "numeric_range", "min": 0}],
        lineage_edges=[{"source_column": "raw.orders.amount", "target_column": "staging.orders.net_amount"},
                       {"source_column": "staging.orders.net_amount", "target_column": "net_amount"}],
    )
    assert result["failed_check_count"] == 1
    finding = result["findings"][0]
    assert finding["probable_root_cause_candidates"] == ["raw.orders.amount"]
    assert finding["root_cause_confidence"] == "lineage_candidate_only"


def test_upstream_finding_corroborates_candidate():
    result = analyze_quality_intelligence(
        [{"email": "bad"}],
        rules=[{"column": "email", "type": "regex", "pattern": r"[^@]+@[^@]+\\.[^@]+"}],
        lineage_edges=[{"source_column": "raw.customer.email", "target_column": "email"}],
        upstream_quality_findings=["raw.customer.email"],
    )
    assert result["findings"][0]["root_cause_confidence"] == "corroborated_by_supplied_upstream_finding"


def test_not_null_and_max_null_rate_rules():
    result = analyze_quality_intelligence(
        [{"id": 1, "name": "A"}, {"id": 2, "name": None}],
        rules=[{"column": "name", "type": "not_null"},
               {"column": "name", "type": "max_null_rate", "threshold": 10}],
    )
    assert result["failed_check_count"] == 2
    assert result["status"] == "needs_attention"


def test_rejects_invalid_rule_and_bad_regex():
    with pytest.raises(ValueError, match="unsupported rule type"):
        analyze_quality_intelligence([{"x": 1}], rules=[{"column": "x", "type": "magic"}])
    with pytest.raises(ValueError, match="invalid regular expression"):
        analyze_quality_intelligence([{"x": "a"}], rules=[{"column": "x", "type": "regex", "pattern": "["}])


def test_rejects_invalid_lineage_payload():
    with pytest.raises(ValueError, match="lineage_edges"):
        analyze_quality_intelligence([{"x": 1}], lineage_edges=["not-an-edge"])
