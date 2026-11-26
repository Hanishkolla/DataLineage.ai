
from app.github_review_policy import evaluate_review_policy, format_pr_comment, check_run_payload

def sample_report(level="high", unparsed=False):
    files = [{"filename":"models/orders.sql","status":"analyzed",
              "comparison":{"changes":{"added_tables":["analytics.orders_new"],
                                       "removed_tables":["legacy.orders"],
                                       "added_columns":["new_col"],"removed_columns":["old_col"]}}}]
    if unparsed:
        files.append({"filename":"models/unknown.sql","status":"unparsed"})
    return {"change_intelligence":{"risk":{"level":level},"counts":{"analyzed":1,"unparsed":int(unparsed),"added":0,"removed":0},
            "files":files,"recommended_tests":["Run downstream model tests."]}}

def test_advisory_policy_is_default_and_never_claims_merge_block():
    result = evaluate_review_policy(sample_report("high"))
    assert result["mode"] == "advisory"
    assert result["manual_review_required"] is True
    assert result["check_conclusion"] == "neutral"
    assert "branch protection" in result["note"]

def test_strict_policy_fails_high_risk():
    result = evaluate_review_policy(sample_report("high"), {"mode":"strict"})
    assert result["check_conclusion"] == "failure"

def test_strict_policy_fails_unparsed_sql():
    result = evaluate_review_policy(sample_report("low", True), {"mode":"strict"})
    assert result["unparsed_sql"] is True
    assert result["check_conclusion"] == "failure"

def test_policy_threshold_can_require_medium_review():
    result = evaluate_review_policy(sample_report("medium"), {"manual_review_from":"medium"})
    assert result["manual_review_required"] is True

def test_invalid_policy_rejected():
    import pytest
    with pytest.raises(ValueError):
        evaluate_review_policy(sample_report(), {"mode":"block-all"})

def test_comment_contains_summary_but_not_raw_sql_or_credentials():
    report = sample_report()
    policy = evaluate_review_policy(report)
    comment = format_pr_comment(report, policy)
    assert "Overall risk" in comment
    assert "analytics.orders_new" in comment
    assert "Run downstream model tests." in comment
    assert "password=" not in comment.lower()
    assert "SELECT *" not in comment

def test_check_payload_maps_policy_conclusion():
    report = sample_report("high")
    policy = evaluate_review_policy(report, {"mode":"strict"})
    payload = check_run_payload("a" * 40, report, policy)
    assert payload["head_sha"] == "a" * 40
    assert payload["conclusion"] == "failure"
    assert payload["status"] == "completed"
