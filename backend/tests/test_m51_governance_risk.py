from app.governance_risk import assess_governance_risk
import pytest


def sample():
    return {"provider":"azure","tables":[
        {"name":"customers","schema":"dbo","owner":"","tags":[],"columns":[{"name":"email_address","type":"varchar"}]},
        {"name":"customer_export","schema":"dbo","owner":"analytics","tags":[],"columns":[{"name":"customer_id","type":"int"}]},
        {"name":"summary","schema":"dbo","owner":"analytics","tags":["internal"],"columns":[{"name":"total","type":"decimal"}]}
    ]}


def test_sensitive_metadata_creates_governance_findings():
    result=assess_governance_risk(sample(), [{"source":"customers","target":"customer_export"},{"source":"customer_export","target":"summary"}])
    codes={f["code"] for f in result["findings"]}
    assert "OWNER_MISSING" in codes
    assert "SENSITIVE_TAG_MISSING" in codes
    assert "SENSITIVE_DATA_PROPAGATED" in codes
    assert result["risk_score"] > 0
    assert result["risk_level"] in {"low","medium","high","critical"}


def test_custom_required_tag_policy():
    result=assess_governance_risk(sample(), [], [{"id":"pii_tag","name":"PII tag required","kind":"required_tag","tag":"pii","severity":"critical"}])
    assert any(f["code"]=="POLICY_PII_TAG" for f in result["findings"])


def test_clean_metadata_low_risk():
    metadata={"provider":"snowflake","tables":[{"name":"dim_date","owner":"data-team","tags":["public"],"columns":[{"name":"date_key","type":"date"}]}]}
    result=assess_governance_risk(metadata, [], [])
    assert result["finding_count"]==0
    assert result["risk_score"]==0
    assert result["risk_level"]=="low"


def test_rejects_bad_policy_and_unbounded_edges():
    with pytest.raises(ValueError):
        assess_governance_risk(sample(), [], [{"id":"x","kind":"unknown"}])
    with pytest.raises(ValueError):
        assess_governance_risk(sample(), [{}]*250001, [])


def test_policy_provider_allowlist():
    result=assess_governance_risk(sample(), [], [{"id":"provider","kind":"allowed_provider","providers":["snowflake"],"severity":"high"}])
    assert any(f["code"]=="POLICY_PROVIDER" for f in result["findings"])
