import json
import pytest
from app import governance_repository as store


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SAAS_DB_PATH", str(tmp_path / "saas.sqlite3"))
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)


def sample_result():
    return {"provider":"azure","risk_score":42,"risk_level":"high","finding_count":2,
            "summary":{"metadata_objects":3},"findings":[
                {"code":"OWNER_MISSING","title":"Owner missing","object":"sales.customers","severity":"medium","evidence":"No owner","remediation":"Assign owner","status":"open"},
                {"code":"PII_TAG","title":"PII tag missing","object":"sales.customers","severity":"high","evidence":"Potential PII","remediation":"Tag it","status":"open"}]}


def test_scan_and_findings_persist_and_filter(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    saved=store.save_scan("org-a",sample_result())
    assert saved["finding_count"] == 2
    assert len(store.list_scans("org-a")) == 1
    assert len(store.list_findings("org-a")) == 2
    assert len(store.list_findings("org-a",severity="high")) == 1
    assert store.list_findings("org-b") == []


def test_finding_workflow_and_summary(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    store.save_scan("org-a",sample_result())
    row=store.list_findings("org-a")[0]
    updated=store.update_finding("org-a",row["id"],status="in_progress",owner="data-team",due_date="2026-12-01")
    assert updated["status"] == "in_progress" and updated["owner"] == "data-team"
    summary=store.summary("org-a")
    assert summary["scan_count"] == 1 and summary["finding_count"] == 2
    assert summary["by_status"]["in_progress"] == 1


def test_update_is_tenant_scoped_and_status_validated(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    store.save_scan("org-a",sample_result())
    fid=store.list_findings("org-a")[0]["id"]
    assert store.update_finding("org-b",fid,status="resolved") is None
    with pytest.raises(ValueError): store.update_finding("org-a",fid,status="closed")


def test_policy_upsert_and_isolation(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    p={"id":"owner-check","name":"Owner check","kind":"owner","severity":"high"}
    store.save_policy("org-a",p)
    assert len(store.list_policies("org-a")) == 1
    assert store.list_policies("org-b") == []
    p["name"]="Updated owner check"; store.save_policy("org-a",p)
    assert len(store.list_policies("org-a")) == 1
    assert store.list_policies("org-a")[0]["name"] == "Updated owner check"
