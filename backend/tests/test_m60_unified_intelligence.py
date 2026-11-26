from app import governance_overview as m60


def test_unified_overview_aggregates_tenant_scoped_modules(monkeypatch):
    monkeypatch.setattr(m60.governance, "summary", lambda org: {"scan_count": 3, "finding_count": 4, "by_status": {"open": 2, "resolved": 2}, "by_severity": {"critical": 1}})
    monkeypatch.setattr(m60.governance, "list_scans", lambda org, limit: [
        {"id": "s1", "provider": "snowflake", "risk_score": 80, "risk_level": "critical", "finding_count": 2, "created_at": "2026-01-01"}
    ])
    monkeypatch.setattr(m60.governance, "list_findings", lambda org, limit: [
        {"severity": "critical", "status": "open"}, {"severity": "high", "status": "in_progress"}
    ])
    monkeypatch.setattr(m60.monitoring, "list_schedules", lambda org, limit: [{"enabled": True}, {"enabled": False}])
    monkeypatch.setattr(m60.monitoring, "list_runs", lambda org, limit: [{"id": "r1", "status": "completed", "started_at": "now"}])
    monkeypatch.setattr(m60.connectors, "list_snapshots", lambda org, limit: [{"id": "x1", "provider": "snowflake", "table_count": 10, "column_count": 40}])
    monkeypatch.setattr(m60.connectors, "list_changes", lambda org, limit: [{"changes": {"risk": "high"}}])
    monkeypatch.setattr(m60.audit, "list_approvals", lambda org, status, limit: [{"id": "a1"}])
    monkeypatch.setattr(m60.audit, "list_events", lambda org, limit: [{"action": "policy.saved", "resource_type": "policy", "created_at": "now", "payload": {"secret": "must-not-leak"}}])
    monkeypatch.setattr(m60.audit, "verify_chain", lambda org: {"valid": True, "events_checked": 7})

    result = m60.build_unified_overview("tenant-a")
    assert result["headline"] == {
        "governance_scans": 3,
        "open_findings": 2,
        "critical_findings": 1,
        "pending_approvals": 1,
        "connected_source_providers": 1,
        "enabled_monitoring_schedules": 1,
    }
    assert result["connectors"]["changes_by_risk"] == {"high": 1}
    assert result["audit"]["integrity_valid"] is True
    assert "payload" not in result["audit"]["recent_activity"][0]


def test_invalid_org_rejected():
    try:
        m60.build_unified_overview("")
    except ValueError as exc:
        assert "organization" in str(exc)
    else:
        raise AssertionError("empty organization id must be rejected")


def test_unified_overview_reads_real_tenant_records(tmp_path, monkeypatch):
    from app import governance_repository as governance_store
    from app import audit_approvals as audit_store
    from app import metadata_connectors as connector_store

    monkeypatch.setenv("DATALINEAGE_SAAS_DB_PATH", str(tmp_path / "m60.sqlite3"))
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    governance_store.save_scan("tenant-live", {
        "provider": "snowflake", "risk_score": 50, "risk_level": "high", "finding_count": 1,
        "summary": {"metadata_objects": 1},
        "findings": [{"code": "OWNER_MISSING", "title": "Owner missing", "object": "orders",
                      "severity": "critical", "evidence": "No owner", "remediation": "Assign owner", "status": "open"}],
    })
    connector_store.save_snapshot("tenant-live", "admin@example.test", {
        "provider": "snowflake", "tables": [{"name": "orders", "schema": "public", "columns": [{"name": "id", "type": "integer"}]}],
    })
    audit_store.request_approval("tenant-live", "requester@example.test", "policy", "pii", "change", "Review policy change")

    overview = m60.build_unified_overview("tenant-live")
    assert overview["headline"]["governance_scans"] == 1
    assert overview["headline"]["critical_findings"] == 1
    assert overview["headline"]["pending_approvals"] == 1
    assert overview["headline"]["connected_source_providers"] == 1
    assert overview["audit"]["integrity_valid"] is True
    # A different tenant receives no records from this tenant.
    other = m60.build_unified_overview("tenant-other")
    assert other["headline"]["governance_scans"] == 0
    assert other["headline"]["pending_approvals"] == 0
