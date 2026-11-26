"""M60 unified tenant-scoped enterprise intelligence overview.

Aggregates persisted governance, monitoring, connector, approval and audit
metadata. It deliberately returns summaries rather than source data, credentials,
or raw audit payloads.
"""
from __future__ import annotations
from collections import Counter
from typing import Any

from . import governance_repository as governance
from . import audit_approvals as audit
from . import governance_monitoring as monitoring
from . import metadata_connectors as connectors


def _count_by(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts = Counter(str(item.get(key) or "unknown") for item in items)
    return dict(sorted(counts.items()))


def build_unified_overview(org_id: str) -> dict[str, Any]:
    """Return a bounded executive/operations snapshot for one organization."""
    if not isinstance(org_id, str) or not org_id.strip() or len(org_id) > 256:
        raise ValueError("a valid organization id is required")

    gov_summary = governance.summary(org_id)
    scans = governance.list_scans(org_id, 100)
    findings = governance.list_findings(org_id, limit=500)
    schedules = monitoring.list_schedules(org_id, 200)
    monitor_runs = monitoring.list_runs(org_id, limit=200)
    snapshots = connectors.list_snapshots(org_id, limit=200)
    changes = connectors.list_changes(org_id, limit=200)
    pending_approvals = audit.list_approvals(org_id, status="pending", limit=200)
    recent_events = audit.list_events(org_id, limit=20)
    audit_integrity = audit.verify_chain(org_id)

    risk_levels = _count_by(findings, "severity")
    finding_status = _count_by(findings, "status")
    enabled_schedules = sum(1 for item in schedules if item.get("enabled"))
    monitor_run_status = _count_by(monitor_runs, "status")
    provider_counts = _count_by(snapshots, "provider")

    change_risk = Counter()
    for item in changes:
        details = item.get("changes") if isinstance(item.get("changes"), dict) else {}
        risk = str(details.get("risk") or "unknown")
        change_risk[risk] += 1

    recent_scan_summaries = []
    for scan in scans[:10]:
        recent_scan_summaries.append({
            "id": scan.get("id"), "provider": scan.get("provider"),
            "risk_score": scan.get("risk_score"), "risk_level": scan.get("risk_level"),
            "finding_count": scan.get("finding_count"), "created_at": scan.get("created_at"),
        })

    # Expose only safe audit descriptors; omit payloads and hash internals.
    activity = [{
        "action": event.get("action"),
        "resource_type": event.get("resource_type"),
        "created_at": event.get("created_at"),
    } for event in recent_events[:10]]

    configured_provider_names = sorted({str(s.get("provider")) for s in snapshots if s.get("provider")})
    return {
        "organization_scope": "current_organization",
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "headline": {
            "governance_scans": int(gov_summary.get("scan_count", 0)),
            "open_findings": int(finding_status.get("open", 0)) + int(finding_status.get("in_progress", 0)),
            "critical_findings": int(risk_levels.get("critical", 0)),
            "pending_approvals": len(pending_approvals),
            "connected_source_providers": len(configured_provider_names),
            "enabled_monitoring_schedules": enabled_schedules,
        },
        "governance": {
            **gov_summary,
            "findings_by_severity": risk_levels,
            "findings_by_status": finding_status,
            "recent_scans": recent_scan_summaries,
        },
        "monitoring": {
            "schedule_count": len(schedules),
            "enabled_schedule_count": enabled_schedules,
            "run_count": len(monitor_runs),
            "runs_by_status": monitor_run_status,
            "recent_runs": [{k: run.get(k) for k in ("id", "schedule_id", "status", "risk_score", "finding_count", "started_at", "finished_at")} for run in monitor_runs[:10]],
        },
        "connectors": {
            "snapshot_count": len(snapshots),
            "providers_with_snapshots": configured_provider_names,
            "snapshots_by_provider": provider_counts,
            "schema_change_count": len(changes),
            "changes_by_risk": dict(sorted(change_risk.items())),
            "recent_snapshots": [{k: snap.get(k) for k in ("id", "provider", "table_count", "column_count", "created_at")} for snap in snapshots[:10]],
        },
        "approvals": {"pending_count": len(pending_approvals)},
        "audit": {
            "integrity_valid": bool(audit_integrity.get("valid")),
            "events_checked": int(audit_integrity.get("events_checked", 0)),
            "recent_activity": activity,
        },
        "limitations": [
            "This overview aggregates persisted M51-M55 records; it does not infer live source health or query source systems.",
            "Connector counts represent saved metadata snapshots, not necessarily currently reachable connections.",
            "Quality and lineage analyses that have not been persisted by their respective workflows are not included in these totals.",
            "Audit integrity verification is tamper-evidence, not protection against a privileged database administrator rewriting the entire chain.",
        ],
    }
