"""M64 repeatable tenant-isolation validation across persisted enterprise modules.

Runs against temporary SQLite databases only. It does not connect to customer data,
mutate a configured production database, or prove HTTP middleware isolation.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def run_tenant_isolation_suite(workdir: str | Path | None = None) -> dict[str, Any]:
    """Create two synthetic tenants and verify stored records stay tenant-scoped."""
    previous = {key: os.environ.get(key) for key in (
        "DATALINEAGE_DATABASE_URL", "DATALINEAGE_SAAS_DB_PATH", "DATALINEAGE_ACCESS_DB"
    )}
    owned_tmp = None
    try:
        if workdir is None:
            owned_tmp = tempfile.TemporaryDirectory(prefix="dla_m64_")
            root = Path(owned_tmp.name)
        else:
            root = Path(workdir).expanduser().resolve()
            root.mkdir(parents=True, exist_ok=True)
        # Explicitly isolate this exercise from any configured production database.
        os.environ.pop("DATALINEAGE_DATABASE_URL", None)
        os.environ["DATALINEAGE_SAAS_DB_PATH"] = str(root / "tenant-validation.sqlite3")
        os.environ["DATALINEAGE_ACCESS_DB"] = str(root / "access-validation.sqlite3")

        from app import governance_repository as governance
        from app import audit_approvals as audit
        from app import governance_monitoring as monitor
        from app import metadata_connectors as connectors
        from app import role_access_control as access

        checks: list[dict[str, Any]] = []

        def record(name: str, passed: bool, detail: str) -> None:
            checks.append({"name": name, "status": "passed" if passed else "failed", "detail": detail})
            if not passed:
                raise AssertionError(f"M64 tenant isolation check failed: {name}")

        a, b = "m64-tenant-alpha", "m64-tenant-bravo"
        sample = {
            "provider": "synthetic", "risk_score": 35, "risk_level": "medium",
            "finding_count": 1, "summary": {"metadata_objects": 2},
            "findings": [{"code": "OWNER_MISSING", "title": "Owner missing",
                "object": "sales.customers", "severity": "medium", "evidence": "Synthetic fixture",
                "remediation": "Assign owner", "status": "open"}],
        }
        scan = governance.save_scan(a, sample)
        record("governance_scan_list_isolation", len(governance.list_scans(a)) == 1 and governance.list_scans(b) == [],
               "Tenant Bravo cannot list Tenant Alpha governance scans")
        finding_id = governance.list_findings(a)[0]["id"]
        record("foreign_finding_update_rejected", governance.update_finding(b, finding_id, status="resolved") is None,
               "A foreign tenant cannot update a finding by guessed identifier")

        approval = audit.request_approval(a, "alpha-requester", "finding", finding_id,
                                          "accept_risk", "Synthetic M64 validation")
        record("approval_list_isolation", len(audit.list_approvals(a)) == 1 and audit.list_approvals(b) == [],
               "Approval records are visible only to their owning tenant")
        foreign_decision = audit.decide_approval(b, approval["id"], "bravo-reviewer", "approved", "cross-tenant probe")
        record("foreign_approval_decision_rejected", foreign_decision is None,
               "A foreign tenant cannot decide another tenant's approval")
        record("audit_chain_tenant_scope", audit.verify_chain(a)["valid"] and audit.list_events(b) == [],
               "Alpha audit chain verifies and Bravo has no Alpha audit events")

        schedule = monitor.create_schedule(a, "alpha-admin", {
            "name": "Alpha synthetic schedule", "interval_minutes": 60,
            "metadata": {"provider": "azure", "tables": [{"name": "customers", "columns": ["id", "email"]}]},
            "edges": [],
        })
        record("monitor_schedule_isolation", len(monitor.list_schedules(a)) == 1 and monitor.list_schedules(b) == [],
               "Governance monitor schedules are tenant-scoped")
        record("foreign_schedule_lookup_rejected", monitor.get_schedule(b, schedule["id"]) is None,
               "A foreign tenant cannot retrieve a schedule by guessed identifier")

        snapshot = connectors.save_snapshot(a, "alpha-admin", {
            "provider": "snowflake", "tables": [{"schema": "PUBLIC", "name": "CUSTOMERS",
                "columns": [{"name": "ID", "type": "NUMBER"}, {"name": "EMAIL", "type": "VARCHAR"}]}],
        })
        record("connector_snapshot_isolation", len(connectors.list_snapshots(a)) == 1 and connectors.list_snapshots(b) == [],
               "Connector metadata snapshots are tenant-scoped")
        record("connector_change_isolation", len(connectors.list_changes(a)) >= 1 and connectors.list_changes(b) == [],
               "Connector schema-change history is tenant-scoped")

        access.save_role_policy(a, "alpha-owner", "analyst", ["lineage.read"])
        alpha_perms = access.effective_permissions(a, "analyst")
        bravo_perms = access.effective_permissions(b, "analyst")
        record("rbac_policy_isolation", alpha_perms == {"lineage.read"} and "audit.read" in bravo_perms,
               "Alpha's restrictive analyst policy does not alter Bravo's default role ceiling")
        record("rbac_role_ceiling_enforced", not access.authorize(a, "analyst", "security.manage"),
               "Tenant policy cannot elevate analyst above the platform role ceiling")

        summary = governance.summary(a)
        record("tenant_summary_isolation", summary["scan_count"] == 1 and governance.summary(b)["scan_count"] == 0,
               "Aggregated governance counts do not cross tenant boundaries")

        return {
            "milestone": "M64",
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "status": "passed" if all(x["status"] == "passed" for x in checks) else "failed",
            "synthetic_tenants": 2,
            "checks_passed": sum(x["status"] == "passed" for x in checks),
            "checks_failed": sum(x["status"] == "failed" for x in checks),
            "checks": checks,
            "limitations": [
                "Uses isolated temporary SQLite databases; PostgreSQL multi-tenant behavior requires a separate live run.",
                "Validates persistence-layer tenant filters, not every FastAPI route or authentication middleware path.",
                "Does not constitute an independent penetration test or formal security certification.",
                "Synthetic metadata only; no customer SQL, credentials or production records are accessed.",
            ],
        }
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if owned_tmp is not None:
            owned_tmp.cleanup()


def render_markdown(report: dict[str, Any]) -> str:
    lines = ["# DataLineage AI — M64 Tenant Isolation Validation", "",
             f"- Generated: `{report['generated_at_utc']}`",
             f"- Status: **{report['status']}**",
             f"- Synthetic tenants: {report['synthetic_tenants']}",
             f"- Checks: {report['checks_passed']} passed / {report['checks_failed']} failed", "",
             "## Check results", "", "| Check | Status | Detail |", "|---|---|---|"]
    for check in report["checks"]:
        detail = check["detail"].replace("|", "\\|")
        lines.append(f"| {check['name']} | {check['status']} | {detail} |")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Run isolated two-tenant validation")
    parser.add_argument("--workdir", help="Optional directory for temporary validation DBs")
    parser.add_argument("--json-out", help="Write JSON report")
    parser.add_argument("--markdown-out", help="Write Markdown report")
    args = parser.parse_args(argv)
    report = run_tenant_isolation_suite(args.workdir)
    payload = json.dumps(report, indent=2)
    if args.json_out:
        Path(args.json_out).expanduser().write_text(payload + "\n", encoding="utf-8")
    if args.markdown_out:
        Path(args.markdown_out).expanduser().write_text(render_markdown(report), encoding="utf-8")
    print(payload)
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
