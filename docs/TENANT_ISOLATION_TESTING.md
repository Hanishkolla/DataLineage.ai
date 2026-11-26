# DataLineage AI — M64 Tenant Isolation Validation

- Generated: `2026-11-13T10:02:48.502345+00:00`
- Status: **passed**
- Synthetic tenants: 2
- Checks: 12 passed / 0 failed

## Check results

| Check | Status | Detail |
|---|---|---|
| governance_scan_list_isolation | passed | Tenant Bravo cannot list Tenant Alpha governance scans |
| foreign_finding_update_rejected | passed | A foreign tenant cannot update a finding by guessed identifier |
| approval_list_isolation | passed | Approval records are visible only to their owning tenant |
| foreign_approval_decision_rejected | passed | A foreign tenant cannot decide another tenant's approval |
| audit_chain_tenant_scope | passed | Alpha audit chain verifies and Bravo has no Alpha audit events |
| monitor_schedule_isolation | passed | Governance monitor schedules are tenant-scoped |
| foreign_schedule_lookup_rejected | passed | A foreign tenant cannot retrieve a schedule by guessed identifier |
| connector_snapshot_isolation | passed | Connector metadata snapshots are tenant-scoped |
| connector_change_isolation | passed | Connector schema-change history is tenant-scoped |
| rbac_policy_isolation | passed | Alpha's restrictive analyst policy does not alter Bravo's default role ceiling |
| rbac_role_ceiling_enforced | passed | Tenant policy cannot elevate analyst above the platform role ceiling |
| tenant_summary_isolation | passed | Aggregated governance counts do not cross tenant boundaries |

## Limitations

- Uses isolated temporary SQLite databases; PostgreSQL multi-tenant behavior requires a separate live run.
- Validates persistence-layer tenant filters, not every FastAPI route or authentication middleware path.
- Does not constitute an independent penetration test or formal security certification.
- Synthetic metadata only; no customer SQL, credentials or production records are accessed.
