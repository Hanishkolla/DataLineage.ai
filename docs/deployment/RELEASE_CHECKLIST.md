# DataLineage AI Release Checklist

## A. Build and regression
- [ ] Extract the ZIP into a clean folder.
- [ ] Install dependencies from `backend/requirements.txt`.
- [ ] Run `py -m pytest -q tests` from `backend/`.
- [ ] Save test output, Python version and dependency versions.
- [ ] Build Docker image and start Compose successfully.
- [ ] Run `py smoke_test.py http://localhost:8000` from project root.

## B. Core product acceptance
- [ ] Upload SQL files and run lineage analysis.
- [ ] Validate table/column lineage and unsupported SQL warnings.
- [ ] Compare old/new SQL and verify added/removed tables and columns.
- [ ] Verify PR impact, risk labels and review comments using a test repository.
- [ ] Verify data quality profile and dataset comparison endpoints.
- [ ] Verify supported metadata import flows with known fixtures.

## C. Account and tenant safety
- [ ] Signup, login, logout and session expiry.
- [ ] Email verification and password reset with a test mailbox.
- [ ] Verify one tenant cannot read or modify another tenant's records.
- [ ] Verify role permissions for owner/admin/developer/viewer.
- [ ] Verify audit events do not contain passwords, tokens or secrets.
- [ ] Test billing only in payment-provider test mode.

## D. Operations and security
- [ ] HTTPS enabled; HTTP redirects or is blocked at the reverse proxy.
- [ ] Strong unique secrets stored outside source code.
- [ ] Exact CORS origins configured; no wildcard with credentials.
- [ ] Database backup schedule configured and restore tested.
- [ ] Logs, uptime alerts and error monitoring configured.
- [ ] File upload limits and rate limits reviewed.
- [ ] Dependency vulnerability review completed.
- [ ] Load and concurrency testing completed.
- [ ] Incident contact and rollback procedure documented.

## E. Pilot approval
- [ ] Pilot users use synthetic or approved non-sensitive data initially.
- [ ] Written scope, retention and support expectations agreed.
- [ ] Known limitations communicated to pilot users.
- [ ] Feedback and issue-tracking owner assigned.
- [ ] Go/no-go decision recorded.
