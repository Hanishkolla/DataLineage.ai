# DataLineage AI SaaS foundation (Milestone 19)

## Scope and safety
This milestone adds an isolated SQLite SaaS metadata store (`DATALINEAGE_SAAS_DB_PATH`, default `backend/data/saas.sqlite3`). It does not activate payment processing. Plan prices are configuration values only. No card or bank details are collected.

## Organizations and roles
Organizations have UUID identifiers and memberships keyed by organization and normalized email. Owner/Admin operations are checked in the store layer; Developers can record analysis usage; Viewers can read the organization summary and member list. Invitation secrets are random, stored as SHA-256 hashes, expire after seven days, are bound to the invited email, and are single-use. Invitation tokens are stored only as SHA-256 hashes. The API does not return the raw token; it is delivered through the configured email channel and is carried in the URL fragment for acceptance. Do not log or persist it in frontend storage.

## Plans and usage
Plans are defined in `backend/app/saas_store.py`. Usage events use an organization-scoped idempotency key and a UTC calendar-month period. SQLite `BEGIN IMMEDIATE` protects the analysis quota check-and-insert against concurrent writers. Current enforced quota is monthly successful analysis events. Other metric categories are recorded for reporting.

## Billing readiness
Subscription rows and billing event metadata are stored. `process_mock_event` is a test/mock ingestion path with provider/event uniqueness. `verify_webhook_signature` exposes an HMAC-SHA256 verification primitive. No live Razorpay or Stripe client, webhook route, invoice issuance, payment capture, or customer billing action is enabled.

## Remaining integration limitations
Authenticated analysis runs and project history are now organization-scoped, and user GitHub REST requests use encrypted organization credentials. The deployment-managed CI bearer workflow remains separate and still uses a server credential; repository-to-tenant binding for CI/webhooks needs additional deployment-specific controls. Browser-generated HTML report downloads are not server-metered. The in-process action limiter must be backed by a shared gateway/Redis limiter in a multi-instance deployment. The complete legacy suite and browser-level end-to-end tests must pass before production use.

## API
- `GET/POST /api/v1/organizations`
- `GET/PATCH /api/v1/organizations/{org_id}`
- `GET /api/v1/organizations/{org_id}/members`
- `POST /api/v1/organizations/{org_id}/invitations`
- `POST /api/v1/organizations/invitations/accept`
- `DELETE /api/v1/organizations/{org_id}/invitations/{invitation_id}`
- `GET /api/v1/organizations/{org_id}/subscription`
- `POST /api/v1/organizations/{org_id}/subscription/plan`
- `POST /api/v1/organizations/{org_id}/usage`
- `GET /api/v1/organizations/{org_id}/billing/history`
- `GET /api/v1/saas/plans`

Organization APIs require a verified signed-in account. Production still requires the existing secure auth, cookie, HTTPS, CORS and email settings.


## Milestone 20 integration notes

- Analysis run records now include nullable `organization_id`; startup migration adds the column and index without dropping legacy rows. The first authenticated personal-workspace resolution associates the user's pre-existing account-owned runs with that workspace.
- Project records use `(organization_id, name)` uniqueness. Project list/create APIs check membership and plan limits.
- Analysis history, single-run retrieval and run comparison accept only the active organization scope for authenticated users. A multi-workspace user must send `X-Organization-ID`.
- Monthly analysis capacity uses SQLite `BEGIN IMMEDIATE` reservations so concurrent analyses cannot reserve beyond the plan cap. Successful parsing commits usage; failed requests release reservations.
- Owner-only role management protects the owner role; the final owner cannot be removed. Pending invitations count toward the member cap, and acceptance rechecks the cap.
- Organization GitHub tokens are Fernet-encrypted at rest and only decrypted server-side for requests. Tokens are not returned in connection metadata. Configure `DATALINEAGE_GITHUB_CREDENTIAL_KEY` before connecting GitHub.
- Existing CI bearer integration remains deployment-managed and uses the server-side GitHub token; it is not a user workspace connection.
- Client-generated HTML report downloads are not server-metered because the report is created in the browser.
- Billing remains simulated/metadata-only. No card data, live subscriptions, or charges are processed.

- Usage summaries include current-period metric totals, project/member counts, and 80% threshold warnings. Historical usage is available through the organization usage-history endpoint.

- Owners can activate one 14-day (configurable 1–30 days) internal trial per organization. Trial activation is recorded and cannot be repeated for the same organization.
- If an account has multiple workspaces before its legacy history was migrated, an owner can explicitly select the destination workspace using the legacy-history migration endpoint.

- Authenticated organization creation, invitations, and GitHub credential updates have per-identity in-process throttles. The deployment proxy or a shared Redis limiter must enforce equivalent limits across multiple application instances.
