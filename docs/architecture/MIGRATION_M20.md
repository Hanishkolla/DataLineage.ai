# Milestone 20 database migration and recovery

## Automatic additive migration

The analysis run store adds a nullable `organization_id` column and an organization/project/time index using `CREATE TABLE IF NOT EXISTS`, `PRAGMA table_info`, and `ALTER TABLE`. It also creates the `organization_projects` table. Existing rows are retained.

The SaaS database creates organization-scoped GitHub connection metadata and analysis usage reservation tables. GitHub tokens are encrypted with Fernet using `DATALINEAGE_GITHUB_CREDENTIAL_KEY`.

On first authenticated workspace resolution, if the account has exactly one organization, legacy runs belonging to that account with a null organization ID are associated with that organization. If the account belongs to multiple organizations, migration is intentionally not guessed; an administrator must select and verify the correct destination before performing a controlled migration.

## Before upgrading

1. Stop the application.
2. Back up both SQLite files configured by `DATALINEAGE_DB_PATH` and `DATALINEAGE_SAAS_DB_PATH`, plus the users database configured by `DATALINEAGE_USERS_DB_PATH`.
3. Preserve the Fernet key separately in a secrets manager. Loss of this key makes encrypted organization GitHub credentials unrecoverable.
4. Install dependencies from `backend/requirements.txt`.
5. Start the application and verify readiness and tests.

## Rollback

Do not drop the new columns or tables as a rollback strategy. Stop the application and restore the pre-upgrade database backups as a matched set. Any organization records, projects, invitations, or usage created after the backup will not exist in the restored state. Preserve a copy of the upgraded databases for forensic recovery.
