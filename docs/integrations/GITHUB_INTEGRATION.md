# GitHub Integration — Milestone 17

## Current implementation scope

The backend includes a secure, read-only GitHub API helper, repository metadata lookup, SQL snapshot PR analysis endpoint, HMAC webhook verification, delivery replay guard, and a dashboard panel. The PR analysis endpoint accepts base/head SQL snapshots supplied by a trusted caller; it does not yet automatically enumerate a PR's changed files or fetch private file contents. This explicit boundary avoids claiming a fully live GitHub App installation.

## Environment variables

- `DATALINEAGE_GITHUB_TOKEN`: optional server-side fine-grained PAT for read-only repository metadata calls. Never put it in frontend code or commit it. Grant only Metadata: read and Contents: read / Pull requests: read if extending PR retrieval.
- `DATALINEAGE_GITHUB_API_URL`: optional; must remain `https://api.github.com` (default).
- `DATALINEAGE_GITHUB_WEBHOOK_SECRET`: optional webhook HMAC secret.
- `DATALINEAGE_GITHUB_ENFORCE`: optional boolean; defaults to false.
- `DATALINEAGE_GITHUB_CI_TOKEN`: optional high-entropy bearer token for trusted CI clients calling GitHub endpoints. Configure only in the server secret store and GitHub Actions secrets. When app authentication is enabled, this token is accepted only on `/api/v1/github/*`. Enforcement is not wired to merge blocking.

For production, prefer a GitHub App with repository-scoped installation permissions and short-lived installation tokens. Store private keys/secrets in a managed secret store. Rotate credentials.

## API

- `GET /api/v1/github/status`: returns configured state only; never returns token material.
- `GET /api/v1/github/repositories/{owner}/{repo}`: read-only repository metadata using the server token.
- `POST /api/v1/github/analyze`: accepts `{repository,base_branch,head_branch,pull_request_number,files:[{filename,base_content,head_content}]}`. File paths must be relative `.sql` paths. Content limit is 2 MiB per snapshot.
- `POST /api/v1/github/webhook`: verifies `X-Hub-Signature-256`, `X-GitHub-Delivery`, and `X-DataLineage-Timestamp`. Webhook processing is acknowledged but not yet connected to automatic PR ingestion.

All APIs inherit existing authentication middleware when authentication is enabled. SQL is parsed, never executed. Repository API paths are constructed internally; arbitrary URLs and redirects are rejected.

## GitHub Actions example

This starter workflow calls the snapshot-analysis API. A production workflow must securely obtain base/head SQL contents and pass them as JSON (for example through a trusted checked-out workspace script); do not echo secrets or SQL contents into logs. The sample is deliberately non-blocking and does not set commit status because the API does not yet expose a GitHub App check-run publisher.

```yaml
name: DataLineage AI SQL impact
on:
  pull_request:
    types: [opened, synchronize, reopened]
permissions:
  contents: read
  pull-requests: read
jobs:
  lineage-impact:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Prepare SQL snapshot payload
        env:
          BASE_SHA: ${{ github.event.pull_request.base.sha }}
          HEAD_SHA: ${{ github.event.pull_request.head.sha }}
        run: |
          python .github/scripts/create_lineage_payload.py "$BASE_SHA" "$HEAD_SHA" > lineage-payload.json
      - name: Analyze with DataLineage AI
        env:
          DATALINEAGE_API_URL: ${{ secrets.DATALINEAGE_API_URL }}
          DATALINEAGE_API_TOKEN: ${{ secrets.DATALINEAGE_API_TOKEN }}
        run: |
          curl --fail --silent --show-error \
            -H "Authorization: Bearer $DATALINEAGE_API_TOKEN" \
            -H "Content-Type: application/json" \
            --data-binary @lineage-payload.json \
            "$DATALINEAGE_API_URL/api/v1/github/analyze" \
            -o lineage-impact-result.json
      - name: Publish summary
        if: always()
        run: |
          if [ -f lineage-impact-result.json ]; then
            python -c "import json; d=json.load(open('lineage-impact-result.json')); print('Status:',d.get('status')); print('Changed SQL files:',d.get('changed_sql_files'))" >> "$GITHUB_STEP_SUMMARY"
          fi
```

The workflow uses the dedicated `DATALINEAGE_GITHUB_CI_TOKEN` bearer token, accepted only on `/api/v1/github/*` when normal application authentication is enabled. Set the same high-entropy value in the server secret store and the repository Actions secret `DATALINEAGE_API_TOKEN`. Keep it scoped to the CI integration and rotate it regularly.

## Limitations

- Live GitHub API metadata lookup is implemented but has not been tested against a real GitHub account in this environment.
- GitHub App installation/token exchange, automatic PR file retrieval, GitHub Check Runs publication, and merge enforcement are not implemented.
- PR analysis is based on supplied base/head snapshots; lexical table-reference differences are hints, not confirmed breakages.
- The webhook replay registry is process-local; multi-worker production requires shared persistent storage.
- Impact confidence is bounded by the SQL dialects and lineage constructs supported by the existing analyzer.
- No SQL is executed and no repository, branch, pull request, or merge is modified.


## Milestone 18: live pull-request retrieval (PAT-based initial integration)

The backend now exposes:
- `GET /api/v1/github/repositories` — paginated repositories visible to the configured token.
- `GET /api/v1/github/repositories/{owner}/{repo}/branches` — branches.
- `GET /api/v1/github/repositories/{owner}/{repo}/pulls` — pull requests.
- `POST /api/v1/github/analyze-pr` — retrieves PR metadata, changed SQL files, and base/head file contents using GitHub REST APIs, then invokes the existing SQL analyzer.
- `POST /api/v1/github/publish-check` — creates a Check Run on a commit. The token must have Checks: write; enforcement remains disabled unless explicitly configured.

### Configuration
Set `DATALINEAGE_GITHUB_TOKEN` in the backend environment (never in browser code). For repository and PR retrieval, use a fine-grained token limited to selected repositories with Metadata: read, Contents: read, and Pull requests: read. To publish Check Runs, add Checks: write. Prefer a GitHub App with narrowly scoped installation permissions for production; this release still uses a server-side fine-grained PAT and does not implement GitHub App JWT/installation-token exchange.

Also set:
- `DATALINEAGE_GITHUB_CI_TOKEN`: a high-entropy CI bearer token.
- `DATALINEAGE_GITHUB_API_URL`: must be the official `https://api.github.com`.
- `DATALINEAGE_GITHUB_ENFORCE=false`: default non-blocking policy.
- `DATALINEAGE_GITHUB_WEBHOOK_SECRET`: optional HMAC secret for webhook verification.

### Dashboard
Use **Load accessible repositories**, choose a repository, load open PRs, then choose a PR and select **Fetch and analyze selected PR**. Existing caller-supplied snapshot analysis remains available.

### Workflow
`.github/workflows/datalineage-impact.yml` calls the authenticated analyze-pr API. Configure repository Actions secrets `DATALINEAGE_API_URL` and `DATALINEAGE_API_TOKEN`. The workflow uses read-only backend analysis and does not merge, approve, or modify the PR. Publishing a GitHub Check Run is a separate API operation; this sample currently prints a short summary and does not automatically call publish-check.

### Limitations and security boundary
This milestone's real PR retrieval uses a server-side fine-grained PAT; GitHub App installation flow is a production follow-up. The Check Run API exists but must be called separately by a trusted CI orchestrator and requires Checks: write. API calls use fixed official GitHub API paths, bounded pagination, timeouts, and no redirects. Private repository content is returned only to the authenticated caller's API response; deploy with authentication enabled and per-user authorization before multi-tenant production. No SQL is executed. No GitHub repository contents, branches, PRs, or merges are modified.
