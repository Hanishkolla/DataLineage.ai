# DataLineage AI — Enterprise Upgrade Notes (M35 → M36)

## What changed
M36 adds backend API foundations and a Kubernetes starter. Existing M35 files and routes were retained. No existing production data or credentials were included.

## Run locally (Windows PowerShell)
```powershell
cd backend
py -m pip install -r requirements.txt
py -m pytest -q tests
py -m uvicorn app.main:app --reload
```
Open `http://127.0.0.1:8000/docs` and inspect the `/api/v1/enterprise/*` endpoints.

## First metadata test
POST to `/api/v1/enterprise/connectors/snowflake/metadata`:
```json
{
  "tables": [
    {"database":"ANALYTICS","schema":"PUBLIC","name":"CUSTOMERS","columns":[
      {"name":"CUSTOMER_ID","type":"NUMBER"},
      {"name":"EMAIL_ADDRESS","type":"VARCHAR"}
    ]}
  ]
}
```

## Required next engineering work before enterprise sales
1. Build real provider adapters one at a time (Azure/AWS identity, Snowflake, Databricks, BigQuery), with read-only scopes, secret-manager integration, pagination, incremental sync, retries and connector health.
2. Persist metadata, lineage, connector state and audit events in a production database; replace process-local jobs/cache with a shared queue/cache.
3. Add tenant-scoped authorization and object-level access checks to every enterprise endpoint; verify isolation with adversarial tests.
4. Implement SQL AST column-level lineage across dialects and validate against customer golden datasets.
5. Add streaming pipeline events, alert delivery, SLOs, deduplication and incident timelines.
6. Add content-aware sensitive-data discovery, configurable classification policies, approvals and audit exports.
7. Build a real LLM copilot with retrieval, citations, permission filtering, prompt-injection defenses and evaluation; do not send customer metadata to external models without explicit customer controls.
8. Add frontend workflows for connector setup, lineage exploration, incidents, policy management and access reviews.
9. Complete threat modeling, independent penetration test, load/chaos tests, disaster-recovery drills, compliance mapping and customer pilots.

A high acquisition valuation depends on measurable adoption, retention, ARR, differentiated technology, low-risk security posture and strategic buyer demand—not the number of modules or API routes.
