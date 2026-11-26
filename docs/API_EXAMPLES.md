# M40 API examples

## Copilot
```json
{
  "question": "Where is customer email stored?",
  "metadata": {"tables": [{"schema": "crm", "name": "customers", "columns": [{"name": "email"}]}]},
  "lineage_edges": [{"source": "crm.customers.email", "target": "mart.customer_email"}]
}
```

## Impact explanation
```json
{"changed_object": "raw.orders", "edges": [{"source": "raw.orders", "target": "staging.orders"}]}
```

## Incident summary
```json
{"incidents": [{"cause_code": "timeout", "severity": "high", "pipeline": "daily_load"}]}
```

## Risk assessment
```json
{"schema_changes": [{"risk": "high"}], "quality_findings": [{"severity": "high"}], "incidents": []}
```
