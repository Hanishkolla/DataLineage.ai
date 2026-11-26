"""Milestone 36: enterprise metadata, observability, governance and impact primitives.

Connectors in this milestone ingest normalized metadata/events supplied by exports or
trusted collectors. They do NOT open cloud connections or execute customer workloads.
"""
from __future__ import annotations
import re
from typing import Any

MAX_OBJECTS = 100_000
MAX_EVENTS = 50_000
PROVIDERS = {
    "azure", "aws", "gcp", "snowflake", "databricks", "bigquery",
    "postgresql", "sqlserver", "oracle", "dbt", "airflow", "azure_data_factory",
}
SENSITIVE_PATTERNS = {
    "email": re.compile(r"(?i)(email|e_mail|mail_address)"),
    "phone": re.compile(r"(?i)(phone|mobile|telephone)"),
    "person_name": re.compile(r"(?i)(first_name|last_name|full_name|customer_name)"),
    "government_identifier": re.compile(r"(?i)(ssn|national_id|aadhaar|passport)"),
    "payment_card": re.compile(r"(?i)(card_number|credit_card|pan_number)"),
    "financial_account": re.compile(r"(?i)(bank_account|account_number|iban)"),
    "credential": re.compile(r"(?i)(password|secret|access_token|api_key)"),
}

def _txt(v: Any, n: int = 500) -> str:
    return str(v or "").strip()[:n]

def normalize_metadata(payload: dict[str, Any], provider: str) -> dict[str, Any]:
    provider = _txt(provider, 80).lower()
    if provider not in PROVIDERS:
        raise ValueError(f"Unsupported provider. Supported providers: {', '.join(sorted(PROVIDERS))}")
    if not isinstance(payload, dict): raise ValueError("metadata must be an object")
    raw = payload.get("tables", payload.get("objects", []))
    if not isinstance(raw, list) or len(raw) > MAX_OBJECTS: raise ValueError("tables must be a bounded list")
    tables, seen = [], set()
    for item in raw:
        if not isinstance(item, dict): continue
        name = _txt(item.get("name") or item.get("table_name"), 300)
        schema = _txt(item.get("schema") or item.get("schema_name"), 300)
        database = _txt(item.get("database") or item.get("catalog"), 300)
        if not name: continue
        key = (database + "." + schema + "." + name).casefold()
        if key in seen: continue
        seen.add(key)
        raw_cols = item.get("columns", [])
        if not isinstance(raw_cols, list) or len(raw_cols) > 10_000: raise ValueError("columns must be a bounded list")
        cols = []
        for c in raw_cols:
            if isinstance(c, dict) and (c.get("name") or c.get("column_name")):
                cols.append({"name": _txt(c.get("name") or c.get("column_name"), 300),
                    "type": _txt(c.get("type") or c.get("data_type") or "unknown", 200),
                    "nullable": c.get("nullable"), "description": _txt(c.get("description"), 1000)})
        tables.append({"id": key, "name": name, "schema": schema, "database": database,
                       "columns": cols, "owner": _txt(item.get("owner"), 300),
                       "tags": item.get("tags", []) if isinstance(item.get("tags", []), list) else []})
    return {"provider": provider, "table_count": len(tables), "column_count": sum(len(t["columns"]) for t in tables),
            "tables": tables, "ingestion_mode": "metadata_snapshot", "live_connection": False,
            "warnings": ["Snapshot ingestion only; configure and validate a provider-specific collector for live synchronization."]}

def build_unified_lineage(sources: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(sources, list) or len(sources) > 500: raise ValueError("sources must be a bounded list")
    nodes, edges, warnings = {}, [], []
    for source in sources:
        if not isinstance(source, dict): continue
        provider = _txt(source.get("provider"), 80).lower()
        normalized = normalize_metadata(source.get("metadata", {}), provider)
        for table in normalized["tables"]:
            node_id = f"{provider}:{table['id']}"
            nodes[node_id] = {**table, "id": node_id, "provider": provider, "type": "table"}
        for edge in source.get("edges", []) if isinstance(source.get("edges", []), list) else []:
            if not isinstance(edge, dict): continue
            src, dst = _txt(edge.get("source"), 600), _txt(edge.get("target"), 600)
            if src and dst:
                edges.append({"source": src, "target": dst, "kind": _txt(edge.get("kind") or "data_dependency", 100), "provider": provider})
        warnings.extend(normalized["warnings"])
    return {"nodes": list(nodes.values()), "edges": edges, "node_count": len(nodes), "edge_count": len(edges),
            "warnings": sorted(set(warnings)), "lineage_semantics": "explicit supplied dependencies only; no inferred cross-system joins"}

def analyze_pipeline_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(events, list) or len(events) > MAX_EVENTS or any(not isinstance(e, dict) for e in events):
        raise ValueError("events must be a bounded list of objects")
    failed = [e for e in events if _txt(e.get("status")).lower() in {"failed", "error", "failure"}]
    results = []
    for e in failed:
        msg = _txt(e.get("message") or e.get("error"), 2000)
        low = msg.lower()
        if any(x in low for x in ("permission", "access denied", "unauthorized", "forbidden")):
            cause, action = "Permission or identity failure", "Verify workload identity, role assignments and least-privilege access."
        elif any(x in low for x in ("timeout", "timed out", "connection")):
            cause, action = "Connectivity or timeout", "Check network path, endpoint health, retry policy and workload duration."
        elif any(x in low for x in ("schema", "column", "type mismatch")):
            cause, action = "Schema or contract mismatch", "Compare source and target schemas; validate recent upstream changes."
        elif any(x in low for x in ("quota", "throttle", "rate limit")):
            cause, action = "Quota or throttling", "Inspect service quotas and concurrency; apply bounded backoff."
        else:
            cause, action = "Unclassified pipeline failure", "Inspect sanitized logs, recent deployments and upstream dependencies."
        results.append({"pipeline": _txt(e.get("pipeline") or e.get("job") or e.get("name"), 300),
            "timestamp": _txt(e.get("timestamp"), 80), "probable_cause": cause,
            "recommendation": action, "confidence": "heuristic", "evidence": msg[:500]})
    return {"event_count": len(events), "failure_count": len(failed), "failures": results,
            "note": "Rule-based triage of supplied events; not an autonomous diagnosis or live pipeline monitor."}

def classify_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_metadata(metadata, metadata.get("provider", "azure"))
    findings = []
    for table in normalized["tables"]:
        for col in table["columns"]:
            labels = [label for label, pattern in SENSITIVE_PATTERNS.items() if pattern.search(col["name"])]
            if labels:
                findings.append({"table": table["name"], "schema": table["schema"], "column": col["name"],
                                 "classifications": labels, "risk": "critical" if "credential" in labels or "payment_card" in labels else "high",
                                 "method": "column_name_heuristic", "review_required": True})
    return {"provider": normalized["provider"], "finding_count": len(findings), "findings": findings,
            "limitations": ["Name-based classification can miss sensitive values and create false positives; validate with approved content scanning and human review."]}

def evaluate_governance(metadata: dict[str, Any], policies: list[dict[str, Any]]) -> dict[str, Any]:
    normalized = normalize_metadata(metadata, metadata.get("provider", "azure"))
    if not isinstance(policies, list) or len(policies) > 1000: raise ValueError("policies must be a bounded list")
    findings = []
    for table in normalized["tables"]:
        for policy in policies:
            if not isinstance(policy, dict): continue
            required = _txt(policy.get("required_tag"), 100)
            if required and required not in table["tags"]:
                findings.append({"table": table["name"], "policy": _txt(policy.get("name") or required, 200),
                                 "status": "failed", "reason": f"Required tag '{required}' is missing"})
            if policy.get("require_owner") and not table["owner"]:
                findings.append({"table": table["name"], "policy": _txt(policy.get("name") or "owner_required", 200),
                                 "status": "failed", "reason": "Data owner is not assigned"})
    return {"provider": normalized["provider"], "evaluated_table_count": normalized["table_count"],
            "finding_count": len(findings), "findings": findings,
            "status": "passed" if not findings else "needs_attention",
            "note": "Evaluates only explicitly supplied metadata and policy rules."}

def simulate_impact(changed_object: str, edges: list[dict[str, Any]], objects: list[str] | None = None) -> dict[str, Any]:
    changed = _txt(changed_object, 600)
    if not changed: raise ValueError("changed_object is required")
    if not isinstance(edges, list) or len(edges) > 500_000: raise ValueError("edges must be a bounded list")
    graph: dict[str, set[str]] = {}
    for edge in edges:
        if isinstance(edge, dict):
            a, b = _txt(edge.get("source"), 600), _txt(edge.get("target"), 600)
            if a and b: graph.setdefault(a, set()).add(b)
    visited, frontier = set(), [changed]
    while frontier:
        cur = frontier.pop(0)
        for nxt in graph.get(cur, set()):
            if nxt not in visited and nxt != changed:
                visited.add(nxt); frontier.append(nxt)
    return {"changed_object": changed, "downstream_impact_count": len(visited),
            "downstream_objects": sorted(visited), "risk": "high" if len(visited) >= 20 else "medium" if visited else "low",
            "simulation": "graph_reachability_only", "note": "Does not execute changes or model runtime/business semantics."}

def copilot_answer(question: str, metadata: dict[str, Any]) -> dict[str, Any]:
    q = _txt(question, 2000).lower()
    normalized = normalize_metadata(metadata, metadata.get("provider", "azure"))
    matches = []
    for table in normalized["tables"]:
        haystack = " ".join([table["name"], table["schema"], *(c["name"] for c in table["columns"])]).lower()
        terms = [t for t in re.findall(r"[a-z0-9_]+", q) if len(t) > 2]
        score = sum(1 for t in terms if t in haystack)
        if score: matches.append((score, table))
    matches.sort(key=lambda x: (-x[0], x[1]["name"]))
    return {"answer": f"Found {len(matches)} metadata objects matching your question." if matches else "No matching objects were found in the supplied metadata snapshot.",
            "evidence": [{"table": t["name"], "schema": t["schema"], "columns": [c["name"] for c in t["columns"]]} for _, t in matches[:20]],
            "mode": "deterministic_metadata_retrieval", "limitations": ["This is not an LLM-based copilot and cannot answer beyond supplied metadata."]}
