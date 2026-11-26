"""M51 governance-aware data risk assessment over supplied metadata and lineage.

Deterministic metadata-only analysis. It never reads row values or connects to sources.
"""
from __future__ import annotations
from collections import defaultdict, deque
from typing import Any
from .metadata_governance import normalize_metadata, classify_metadata

MAX_EDGES = 250_000
MAX_POLICIES = 1_000
MAX_OBJECTS = 100_000

DEFAULT_CONTROLS = [
    {"id":"owner_required", "name":"Data owner assigned", "severity":"medium", "kind":"owner"},
    {"id":"classification_required", "name":"Sensitive data classified", "severity":"high", "kind":"classification"},
    {"id":"sensitive_lineage", "name":"Sensitive data lineage documented", "severity":"high", "kind":"lineage"},
]

SEVERITY_POINTS = {"low": 5, "medium": 12, "high": 22, "critical": 30}

def _s(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]

def assess_governance_risk(metadata: dict[str, Any], edges: list[dict[str, Any]] | None = None,
                           policies: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be an object")
    normalized = normalize_metadata(metadata, metadata.get("provider", "azure"))
    tables = normalized["tables"]
    if len(tables) > MAX_OBJECTS:
        raise ValueError("metadata object limit exceeded")
    edges = [] if edges is None else edges
    policies = DEFAULT_CONTROLS if policies is None else policies
    if not isinstance(edges, list) or len(edges) > MAX_EDGES:
        raise ValueError("edges must be a bounded list")
    if not isinstance(policies, list) or len(policies) > MAX_POLICIES:
        raise ValueError("policies must be a bounded list")

    table_by_id = {t["id"].casefold(): t for t in tables}
    table_by_name = {t["name"].casefold(): t for t in tables}
    sensitive = classify_metadata(metadata)
    sensitive_by_table: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in sensitive["findings"]:
        key = (f"{finding.get('schema') or ''}.{finding['table']}").strip('.').casefold()
        sensitive_by_table[key].append(finding)
        sensitive_by_table[finding['table'].casefold()].append(finding)

    graph: dict[str, set[str]] = defaultdict(set)
    reverse: dict[str, set[str]] = defaultdict(set)
    valid_edges = []
    for edge in edges:
        if not isinstance(edge, dict):
            continue
        src, dst = _s(edge.get("source"), 600), _s(edge.get("target"), 600)
        if not src or not dst:
            continue
        graph[src.casefold()].add(dst.casefold())
        reverse[dst.casefold()].add(src.casefold())
        valid_edges.append({"source":src,"target":dst})

    # Build case-insensitive aliases for metadata identifiers and plain table names.
    aliases = {}
    for t in tables:
        aliases[t["id"].casefold()] = t["id"].casefold()
        aliases[t["name"].casefold()] = t["id"].casefold()
        qualified = '.'.join(x for x in (t.get('database'),t.get('schema'),t['name']) if x)
        aliases[qualified.casefold()] = t["id"].casefold()
    normalized_graph: dict[str, set[str]] = defaultdict(set)
    for src, targets in graph.items():
        a = aliases.get(src, src)
        for dst in targets:
            b = aliases.get(dst, dst)
            normalized_graph[a].add(b)

    findings = []
    def add(code: str, title: str, object_name: str, severity: str, evidence: str, remediation: str):
        findings.append({"code":code,"title":title,"object":object_name,"severity":severity,
                         "evidence":evidence[:1000],"remediation":remediation,"status":"open"})

    for table in tables:
        name = table["name"]
        has_sensitive = bool(sensitive_by_table.get(name.casefold())) or any(
            f"{table.get('schema') or ''}.{name}".strip('.').casefold() == k
            for k in sensitive_by_table)
        if not table.get("owner"):
            add("OWNER_MISSING","Data owner is not assigned",name,"medium",
                "Metadata snapshot contains no owner value.","Assign a accountable data owner and review cadence.")
        if has_sensitive and not table.get("tags"):
            add("SENSITIVE_TAG_MISSING","Sensitive data has no governance tags",name,"high",
                "Column-name heuristic identified potentially sensitive fields; table has no tags.",
                "Validate classification and apply approved sensitivity, retention and access tags.")
        if has_sensitive and not normalized_graph.get(table["id"].casefold()):
            add("SENSITIVE_LINEAGE_GAP","Sensitive object has no outgoing lineage edge",name,"high",
                "No downstream edge was supplied for this object; this may indicate incomplete lineage.",
                "Connect trusted lineage collectors and validate upstream/downstream dependencies.")

    for policy in policies:
        if not isinstance(policy, dict):
            raise ValueError("each policy must be an object")
        control_id = _s(policy.get("id"),100)
        if not control_id:
            raise ValueError("each policy requires an id")
        kind = _s(policy.get("kind"),80).lower()
        severity = _s(policy.get("severity") or "medium",20).lower()
        if severity not in SEVERITY_POINTS:
            raise ValueError(f"invalid severity for policy {control_id}")
        for table in tables:
            failed = False; evidence = ""; remediation = _s(policy.get("remediation"),1000)
            if kind == "owner":
                failed = bool(policy.get("required", True)) and not table.get("owner")
                evidence = "No owner supplied in metadata."
                remediation = remediation or "Assign an accountable owner."
            elif kind == "required_tag":
                tag = _s(policy.get("tag"),100)
                if not tag: raise ValueError(f"policy {control_id} requires tag")
                failed = tag not in table.get("tags", [])
                evidence = f"Required tag '{tag}' is absent."
                remediation = remediation or f"Apply and validate the '{tag}' tag."
            elif kind == "classification":
                failed = bool(policy.get("require_sensitive_tags", True)) and bool(sensitive_by_table.get(table['name'].casefold())) and not table.get("tags")
                evidence = "Potentially sensitive column names found but no tags supplied."
                remediation = remediation or "Review the heuristic classification and apply approved tags."
            elif kind == "lineage":
                is_sensitive = bool(sensitive_by_table.get(table["name"].casefold()))
                table_key = table["id"].casefold()
                failed = bool(policy.get("require_sensitive_lineage", True)) and is_sensitive and not normalized_graph.get(table_key)
                evidence = "Potentially sensitive object has no supplied outgoing lineage edge."
                remediation = remediation or "Connect trusted lineage collectors and validate dependencies."
            elif kind == "allowed_provider":
                allowed = policy.get("providers", [])
                if not isinstance(allowed, list): raise ValueError("providers must be a list")
                failed = normalized["provider"] not in [str(x).lower() for x in allowed]
                evidence = f"Provider '{normalized['provider']}' is not in the policy allowlist."
                remediation = remediation or "Move the workload to an approved provider or update policy through governance review."
            else:
                raise ValueError(f"unsupported policy kind: {kind}")
            if failed:
                add("POLICY_"+control_id.upper(),_s(policy.get("name") or control_id,200),table["name"],severity,evidence,remediation)

    # Propagate sensitive-data exposure to reachable downstream nodes using explicit edges only.
    sensitive_sources = {t["id"].casefold() for t in tables if sensitive_by_table.get(t["name"].casefold())}
    propagated = set()
    for source in sensitive_sources:
        queue = deque(normalized_graph.get(source, set())); seen = set()
        while queue:
            node = queue.popleft()
            if node in seen or node == source: continue
            seen.add(node); propagated.add(node)
            queue.extend(normalized_graph.get(node, set()) - seen)
    for node in sorted(propagated):
        if node not in table_by_id:
            continue
        table = table_by_id[node]
        add("SENSITIVE_DATA_PROPAGATED","Downstream object may contain sensitive-derived data",table["name"],"medium",
            "Reachable from an object with potentially sensitive column names through supplied lineage edges.",
            "Validate column-level propagation and apply access, masking and retention controls as appropriate.")

    # Deduplicate identical code/object findings while preserving first evidence.
    unique = {}
    for f in findings:
        unique.setdefault((f["code"],f["object"].casefold()), f)
    findings = list(unique.values())
    raw_score = sum(SEVERITY_POINTS[f["severity"]] for f in findings)
    score = min(100, raw_score)
    level = "critical" if score >= 75 else "high" if score >= 45 else "medium" if score >= 20 else "low"
    return {"provider":normalized["provider"],"risk_score":score,"risk_level":level,
        "finding_count":len(findings),"findings":findings,
        "summary":{"metadata_objects":len(tables),"lineage_edges":len(valid_edges),
                   "potentially_sensitive_objects":len(sensitive_sources),"downstream_sensitive_objects":len(propagated),
                   "controls_evaluated":len(policies)},
        "method":"deterministic_metadata_and_explicit_lineage_rules",
        "limitations":["Classification uses column-name heuristics, not content inspection.",
          "Lineage propagation uses only supplied edges and cannot prove actual data movement.",
          "Risk score is a prioritization heuristic, not a compliance certification or probability of breach.",
          "Human review is required before enforcing access, retention or regulatory decisions."]}
