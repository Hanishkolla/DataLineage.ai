
"""Milestone 27 GitHub review policy and safe PR summary formatting."""
from __future__ import annotations
from typing import Any

_LEVEL = {"low": 1, "medium": 2, "high": 3}

def evaluate_review_policy(report: dict[str, Any], policy: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = policy or {}
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    mode = policy.get("mode", "advisory")
    if mode not in {"advisory", "strict"}:
        raise ValueError("policy.mode must be advisory or strict")
    threshold = str(policy.get("manual_review_from", "high")).lower()
    if threshold not in _LEVEL:
        raise ValueError("manual_review_from must be low, medium, or high")
    change = report.get("change_intelligence") or {}
    risk = (change.get("risk") or {}).get("level", "low")
    if str(risk).lower() not in _LEVEL:
        risk = "medium"
    files = change.get("files") or []
    unparsed = any(isinstance(f, dict) and f.get("status") == "unparsed" for f in files)
    manual = _LEVEL[str(risk).lower()] >= _LEVEL[threshold] or unparsed
    reasons = []
    if _LEVEL[str(risk).lower()] >= _LEVEL[threshold]:
        reasons.append(f"{str(risk).title()} risk meets the configured manual-review threshold.")
    if unparsed:
        reasons.append("One or more SQL files could not be parsed and require manual review.")
    conclusion = "success"
    if mode == "strict" and (str(risk).lower() == "high" or unparsed):
        conclusion = "failure"
    elif manual:
        conclusion = "neutral"
    return {
        "mode": mode, "manual_review_required": manual, "reasons": reasons,
        "risk_level": str(risk).lower(), "unparsed_sql": unparsed,
        "check_conclusion": conclusion,
        "note": "A failed check is advisory unless GitHub branch protection requires this check."
    }

def format_pr_comment(report: dict[str, Any], policy_result: dict[str, Any]) -> str:
    """Build a bounded, non-sensitive comment. Never echo raw SQL or credentials."""
    change = report.get("change_intelligence") or {}
    risk = (change.get("risk") or {}).get("level", policy_result.get("risk_level", "unknown"))
    counts = change.get("counts") or {}
    lines = [
        "## DataLineage AI — SQL Change Review",
        "",
        f"**Overall risk:** {str(risk).upper()}",
        f"**Review policy:** {policy_result.get('mode', 'advisory')}",
        f"**Manual review required:** {'Yes' if policy_result.get('manual_review_required') else 'No'}",
        "",
        "### Changed SQL files",
        f"- Analyzed: {int(counts.get('analyzed', 0) or 0)}",
        f"- Unparsed / manual review: {int(counts.get('unparsed', 0) or 0)}",
        f"- Added files: {int(counts.get('added', 0) or 0)}",
        f"- Removed files: {int(counts.get('removed', 0) or 0)}",
    ]
    added, removed, added_cols, removed_cols = [], [], [], []
    for item in change.get("files", []) if isinstance(change.get("files"), list) else []:
        cmp = item.get("comparison") if isinstance(item, dict) else None
        if not isinstance(cmp, dict): continue
        changes = cmp.get("changes") or {}
        added.extend(changes.get("added_tables", []) or [])
        removed.extend(changes.get("removed_tables", []) or [])
        added_cols.extend(changes.get("added_columns", []) or [])
        removed_cols.extend(changes.get("removed_columns", []) or [])
    for heading, values in [
        ("Added table references", added), ("Removed table references", removed),
        ("Added columns", added_cols), ("Removed columns", removed_cols)
    ]:
        if values:
            lines += ["", f"### {heading}"] + [f"- `{str(x)[:160]}`" for x in sorted(set(values))[:20]]
    if policy_result.get("reasons"):
        lines += ["", "### Review warnings"] + [f"- {str(x)[:300]}" for x in policy_result["reasons"][:10]]
    tests = change.get("recommended_tests") or []
    if tests:
        lines += ["", "### Recommended tests"] + [f"- {str(x)[:300]}" for x in tests[:10]]
    lines += ["", "> Static analysis only. SQL was not executed. Risk is a review-priority heuristic, not a prediction of production failure.",
              "> Configure GitHub branch protection separately if this check must be required before merging."]
    return "\\n".join(lines)[:60000]

def check_run_payload(head_sha: str, report: dict[str, Any], policy_result: dict[str, Any]) -> dict[str, Any]:
    change = report.get("change_intelligence") or {}
    counts = change.get("counts") or {}
    summary = "\\n".join([
        f"Overall SQL risk: {policy_result.get('risk_level', 'unknown').upper()}",
        f"Analyzed SQL files: {int(counts.get('analyzed', 0) or 0)}",
        f"Unparsed SQL files: {int(counts.get('unparsed', 0) or 0)}",
        f"Manual review required: {'Yes' if policy_result.get('manual_review_required') else 'No'}",
        policy_result.get("note", ""),
    ])[:60000]
    return {"name": "DataLineage AI SQL Change Review", "head_sha": head_sha,
            "status": "completed", "conclusion": policy_result["check_conclusion"],
            "output": {"title": "SQL change impact review", "summary": summary}}
