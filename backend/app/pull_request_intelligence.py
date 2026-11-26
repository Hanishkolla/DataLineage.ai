"""Milestone 26: structured SQL change intelligence for GitHub pull requests.

This module performs static parsing only. It never executes submitted SQL.
"""
from __future__ import annotations

from typing import Any

from .sql_change_intelligence import compare_sql_changes

_RANK = {"low": 1, "medium": 2, "high": 3}


def analyze_pr_sql_changes(snapshots: list[dict[str, Any]], dialect: str = "") -> dict[str, Any]:
    """Compare each changed SQL file and produce an aggregate review summary.

    Missing base/head content is represented as an unparsed file instead of
    being guessed. Parse errors are isolated to their file so one unsupported
    SQL dialect does not discard the rest of the PR report.
    """
    files: list[dict[str, Any]] = []
    counts = {"analyzed": 0, "unparsed": 0, "added": 0, "removed": 0}
    risk_level = "low"
    risk_score = 0
    recommended_tests: list[str] = []
    for item in snapshots:
        filename = item.get("filename")
        before, after = item.get("base_content"), item.get("head_content")
        if before is None or after is None:
            state = "added" if before is None else "removed"
            counts[state] += 1
            files.append({"filename": filename, "status": state,
                          "message": "File exists on only one side of the pull request; SQL comparison requires both snapshots."})
            continue
        try:
            result = compare_sql_changes(before, after, dialect)
            counts["analyzed"] += 1
            level = result.get("risk", {}).get("level", "low")
            score = int(result.get("risk", {}).get("score", 0))
            if _RANK.get(level, 0) > _RANK.get(risk_level, 0):
                risk_level = level
            risk_score = max(risk_score, score)
            for test in result.get("recommended_tests", []):
                if test not in recommended_tests:
                    recommended_tests.append(test)
            files.append({"filename": filename, "status": "analyzed", "comparison": result})
        except (ValueError, TypeError) as exc:
            counts["unparsed"] += 1
            files.append({"filename": filename, "status": "unparsed", "message": str(exc),
                          "action": "Confirm the SQL dialect or syntax manually; no impact was inferred for this file."})
    if counts["unparsed"] and _RANK[risk_level] < _RANK["medium"]:
        risk_level = "medium"
    if not recommended_tests:
        recommended_tests.append("Run the project's SQL compilation and representative downstream tests before merging.")
    return {
        "status": "completed" if counts["analyzed"] or counts["added"] or counts["removed"] else "no_sql_comparisons",
        "risk": {"level": risk_level, "score": risk_score,
                 "explanation": "Highest per-file static SQL risk. Unparsed SQL raises the review level to at least Medium; this is not a probability of production failure."},
        "counts": counts,
        "files": files,
        "recommended_tests": recommended_tests,
        "limitations": [
            "Static SQL parsing only; statements are never executed.",
            "Risk is a review-priority heuristic, not a production-failure probability.",
            "Unparsed SQL is explicitly flagged and must be reviewed manually.",
            "Downstream runtime lineage and live data-quality checks require separately configured metadata or data connections.",
        ],
    }
