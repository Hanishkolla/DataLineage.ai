"""Milestone 32: deterministic data quality profiling and validation."""
from __future__ import annotations
from collections import Counter
from typing import Any

MAX_ROWS=200_000
MAX_COLUMNS=2_000

def profile_dataset(rows: list[dict[str,Any]], required_columns: list[str] | None = None,
                    unique_columns: list[str] | None = None,
                    allowed_values: dict[str,list[Any]] | None = None) -> dict[str,Any]:
    if not isinstance(rows,list) or len(rows)>MAX_ROWS or any(not isinstance(r,dict) for r in rows):
        raise ValueError("rows must be a bounded list of row objects")
    required_columns=required_columns or []
    unique_columns=unique_columns or []
    allowed_values=allowed_values or {}
    if not all(isinstance(x,str) and x for x in required_columns+unique_columns):
        raise ValueError("column names must be non-empty strings")
    columns=sorted({str(k) for row in rows for k in row})
    if len(columns)>MAX_COLUMNS: raise ValueError("dataset contains too many columns")
    total=len(rows); checks=[]; issues=0
    for col in columns:
        values=[r.get(col) for r in rows]
        null_count=sum(v is None or (isinstance(v,str) and not v.strip()) for v in values)
        non_null=[v for v in values if v is not None and not (isinstance(v,str) and not v.strip())]
        duplicates=len(non_null)-len({(type(v).__name__,repr(v)) for v in non_null})
        checks.append({"column":col,"row_count":total,"null_count":null_count,
            "null_rate_pct":round(null_count*100/total,2) if total else 0,
            "distinct_count":len({(type(v).__name__,repr(v)) for v in non_null}),
            "duplicate_value_count":duplicates,
            "inferred_types":sorted({type(v).__name__ for v in non_null})})
    by_col={x["column"]:x for x in checks}
    for col in required_columns:
        if col not in columns:
            checks.append({"column":col,"check":"required_column","status":"failed","failure_count":total or 1,"message":"Required column is missing"})
        else:
            count=by_col[col]["null_count"]
            checks.append({"column":col,"check":"required_column","status":"failed" if count else "passed","failure_count":count,"message":"Required values must not be null or blank"})
    for col in unique_columns:
        if col not in columns:
            checks.append({"column":col,"check":"uniqueness","status":"failed","failure_count":total or 1,"message":"Unique-key column is missing"})
        else:
            count=by_col[col]["duplicate_value_count"]
            checks.append({"column":col,"check":"uniqueness","status":"failed" if count else "passed","failure_count":count,"message":"Values must be unique"})
    for col, allowed in allowed_values.items():
        if not isinstance(allowed,list): raise ValueError("allowed_values entries must be lists")
        invalid=sum(1 for r in rows if col in r and r[col] is not None and r[col] not in allowed)
        checks.append({"column":col,"check":"allowed_values","status":"failed" if invalid else "passed","failure_count":invalid,"message":"Values must belong to the configured allowed set"})
    failed=[x for x in checks if x.get("status")=="failed"]
    score=100 if not checks else round((len(checks)-len(failed))*100/len(checks),2)
    return {"row_count":total,"column_count":len(columns),"column_profiles":by_col,
        "checks":checks,"failed_check_count":len(failed),"quality_score_pct":score,
        "status":"passed" if not failed else "needs_attention",
        "limitations":["Profile is based only on the supplied in-memory rows; it does not prove source-system completeness or monitor future freshness."]}

def compare_dataset_rows(source_rows: list[dict[str,Any]], target_rows: list[dict[str,Any]]) -> dict[str,Any]:
    source=profile_dataset(source_rows); target=profile_dataset(target_rows)
    source_cols=set(source["column_profiles"]); target_cols=set(target["column_profiles"])
    delta=target["row_count"]-source["row_count"]
    pct=round(delta*100/source["row_count"],2) if source["row_count"] else (0 if not target["row_count"] else None)
    return {"source_row_count":source["row_count"],"target_row_count":target["row_count"],
        "row_count_delta":delta,"row_count_change_pct":pct,
        "added_columns":sorted(target_cols-source_cols),"removed_columns":sorted(source_cols-target_cols),
        "source_quality_score_pct":source["quality_score_pct"],"target_quality_score_pct":target["quality_score_pct"],
        "warnings":["A zero source row count makes percentage change undefined when target rows exist."] if pct is None else []}
