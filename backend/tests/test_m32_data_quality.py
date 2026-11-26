import pytest
from app.data_quality import profile_dataset, compare_dataset_rows

def test_profile_detects_missing_values_and_inferred_types():
    out=profile_dataset([{"id":1,"name":"A"},{"id":2,"name":None}],required_columns=["name"])
    assert out["column_profiles"]["name"]["null_count"]==1
    assert out["failed_check_count"]==1 and out["status"]=="needs_attention"

def test_profile_detects_duplicate_keys():
    out=profile_dataset([{"id":1},{"id":1},{"id":2}],unique_columns=["id"])
    assert out["checks"][-1]["failure_count"]==1

def test_profile_checks_allowed_values():
    out=profile_dataset([{"state":"ok"},{"state":"bad"}],allowed_values={"state":["ok","hold"]})
    assert out["checks"][-1]["status"]=="failed"

def test_compare_reports_row_count_and_schema_drift():
    out=compare_dataset_rows([{"a":1},{"a":2}],[{"a":1,"b":2}])
    assert out["row_count_delta"]==-1
    assert out["added_columns"]==["b"]

def test_invalid_rows_rejected():
    with pytest.raises(ValueError): profile_dataset([1,2])

def test_oversized_allowed_values_rejected():
    with pytest.raises(ValueError): profile_dataset([{"x":1}],allowed_values={"x":"not-list"})
