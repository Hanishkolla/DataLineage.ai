from app.database_integrations import normalize_database_snapshot, compare_database_snapshots, analyze_airflow_dag
import pytest
def test_sqlserver_snapshot_normalizes_columns():
    x=normalize_database_snapshot({"tables":[{"schema":"dbo","name":"users","columns":[{"name":"id","data_type":"int"}]}]},"sqlserver")
    assert x["table_count"]==1 and x["tables"][0]["columns"][0]["type"]=="int"
def test_oracle_owner_maps_to_schema():
    x=normalize_database_snapshot({"tables":[{"owner":"HR","table_name":"EMP"}]},"oracle")
    assert x["tables"][0]["schema"]=="HR"
def test_invalid_provider_rejected():
    with pytest.raises(ValueError): normalize_database_snapshot({},"mysql")
def test_compare_detects_table_and_column_changes():
    a={"tables":[{"schema":"dbo","name":"T","columns":[{"name":"id","type":"int"}]}]}
    b={"tables":[{"schema":"dbo","name":"T","columns":[{"name":"id","type":"bigint"},{"name":"x","type":"text"}]},{"schema":"dbo","name":"N"}]}
    x=compare_database_snapshots(a,b,"sqlserver")
    assert x["added_tables"]==["dbo.N"] and x["changed_tables"][0]["added_columns"]==["x"] and x["risk"]=="medium"
def test_airflow_edges_and_unresolved():
    x=analyze_airflow_dag({"dag_id":"d","tasks":[{"task_id":"a"},{"task_id":"b","upstream_task_ids":["a","missing"]}]})
    assert x["edges"][0]["source"]=="a" and x["unresolved_dependencies"]==["missing"]
def test_invalid_airflow_tasks_rejected():
    with pytest.raises(ValueError): analyze_airflow_dag({"tasks":"bad"})
