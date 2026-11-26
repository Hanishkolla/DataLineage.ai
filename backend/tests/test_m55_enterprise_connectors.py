import json
import pytest
from app import metadata_connectors as m55


def setup_db(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SAAS_DB_PATH", str(tmp_path / "saas.sqlite3"))
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self.rows = []
    def execute(self, sql, params=()):
        self.connection.statements.append((sql, params))
        if "INFORMATION_SCHEMA.TABLES" in sql:
            self.rows = [("PUBLIC", "CUSTOMERS")]
        elif "INFORMATION_SCHEMA.COLUMNS" in sql:
            self.rows = [("EMAIL", "VARCHAR", "YES"), ("ID", "NUMBER", "NO")]
        else:
            self.rows = []
        return self
    def fetchall(self):
        return self.rows


class FakeSnowflake:
    def __init__(self):
        self.statements = []
        self.closed = False
    def cursor(self):
        return FakeCursor(self)
    def close(self):
        self.closed = True


def test_snowflake_discovery_is_read_only_metadata_and_closes_connection():
    conn = FakeSnowflake()
    result = m55.discover_snowflake("ANALYTICS", connection=conn)
    assert result["provider"] == "snowflake"
    assert result["table_count"] == 1
    assert result["tables"][0]["columns"][0]["name"] == "EMAIL"
    assert conn.closed
    assert all("SELECT" in sql.upper() for sql, _ in conn.statements)


def test_snowflake_rejects_identifier_injection():
    with pytest.raises(ValueError):
        m55.discover_snowflake('DB; DROP DATABASE X')


class FakeDBCursor:
    def __init__(self):
        self.rows = []
    def execute(self, sql):
        upper = sql.upper()
        if upper.startswith("SHOW SCHEMAS"):
            self.rows = [("default",)]
        elif upper.startswith("SHOW TABLES"):
            self.rows = [("default", "customers", False)]
        elif upper.startswith("DESCRIBE TABLE"):
            self.rows = [("email", "STRING", ""), ("id", "BIGINT", "")]
        else:
            self.rows = []
        return self
    def fetchall(self):
        return self.rows


class FakeDatabricks:
    def __init__(self): self.closed = False
    def cursor(self): return FakeDBCursor()
    def close(self): self.closed = True


def test_databricks_discovery_normalizes_catalog_metadata():
    conn = FakeDatabricks()
    result = m55.discover_databricks("main", connection=conn)
    assert result["provider"] == "databricks"
    assert result["table_count"] == 1
    assert result["tables"][0]["name"] == "customers"
    assert conn.closed


class FakeBQTable:
    table_id = "customers"
    schema = [type("Field", (), {"name": "email", "field_type": "STRING", "mode": "NULLABLE"})()]


class FakeBQClient:
    project = "demo"
    def list_datasets(self, project): return [type("Dataset", (), {"dataset_id": "sales"})()]
    def list_tables(self, dataset): return [type("TableRef", (), {"reference": "demo.sales.customers"})()]
    def get_table(self, ref): return FakeBQTable()


def test_bigquery_discovery_uses_client_and_normalizes_fields():
    result = m55.discover_bigquery(client=FakeBQClient())
    assert result["provider"] == "bigquery"
    assert result["tables"][0]["schema"] == "sales"
    assert result["tables"][0]["columns"][0]["nullable"] is True


def test_provider_status_never_returns_secret_values(monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SNOWFLAKE_ACCOUNT", "acct")
    monkeypatch.setenv("DATALINEAGE_SNOWFLAKE_USER", "user")
    monkeypatch.setenv("DATALINEAGE_SNOWFLAKE_PASSWORD", "do-not-leak")
    data = json.dumps(m55.provider_status())
    assert "do-not-leak" not in data
    assert '"configured": true' in data


def test_snapshot_history_detects_schema_drift_and_is_tenant_scoped(tmp_path, monkeypatch):
    setup_db(tmp_path, monkeypatch)
    first = {"provider": "snowflake", "tables": [{"schema": "PUBLIC", "name": "CUSTOMERS", "columns": [{"name": "ID", "type": "NUMBER"}, {"name": "EMAIL", "type": "VARCHAR"}]}]}
    second = {"provider": "snowflake", "tables": [{"schema": "PUBLIC", "name": "CUSTOMERS", "columns": [{"name": "ID", "type": "NUMBER"}, {"name": "EMAIL", "type": "TEXT"}, {"name": "PHONE", "type": "VARCHAR"}]}]}
    base = m55.save_snapshot("org-a", "admin", first)
    assert base["changes"]["baseline"] is True
    changed = m55.save_snapshot("org-a", "admin", second)
    assert changed["changes"]["risk"] == "medium"
    assert changed["changes"]["changed_tables"][0]["added_columns"] == ["phone"]
    assert len(m55.list_snapshots("org-a")) == 2
    assert m55.list_snapshots("org-b") == []
    assert len(m55.list_changes("org-a", "snowflake")) == 2
    assert m55.audit_approvals.verify_chain("org-a")["valid"] is True


def test_snapshot_rejects_unknown_provider_and_oversized_input():
    with pytest.raises(ValueError):
        m55.normalize_snapshot("unknown", [])
    with pytest.raises(ValueError):
        m55.normalize_snapshot("snowflake", [{"name": "t", "columns": [{"name": "c"}] * (m55.MAX_COLUMNS_PER_TABLE + 1)}])


def test_nested_inline_credentials_are_rejected():
    with pytest.raises(ValueError):
        m55.reject_inline_secrets({"metadata": {"connection": {"access_token": "sensitive"}}})
