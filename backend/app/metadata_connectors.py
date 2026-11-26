"""Milestone 55: read-only enterprise metadata connectors and tenant snapshots.

Live Snowflake, Databricks SQL and BigQuery connectors use credentials from the
process environment / official SDK defaults. Secrets are never accepted in API
payloads or returned. Discovery is metadata-only and bounded.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .saas_store import db as _db
from . import audit_approvals

MAX_TABLES = 20_000
MAX_COLUMNS_PER_TABLE = 10_000
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,254}$")


class ConnectorConfigurationError(RuntimeError):
    """Optional SDK or credential configuration is unavailable."""


def reject_inline_secrets(value: Any) -> None:
    """Reject credential-like keys at any nesting depth in API payloads."""
    forbidden = ("password", "token", "secret", "access_key", "private_key", "client_secret", "api_key")
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).casefold()
            if any(part in normalized for part in forbidden):
                raise ValueError("connector credentials must be configured on the server, not sent in API requests")
            reject_inline_secrets(child)
    elif isinstance(value, list):
        for child in value:
            reject_inline_secrets(child)


def _text(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def _identifier(value: Any, label: str) -> str:
    value = _text(value, 255)
    if not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{label} must be a simple SQL identifier")
    return value


def _quote(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _normal_table(name: str, schema: str, columns: list[dict[str, Any]]) -> dict[str, Any]:
    clean_columns = []
    for col in columns[:MAX_COLUMNS_PER_TABLE]:
        if not isinstance(col, dict) or not _text(col.get("name"), 255):
            continue
        clean_columns.append({
            "name": _text(col.get("name"), 255),
            "type": _text(col.get("type") or "unknown", 200),
            "nullable": col.get("nullable") if isinstance(col.get("nullable"), (bool, type(None))) else None,
        })
    return {"name": _text(name, 255), "schema": _text(schema, 255), "columns": clean_columns}


def normalize_snapshot(provider: str, tables: list[dict[str, Any]], **metadata: Any) -> dict[str, Any]:
    provider = _text(provider, 40).lower()
    if provider not in {"snowflake", "databricks", "bigquery", "aws_glue", "azure_data_factory"}:
        raise ValueError("unsupported provider")
    if not isinstance(tables, list) or len(tables) > MAX_TABLES:
        raise ValueError(f"tables must be a list of at most {MAX_TABLES} items")
    normalized = []
    seen = set()
    for item in tables:
        if not isinstance(item, dict):
            continue
        name = _text(item.get("name") or item.get("table_name"), 255)
        schema = _text(item.get("schema") or item.get("dataset") or item.get("database"), 255)
        if not name:
            continue
        key = (schema + "." + name).casefold()
        if key in seen:
            continue
        seen.add(key)
        raw_columns = item.get("columns", [])
        if not isinstance(raw_columns, list):
            raw_columns = []
        if len(raw_columns) > MAX_COLUMNS_PER_TABLE:
            raise ValueError("a table exceeds the column safety limit")
        normalized.append(_normal_table(name, schema, raw_columns))
    normalized.sort(key=lambda t: (t["schema"].casefold(), t["name"].casefold()))
    result = {"provider": provider, "tables": normalized, "table_count": len(normalized),
              "column_count": sum(len(t["columns"]) for t in normalized),
              "metadata": {k: _text(v, 500) for k, v in metadata.items() if v is not None},
              "read_only": True, "discovery_mode": "live_metadata"}
    if len(json.dumps(result, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise ValueError("metadata snapshot exceeds 8 MiB")
    return result


def _cursor_rows(cursor: Any) -> list[Any]:
    rows = cursor.fetchall()
    return list(rows or [])


def discover_snowflake(database: str, schema: str | None = None, *, connection: Any = None) -> dict[str, Any]:
    database = _identifier(database, "database")
    schema = _identifier(schema, "schema") if schema else None
    if connection is None:
        required = ["DATALINEAGE_SNOWFLAKE_ACCOUNT", "DATALINEAGE_SNOWFLAKE_USER", "DATALINEAGE_SNOWFLAKE_PASSWORD"]
        if any(not os.environ.get(k) for k in required):
            raise ConnectorConfigurationError("Configure Snowflake account, user and password in the server environment")
        try:
            import snowflake.connector  # type: ignore
        except ImportError as exc:
            raise ConnectorConfigurationError("Install the optional snowflake-connector-python package") from exc
        connection = snowflake.connector.connect(
            account=os.environ[required[0]], user=os.environ[required[1]], password=os.environ[required[2]],
            database=database, warehouse=os.environ.get("DATALINEAGE_SNOWFLAKE_WAREHOUSE"),
            role=os.environ.get("DATALINEAGE_SNOWFLAKE_ROLE"),
            session_parameters={"QUERY_TAG": "DataLineageAI-M55-read-only-metadata"},
        )
    tables: list[dict[str, Any]] = []
    try:
        cur = connection.cursor()
        sql = f"SELECT TABLE_SCHEMA, TABLE_NAME FROM {_quote(database)}.INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE IN ('BASE TABLE','VIEW')"
        params: tuple[Any, ...] = ()
        if schema:
            sql += " AND TABLE_SCHEMA = %s"
            params = (schema,)
        sql += " ORDER BY TABLE_SCHEMA, TABLE_NAME LIMIT %s"
        cur.execute(sql, params + (MAX_TABLES + 1,))
        table_rows = _cursor_rows(cur)
        if len(table_rows) > MAX_TABLES:
            raise ValueError("Snowflake database exceeds the table safety limit")
        for row in table_rows:
            table_schema, table_name = str(row[0]), str(row[1])
            col_cur = connection.cursor()
            col_cur.execute(
                f"SELECT COLUMN_NAME, DATA_TYPE, IS_NULLABLE FROM {_quote(database)}.INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION LIMIT %s",
                (table_schema, table_name, MAX_COLUMNS_PER_TABLE + 1),
            )
            col_rows = _cursor_rows(col_cur)
            if len(col_rows) > MAX_COLUMNS_PER_TABLE:
                raise ValueError("Snowflake table exceeds the column safety limit")
            tables.append({"name": table_name, "schema": table_schema,
                           "columns": [{"name": r[0], "type": r[1], "nullable": str(r[2]).upper() == "YES"} for r in col_rows]})
    finally:
        try:
            connection.close()
        except Exception:
            pass
    return normalize_snapshot("snowflake", tables, database=database, schema=schema)


def discover_databricks(catalog: str, schema: str | None = None, *, connection: Any = None) -> dict[str, Any]:
    catalog = _identifier(catalog, "catalog")
    schema = _identifier(schema, "schema") if schema else None
    if connection is None:
        hostname = _text(os.environ.get("DATABRICKS_SERVER_HOSTNAME"), 255)
        http_path = _text(os.environ.get("DATABRICKS_HTTP_PATH"), 1000)
        token = os.environ.get("DATABRICKS_TOKEN")
        if not hostname or not http_path or not token:
            raise ConnectorConfigurationError("Configure Databricks hostname, HTTP path and token in the server environment")
        try:
            from databricks import sql  # type: ignore
        except ImportError as exc:
            raise ConnectorConfigurationError("Install the optional databricks-sql-connector package") from exc
        connection = sql.connect(server_hostname=hostname, http_path=http_path, access_token=token)
    tables: list[dict[str, Any]] = []
    try:
        cur = connection.cursor()
        if schema:
            schemas = [schema]
        else:
            cur.execute(f"SHOW SCHEMAS IN {_quote(catalog)}")
            schemas = [str(r[0]) for r in _cursor_rows(cur)]
        for schema_name in schemas:
            schema_name = _text(schema_name, 255)
            if not schema_name:
                continue
            cur.execute(f"SHOW TABLES IN {_quote(catalog)}.{_quote(schema_name)}")
            for row in _cursor_rows(cur):
                table_name = str(row[1] if len(row) > 1 else row[0])
                if len(tables) >= MAX_TABLES:
                    raise ValueError("Databricks catalog exceeds the table safety limit")
                table_name = _text(table_name, 255)
                if not table_name:
                    continue
                cur.execute(f"DESCRIBE TABLE {_quote(catalog)}.{_quote(schema_name)}.{_quote(table_name)}")
                cols = []
                for col in _cursor_rows(cur):
                    if len(col) >= 2 and str(col[0]).strip() and not str(col[0]).startswith("#"):
                        cols.append({"name": col[0], "type": col[1], "nullable": None})
                if len(cols) > MAX_COLUMNS_PER_TABLE:
                    raise ValueError("Databricks table exceeds the column safety limit")
                tables.append({"name": table_name, "schema": schema_name, "columns": cols})
    finally:
        try:
            connection.close()
        except Exception:
            pass
    return normalize_snapshot("databricks", tables, catalog=catalog, schema=schema)


def discover_bigquery(project: str | None = None, dataset: str | None = None, *, client: Any = None) -> dict[str, Any]:
    project = _text(project or os.environ.get("GOOGLE_CLOUD_PROJECT"), 255)
    dataset = _text(dataset, 255) if dataset else None
    if client is None:
        try:
            from google.cloud import bigquery  # type: ignore
        except ImportError as exc:
            raise ConnectorConfigurationError("Install the optional google-cloud-bigquery package") from exc
        try:
            client = bigquery.Client(project=project or None)
        except Exception as exc:
            raise ConnectorConfigurationError("BigQuery application-default credentials or project configuration are unavailable") from exc
    project = project or _text(getattr(client, "project", ""), 255)
    if not project:
        raise ValueError("BigQuery project could not be resolved")
    datasets = [dataset] if dataset else [d.dataset_id for d in client.list_datasets(project=project)]
    tables: list[dict[str, Any]] = []
    for dataset_id in datasets:
        _identifier(dataset_id, "dataset")
        for item in client.list_tables(f"{project}.{dataset_id}"):
            if len(tables) >= MAX_TABLES:
                raise ValueError("BigQuery project exceeds the table safety limit")
            table = client.get_table(item.reference)
            cols = [{"name": f.name, "type": f.field_type, "nullable": f.mode != "REQUIRED"} for f in table.schema]
            if len(cols) > MAX_COLUMNS_PER_TABLE:
                raise ValueError("BigQuery table exceeds the column safety limit")
            tables.append({"name": table.table_id, "schema": dataset_id, "columns": cols})
    return normalize_snapshot("bigquery", tables, project=project, dataset=dataset)


def _schema(c: Any) -> None:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS enterprise_metadata_snapshots (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, provider TEXT NOT NULL,
      fingerprint TEXT NOT NULL, snapshot_json TEXT NOT NULL,
      table_count INTEGER NOT NULL, column_count INTEGER NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_enterprise_snapshots_org_provider
      ON enterprise_metadata_snapshots(org_id,provider,created_at DESC,id DESC);
    CREATE TABLE IF NOT EXISTS enterprise_metadata_changes (
      id TEXT PRIMARY KEY, org_id TEXT NOT NULL, provider TEXT NOT NULL,
      snapshot_id TEXT NOT NULL, change_json TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS ix_enterprise_changes_org_provider
      ON enterprise_metadata_changes(org_id,provider,created_at DESC,id DESC);
    """)


def _diff(before: dict[str, Any] | None, after: dict[str, Any]) -> dict[str, Any]:
    if not before:
        return {"baseline": True, "added_tables": [f'{t["schema"]}.{t["name"]}' for t in after["tables"]],
                "removed_tables": [], "changed_tables": [], "risk": "baseline"}
    key = lambda t: (t["schema"] + "." + t["name"]).casefold()
    old = {key(t): t for t in before.get("tables", [])}
    new = {key(t): t for t in after.get("tables", [])}
    added, removed, changed = sorted(set(new)-set(old)), sorted(set(old)-set(new)), []
    for k in sorted(set(old) & set(new)):
        a = {c["name"].casefold(): c for c in old[k]["columns"]}
        b = {c["name"].casefold(): c for c in new[k]["columns"]}
        addc, delc = sorted(set(b)-set(a)), sorted(set(a)-set(b))
        types = sorted(c for c in set(a)&set(b) if a[c].get("type") != b[c].get("type"))
        if addc or delc or types:
            changed.append({"table": new[k]["name"], "schema": new[k]["schema"],
                            "added_columns": addc, "removed_columns": delc,
                            "type_changes": [{"column": c, "before": a[c].get("type"), "after": b[c].get("type")} for c in types]})
    risk = "high" if removed or any(x["removed_columns"] for x in changed) else ("medium" if changed else ("low" if added else "none"))
    return {"baseline": False, "added_tables": added, "removed_tables": removed,
            "changed_tables": changed, "risk": risk}


def save_snapshot(org_id: str, actor: str, snapshot: dict[str, Any]) -> dict[str, Any]:
    if not org_id or not actor or not isinstance(snapshot, dict):
        raise ValueError("organization, actor and snapshot are required")
    normalized = normalize_snapshot(snapshot.get("provider", ""), snapshot.get("tables", []), **(snapshot.get("metadata") or {}))
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if len(encoded.encode("utf-8")) > MAX_SNAPSHOT_BYTES:
        raise ValueError("metadata snapshot exceeds 8 MiB")
    fingerprint = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    with _db() as c:
        _schema(c)
        row = c.execute("SELECT snapshot_json FROM enterprise_metadata_snapshots WHERE org_id=? AND provider=? ORDER BY created_at DESC,id DESC LIMIT 1",
                        (org_id, normalized["provider"])).fetchone()
        previous = json.loads(row["snapshot_json"]) if row else None
        changes = _diff(previous, normalized)
        snapshot_id, now = str(uuid.uuid4()), datetime.now(timezone.utc).isoformat(timespec="microseconds")
        c.execute("INSERT INTO enterprise_metadata_snapshots VALUES(?,?,?,?,?,?,?,?)",
                  (snapshot_id, org_id, normalized["provider"], fingerprint, encoded,
                   normalized["table_count"], normalized["column_count"], now))
        change_id = str(uuid.uuid4())
        c.execute("INSERT INTO enterprise_metadata_changes VALUES(?,?,?,?,?,?)",
                  (change_id, org_id, normalized["provider"], snapshot_id,
                   json.dumps(changes, sort_keys=True, separators=(",", ":")), now))
    audit_approvals.append_event(org_id, actor, "connector.metadata_snapshot.saved",
        "enterprise_metadata_snapshot", snapshot_id,
        {"provider": normalized["provider"], "fingerprint": fingerprint, "table_count": normalized["table_count"], "change_risk": changes["risk"]})
    return {"snapshot_id": snapshot_id, "provider": normalized["provider"],
            "fingerprint": fingerprint, "table_count": normalized["table_count"],
            "column_count": normalized["column_count"], "changes": changes, "created_at": now}


def list_snapshots(org_id: str, provider: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 200))
    with _db() as c:
        _schema(c)
        if provider:
            rows = c.execute("SELECT id,provider,fingerprint,table_count,column_count,created_at FROM enterprise_metadata_snapshots WHERE org_id=? AND provider=? ORDER BY created_at DESC,id DESC LIMIT ?", (org_id, provider, limit)).fetchall()
        else:
            rows = c.execute("SELECT id,provider,fingerprint,table_count,column_count,created_at FROM enterprise_metadata_snapshots WHERE org_id=? ORDER BY created_at DESC,id DESC LIMIT ?", (org_id, limit)).fetchall()
        return [dict(r) for r in rows]


def list_changes(org_id: str, provider: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 200))
    with _db() as c:
        _schema(c)
        if provider:
            rows = c.execute("SELECT id,provider,snapshot_id,change_json,created_at FROM enterprise_metadata_changes WHERE org_id=? AND provider=? ORDER BY created_at DESC,id DESC LIMIT ?", (org_id, provider, limit)).fetchall()
        else:
            rows = c.execute("SELECT id,provider,snapshot_id,change_json,created_at FROM enterprise_metadata_changes WHERE org_id=? ORDER BY created_at DESC,id DESC LIMIT ?", (org_id, limit)).fetchall()
        return [{**dict(r), "changes": json.loads(r["change_json"])} for r in rows]


def provider_status() -> list[dict[str, Any]]:
    """Report configuration presence only; never reveal credential values."""
    return [
        {"provider": "snowflake", "mode": "live_read_only", "configured": all(bool(os.environ.get(k)) for k in ("DATALINEAGE_SNOWFLAKE_ACCOUNT", "DATALINEAGE_SNOWFLAKE_USER", "DATALINEAGE_SNOWFLAKE_PASSWORD")), "credential_source": "server_environment"},
        {"provider": "databricks", "mode": "live_read_only", "configured": all(bool(os.environ.get(k)) for k in ("DATABRICKS_SERVER_HOSTNAME", "DATABRICKS_HTTP_PATH", "DATABRICKS_TOKEN")), "credential_source": "server_environment"},
        {"provider": "bigquery", "mode": "live_read_only", "configured": bool(os.environ.get("GOOGLE_CLOUD_PROJECT")), "credential_source": "application_default_credentials"},
        {"provider": "aws_glue", "mode": "existing_read_only_connector", "configured": True, "credential_source": "aws_default_credential_chain"},
        {"provider": "azure_data_factory", "mode": "existing_read_only_connector", "configured": True, "credential_source": "azure_default_credential"},
        {"provider": "dbt", "mode": "manifest_import", "configured": True, "credential_source": "uploaded_manifest"},
    ]
