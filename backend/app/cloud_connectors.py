"""Milestone 37: live, read-only Azure Data Factory and AWS Glue discovery.

Credentials are resolved by the official SDK default credential chains. The API never
accepts or stores cloud secrets. Discovery is metadata-only and bounded.
"""
from __future__ import annotations

from typing import Any

MAX_DATABASES = 500
MAX_TABLES = 20_000
MAX_COLUMNS = 10_000


class ConnectorConfigurationError(RuntimeError):
    pass


def _s(value: Any, limit: int = 500) -> str:
    return str(value or "").strip()[:limit]


def _aws_type(column: dict[str, Any]) -> str:
    return _s(column.get("Type") or column.get("type") or "unknown", 200)


def discover_aws_glue(region: str, catalog_id: str | None = None, *, session: Any = None) -> dict[str, Any]:
    """Read Glue Data Catalog databases/tables using boto3's default credential chain."""
    region = _s(region, 100)
    if not region:
        raise ValueError("region is required")
    if session is None:
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise ConnectorConfigurationError("AWS connector dependencies are missing; install boto3") from exc
        session = boto3.Session(region_name=region)
    client = session.client("glue", region_name=region)
    paginator = client.get_paginator("get_databases")
    tables: list[dict[str, Any]] = []
    database_count = 0
    for page in paginator.paginate(CatalogId=catalog_id) if catalog_id else paginator.paginate():
        for db in page.get("DatabaseList", []):
            database_count += 1
            if database_count > MAX_DATABASES:
                raise ValueError(f"Glue catalog exceeds the {MAX_DATABASES} database safety limit")
            db_name = _s(db.get("Name"), 300)
            if not db_name:
                continue
            table_paginator = client.get_paginator("get_tables")
            kwargs = {"DatabaseName": db_name}
            if catalog_id:
                kwargs["CatalogId"] = catalog_id
            for table_page in table_paginator.paginate(**kwargs):
                for item in table_page.get("TableList", []):
                    if len(tables) >= MAX_TABLES:
                        raise ValueError(f"Glue catalog exceeds the {MAX_TABLES} table safety limit")
                    name = _s(item.get("Name"), 300)
                    if not name:
                        continue
                    sd = item.get("StorageDescriptor") or {}
                    raw_cols = sd.get("Columns") or []
                    if len(raw_cols) > MAX_COLUMNS:
                        raise ValueError("A Glue table exceeds the column safety limit")
                    cols = [{"name": _s(c.get("Name"), 300), "type": _aws_type(c),
                             "nullable": None, "description": _s(c.get("Comment"), 1000)}
                            for c in raw_cols if isinstance(c, dict) and c.get("Name")]
                    tables.append({"name": name, "schema": db_name,
                                   "database": catalog_id or "aws_glue_catalog", "columns": cols,
                                   "owner": _s(item.get("Owner"), 300),
                                   "tags": [], "table_type": _s(item.get("TableType"), 100),
                                   "location": _s(sd.get("Location"), 1000)})
    return {"provider": "aws", "service": "glue", "region": region,
            "catalog_id": _s(catalog_id, 100) if catalog_id else None,
            "database_count": database_count, "table_count": len(tables),
            "column_count": sum(len(t["columns"]) for t in tables), "tables": tables,
            "live_connection": True, "read_only": True,
            "credential_source": "boto3_default_credential_chain",
            "warnings": ["Metadata-only discovery. Glue jobs, runtime lineage and data contents are not read."]}


def discover_azure_data_factory(subscription_id: str, resource_group: str, factory_name: str,
                                *, credential: Any = None, client: Any = None) -> dict[str, Any]:
    """Read Azure Data Factory pipeline and dataset definitions using managed identity/default auth."""
    subscription_id, resource_group, factory_name = map(_s, (subscription_id, resource_group, factory_name))
    if not all((subscription_id, resource_group, factory_name)):
        raise ValueError("subscription_id, resource_group and factory_name are required")
    if client is None:
        try:
            from azure.identity import DefaultAzureCredential  # type: ignore
            from azure.mgmt.datafactory import DataFactoryManagementClient  # type: ignore
        except ImportError as exc:
            raise ConnectorConfigurationError("Azure connector dependencies are missing; install azure-identity and azure-mgmt-datafactory") from exc
        credential = credential or DefaultAzureCredential(exclude_interactive_browser_credential=True)
        client = DataFactoryManagementClient(credential, subscription_id)
    pipelines = []
    datasets = []
    for item in client.pipelines.list_by_factory(resource_group, factory_name):
        if len(pipelines) >= MAX_TABLES:
            raise ValueError("ADF factory exceeds the pipeline safety limit")
        name = _s(getattr(item, "name", ""), 300)
        if name:
            pipelines.append({"id": f"{factory_name}/pipeline/{name}", "name": name,
                              "type": "pipeline", "description": _s(getattr(item, "description", ""), 1000)})
    for item in client.datasets.list_by_factory(resource_group, factory_name):
        if len(datasets) >= MAX_TABLES:
            raise ValueError("ADF factory exceeds the dataset safety limit")
        name = _s(getattr(item, "name", ""), 300)
        if name:
            props = getattr(item, "properties", None)
            datasets.append({"id": f"{factory_name}/dataset/{name}", "name": name,
                             "type": "dataset", "description": _s(getattr(props, "description", ""), 1000)})
    return {"provider": "azure", "service": "data_factory", "subscription_id": subscription_id,
            "resource_group": resource_group, "factory_name": factory_name,
            "pipeline_count": len(pipelines), "dataset_count": len(datasets),
            "pipelines": pipelines, "datasets": datasets, "live_connection": True,
            "read_only": True, "credential_source": "azure_default_credential",
            "warnings": ["ADF definitions only. Activity-level source/sink lineage and execution history require a separate runtime collector."]}
