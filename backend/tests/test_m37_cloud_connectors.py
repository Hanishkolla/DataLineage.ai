from types import SimpleNamespace
import pytest

from app.cloud_connectors import (
    ConnectorConfigurationError, discover_aws_glue, discover_azure_data_factory,
)


class FakePaginator:
    def __init__(self, pages): self.pages = pages
    def paginate(self, **kwargs): return iter(self.pages)


class FakeGlue:
    def get_paginator(self, name):
        if name == "get_databases":
            return FakePaginator([{"DatabaseList": [{"Name": "analytics"}]}])
        if name == "get_tables":
            return FakePaginator([{"TableList": [{"Name": "orders", "TableType": "EXTERNAL_TABLE",
                "StorageDescriptor": {"Location": "s3://example/orders", "Columns": [
                    {"Name": "order_id", "Type": "bigint"}, {"Name": "email", "Type": "string"}]}}]}])
        raise AssertionError(name)


class FakeSession:
    def client(self, service, region_name):
        assert service == "glue" and region_name == "ap-south-1"
        return FakeGlue()


def test_aws_glue_discovers_and_normalizes_metadata():
    result = discover_aws_glue("ap-south-1", session=FakeSession())
    assert result["live_connection"] is True
    assert result["table_count"] == 1
    assert result["tables"][0]["schema"] == "analytics"
    assert result["tables"][0]["columns"][1]["name"] == "email"
    assert result["read_only"] is True


def test_aws_requires_region():
    with pytest.raises(ValueError, match="region is required"):
        discover_aws_glue("")


class FakeADF:
    pipelines = SimpleNamespace(list_by_factory=lambda rg, factory: [SimpleNamespace(name="daily_load", description="Nightly load")])
    datasets = SimpleNamespace(list_by_factory=lambda rg, factory: [SimpleNamespace(name="orders_ds", properties=SimpleNamespace(description="Orders source"))])


def test_azure_adf_discovers_pipeline_and_dataset():
    result = discover_azure_data_factory("sub-1", "rg-data", "factory-prod", client=FakeADF())
    assert result["live_connection"] is True
    assert result["pipeline_count"] == 1
    assert result["datasets"][0]["name"] == "orders_ds"
    assert result["read_only"] is True


def test_azure_requires_scope_identifiers():
    with pytest.raises(ValueError, match="subscription_id"):
        discover_azure_data_factory("", "rg", "factory", client=FakeADF())
