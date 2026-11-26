from __future__ import annotations

import hashlib
import importlib.util
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app import api_key_security as api_keys
from app import audit_approvals as audit
from app import role_access_control as access
from app.graph_benchmark import build_synthetic_lineage_graph, run_graph_benchmark

ROOT = Path(__file__).resolve().parents[2]


def _load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def test_synthetic_graph_is_exact_deterministic_dag():
    graph = build_synthetic_lineage_graph(12, 22)
    assert graph.number_of_nodes() == 12
    assert graph.number_of_edges() == 22
    assert graph.has_edge(0, 1)
    assert all(source < target for source, target in graph.edges())


def test_graph_benchmark_reports_integrity_and_measurements():
    report = run_graph_benchmark(100, 180, workers=2, queries=3)
    assert report["integrity"] == {
        "nodes_created": 100, "edges_created": 180, "directed_acyclic_graph": True
    }
    assert report["measurements"]["graph_build_seconds"] >= 0
    assert report["measurements"]["python_traced_peak_bytes"] > 0
    assert len(report["measurements"]["reachable_node_counts"]) == 3
    assert len(report["measurement_limits"]) >= 3


@pytest.mark.parametrize("nodes,edges", [(1, 0), (10, 8), (5, 11), (True, 4)])
def test_graph_benchmark_rejects_invalid_bounds(nodes, edges):
    with pytest.raises(ValueError):
        build_synthetic_lineage_graph(nodes, edges)


def test_api_keys_are_hashed_tenant_scoped_and_revocable(tmp_path, monkeypatch):
    db_path = tmp_path / "api_keys.sqlite3"
    monkeypatch.setenv("DATALINEAGE_SECURITY_DB", str(db_path))
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)

    created = api_keys.create_api_key("tenant-a", "owner@example.test", "ci-readonly", "viewer")
    raw_key = created["api_key"]
    assert api_keys.verify_api_key(raw_key, "tenant-a")["role"] == "viewer"
    assert api_keys.verify_api_key(raw_key, "tenant-b") is None
    assert api_keys.verify_api_key(raw_key) is not None

    with sqlite3.connect(db_path) as conn:
        stored_hash = conn.execute("SELECT key_hash FROM api_keys WHERE key_id=?", (created["key_id"],)).fetchone()[0]
    assert stored_hash == hashlib.sha256(raw_key.encode()).hexdigest()
    assert stored_hash != raw_key

    assert api_keys.revoke_api_key("tenant-a", created["key_id"]) is True
    assert api_keys.verify_api_key(raw_key, "tenant-a") is None
    assert api_keys.revoke_api_key("tenant-b", created["key_id"]) is False


def test_concurrent_tenant_audit_appends_keep_valid_hash_chains(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_SAAS_DB_PATH", str(tmp_path / "audit.sqlite3"))
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)

    def append(index: int):
        return audit.append_event("tenant-a", f"worker-{index}", "benchmark.event",
                                  "benchmark", str(index), {"index": index})

    with ThreadPoolExecutor(max_workers=8) as pool:
        created = list(pool.map(append, range(24)))

    assert len({item["event_hash"] for item in created}) == 24
    assert audit.verify_chain("tenant-a")["valid"] is True
    assert audit.verify_chain("tenant-a")["events_checked"] == 24
    assert audit.list_events("tenant-b") == []


def test_access_policy_cannot_escalate_or_cross_tenants(tmp_path, monkeypatch):
    monkeypatch.setenv("DATALINEAGE_ACCESS_DB", str(tmp_path / "access.sqlite3"))
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    access.save_role_policy("tenant-a", "owner@example.test", "developer", ["lineage.read"])
    assert access.effective_permissions("tenant-a", "developer") == {"lineage.read"}
    assert "lineage.analyze" in access.effective_permissions("tenant-b", "developer")
    with pytest.raises(ValueError, match="above the built-in role ceiling"):
        access.save_role_policy("tenant-a", "owner@example.test", "viewer", ["security.manage"])


def test_sqlite_restore_rejects_checksum_tampering_and_path_traversal(tmp_path):
    restore = _load_script("restore_sqlite_backup")
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    db_path = backup_dir / "tenant.sqlite3"
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE sample(value TEXT)")
        conn.execute("INSERT INTO sample VALUES('safe')")
    digest = hashlib.sha256(db_path.read_bytes()).hexdigest()
    (backup_dir / "manifest.json").write_text(json.dumps({
        "format": "datalineage-sqlite-backup-v1",
        "databases": [{"filename": db_path.name, "sha256": digest}],
    }), encoding="utf-8")

    assert restore.verify_backup(backup_dir)[0]["filename"] == "tenant.sqlite3"
    db_path.write_bytes(db_path.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="checksum mismatch"):
        restore.verify_backup(backup_dir)

    (backup_dir / "manifest.json").write_text(json.dumps({
        "format": "datalineage-sqlite-backup-v1",
        "databases": [{"filename": "../outside.sqlite3", "sha256": "0" * 64}],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="Unsafe database filename"):
        restore.verify_backup(backup_dir)
