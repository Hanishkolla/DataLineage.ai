from __future__ import annotations

from app import saas_store as s
from app.db_backend import PostgresConnection, lock_org


class _Cursor:
    def __init__(self):
        self.calls = []
    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        return self


def test_postgres_tenant_lock_uses_transaction_advisory_lock():
    connection = object.__new__(PostgresConnection)
    connection._connection = type("FakeConnection", (), {"cursor": lambda self: _Cursor()})()
    # Use a lightweight subclass override to capture adapter execution safely.
    calls = []
    connection.execute = lambda sql, params=(): calls.append((sql, params))
    lock_org(connection, "org-123")
    assert len(calls) == 1
    assert "pg_advisory_xact_lock" in calls[0][0]
    assert calls[0][1] == ("datalineage:organization:org-123",)


def test_sqlite_lock_helper_is_noop_for_sqlite_connection(tmp_path, monkeypatch):
    import sqlite3
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    c = sqlite3.connect(tmp_path / "test.db")
    try:
        lock_org(c, "org-123")
    finally:
        c.close()


def test_invitation_and_usage_mutations_still_work_on_sqlite(tmp_path, monkeypatch):
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    monkeypatch.setattr(s, "_path", lambda: tmp_path / "saas.sqlite3")
    org = s.create_org("owner@example.com", "M48 concurrency")
    s.change_plan("owner@example.com", org["id"], "starter")
    invite = s.invite("owner@example.com", org["id"], "dev@example.com", "developer")
    accepted = s.accept_invite("dev@example.com", invite["token"])
    assert accepted["id"] == org["id"]
    first = s.record_usage("owner@example.com", org["id"], "analyses", 1, "m48-idempotency")
    second = s.record_usage("owner@example.com", org["id"], "analyses", 1, "m48-idempotency")
    assert first["recorded"] is True
    assert second["recorded"] is False


def test_razorpay_webhook_uses_conflict_safe_insert():
    source = open(s.__file__, encoding="utf-8").read()
    assert "ON CONFLICT(provider,event_id) DO NOTHING" in source
    assert "except sqlite3.IntegrityError" not in source


def test_concurrent_sqlite_reservations_do_not_exceed_plan_limit(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    monkeypatch.delenv("DATALINEAGE_DATABASE_URL", raising=False)
    monkeypatch.setattr(s, "_path", lambda: tmp_path / "concurrent.sqlite3")
    org = s.create_org("quota@example.com", "M48 quota")

    def reserve(index):
        try:
            return s.reserve_analysis("quota@example.com", org["id"], 10, f"parallel-{index}")
        except OverflowError:
            return "limit"

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(reserve, range(6)))
    assert results.count("limit") == 1
    assert sum(isinstance(value, str) and value != "limit" and value != "duplicate" for value in results) == 5
