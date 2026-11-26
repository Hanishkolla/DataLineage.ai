"""Small optional PostgreSQL adapter for project stores.

SQLite remains the default. PostgreSQL is enabled only when
DATALINEAGE_DATABASE_URL contains a postgres/postgresql DSN. The adapter
intentionally supports the execute/fetch/transaction methods used by the
analysis-run, security, authentication and SaaS stores; it is not an ORM.
"""
from __future__ import annotations

import os
from typing import Any


def configured_database_url() -> str | None:
    raw = os.getenv("DATALINEAGE_DATABASE_URL", "").strip()
    if not raw:
        return None
    if not raw.startswith(("postgresql://", "postgres://")):
        raise ValueError("DATALINEAGE_DATABASE_URL must use postgresql:// or postgres://")
    return raw


def backend_name() -> str:
    return "postgresql" if configured_database_url() else "sqlite"


def qmark_to_pyformat(statement: str) -> str:
    """Translate positional qmark parameters without touching quoted text/comments."""
    out: list[str] = []
    i = 0
    state = "normal"
    while i < len(statement):
        ch = statement[i]
        nxt = statement[i + 1] if i + 1 < len(statement) else ""
        if state == "normal":
            if ch == "'":
                state = "single"
                out.append(ch)
            elif ch == '"':
                state = "double"
                out.append(ch)
            elif ch == "-" and nxt == "-":
                state = "line_comment"
                out.extend((ch, nxt))
                i += 1
            elif ch == "/" and nxt == "*":
                state = "block_comment"
                out.extend((ch, nxt))
                i += 1
            elif ch == "?":
                out.append("%s")
            else:
                out.append(ch)
        elif state == "single":
            out.append(ch)
            if ch == "'":
                if nxt == "'":
                    out.append(nxt)
                    i += 1
                else:
                    state = "normal"
        elif state == "double":
            out.append(ch)
            if ch == '"':
                if nxt == '"':
                    out.append(nxt)
                    i += 1
                else:
                    state = "normal"
        elif state == "line_comment":
            out.append(ch)
            if ch == "\n":
                state = "normal"
        elif state == "block_comment":
            out.append(ch)
            if ch == "*" and nxt == "/":
                out.append(nxt)
                i += 1
                state = "normal"
        i += 1
    return "".join(out)


class PostgresConnection:
    """Compatibility wrapper exposing the subset of sqlite connection API in use."""

    def __init__(self, database_url: str):
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError(
                "PostgreSQL is configured but psycopg is not installed. "
                "Install backend requirements (psycopg[binary])."
            ) from exc
        self._connection = psycopg.connect(
            database_url, connect_timeout=10, row_factory=dict_row
        )

    def executescript(self, script: str) -> None:
        # Project-owned schema scripts contain ordinary semicolon-separated DDL.
        for statement in script.split(";"):
            statement = statement.strip()
            if statement:
                self.execute(statement)

    def execute(self, statement: str, parameters: Any = ()):
        cursor = self._connection.cursor()
        normalized = statement.strip()
        if normalized.upper() == "BEGIN IMMEDIATE":
            normalized = "BEGIN"
        cursor.execute(qmark_to_pyformat(normalized), tuple(parameters or ()))
        return cursor

    def commit(self) -> None:
        self._connection.commit()

    def rollback(self) -> None:
        self._connection.rollback()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        try:
            if exc_type is None:
                self.commit()
            else:
                self.rollback()
        finally:
            self.close()
        return False


def connect_postgres(database_url: str) -> PostgresConnection:
    return PostgresConnection(database_url)


def lock_org(connection: Any, organization_id: str) -> None:
    """Serialize quota and membership mutations for one tenant.

    PostgreSQL advisory locks are transaction-scoped and automatically released
    on commit/rollback. SQLite callers already hold BEGIN IMMEDIATE.
    """
    if isinstance(connection, PostgresConnection):
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))",
            (f"datalineage:organization:{organization_id}",),
        )
