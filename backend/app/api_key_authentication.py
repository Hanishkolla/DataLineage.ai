"""Milestone 43: scoped API-key authentication policy for enterprise APIs.

Keys are verified by the M41 store. This module applies least-privilege HTTP/path
rules and returns a minimal tenant principal; it never returns key material.
"""
from __future__ import annotations
from typing import Any
from .api_key_security import verify_api_key

# Exact route allowlist: do not broaden this to an enterprise API prefix.
# New routes must be added only after tenant scoping has been reviewed and tested.
API_KEY_ROUTE_POLICY = {
    "/api/v1/enterprise/operations/incidents": {
        "GET": frozenset({"viewer", "analyst", "developer"}),
        "HEAD": frozenset({"viewer", "analyst", "developer"}),
    },
    "/api/v1/enterprise/operations/runs/ingest": {
        "POST": frozenset({"developer"}),
    },
}


def bearer_token(header: str | None) -> str | None:
    if not isinstance(header, str) or not header.strip():
        return None
    scheme, separator, token = header.strip().partition(" ")
    if not separator or scheme.casefold() != "bearer" or not token.strip():
        return None
    return token.strip()


def authenticate_authorization_header(header: str | None) -> dict[str, Any] | None:
    token = bearer_token(header)
    if not token:
        return None
    return verify_api_key(token)


def api_key_path_allowed(path: str, method: str, role: str) -> bool:
    """Return true only for explicitly tenant-reviewed API-key endpoints."""
    if not isinstance(path, str) or not isinstance(method, str) or not isinstance(role, str):
        return False
    methods = API_KEY_ROUTE_POLICY.get(path)
    if methods is None:
        return False
    roles = methods.get(method.upper())
    return bool(roles and role.casefold() in roles)

def tenant_principal(key_record: dict[str, Any]) -> dict[str, str]:
    return {
        "organization_id": str(key_record["tenant_key"]),
        "email": str(key_record["owner_identity"]),
        "role": str(key_record["role"]),
        "auth_method": "api_key",
        "api_key_id": str(key_record["key_id"]),
    }
