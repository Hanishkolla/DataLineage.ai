
"""Non-sensitive Firestore organization profile repository.

SQLite remains the source of truth.
This module is not connected to live application routes yet.
"""

from datetime import datetime, timezone

from .firebase_store import get_firestore_client


COLLECTION = "organization_profiles"


def save_organization_profile(
    organization_id: str,
    name: str,
    slug: str,
) -> dict:
    organization_id = organization_id.strip()
    name = name.strip()
    slug = slug.strip()

    if not organization_id:
        raise ValueError("Organization ID is required")

    if not name or len(name) > 100:
        raise ValueError("Organization name must contain 1 to 100 characters")

    if not slug:
        raise ValueError("Organization slug is required")

    profile = {
        "organization_id": organization_id,
        "name": name,
        "slug": slug,
        "synced_at": datetime.now(timezone.utc).isoformat(),
    }

    client = get_firestore_client()
    client.collection(COLLECTION).document(organization_id).set(
        profile,
        merge=True,
    )

    return profile


def get_organization_profile(organization_id: str) -> dict | None:
    organization_id = organization_id.strip()

    if not organization_id:
        raise ValueError("Organization ID is required")

    client = get_firestore_client()
    snapshot = (
        client.collection(COLLECTION)
        .document(organization_id)
        .get()
    )

    if not snapshot.exists:
        return None

    return snapshot.to_dict()

def sync_organization_profile(email: str, organization_id: str) -> dict:
    """Sync an authorized SQLite organization profile to Firestore."""

    from . import saas_store

    organization = saas_store.get_org(email, organization_id)

    if not organization:
        raise PermissionError("Organization not found")

    return save_organization_profile(
        organization["id"],
        organization["name"],
        organization["slug"],
    )
