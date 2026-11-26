
import pytest

from app import firestore_store


class FakeDocument:
    def __init__(self):
        self.data = None

    def set(self, data, merge=False):
        if merge and self.data:
            self.data.update(data)
        else:
            self.data = dict(data)

    def get(self):
        return FakeSnapshot(self.data)


class FakeSnapshot:
    def __init__(self, data):
        self.exists = data is not None
        self._data = data

    def to_dict(self):
        return dict(self._data) if self._data else None


class FakeCollection:
    def __init__(self):
        self.documents = {}

    def document(self, document_id):
        return self.documents.setdefault(document_id, FakeDocument())


class FakeFirestore:
    def __init__(self):
        self.collections = {}

    def collection(self, name):
        return self.collections.setdefault(name, FakeCollection())


@pytest.fixture
def fake_firestore(monkeypatch):
    client = FakeFirestore()
    monkeypatch.setattr(
        firestore_store,
        "get_firestore_client",
        lambda: client,
    )
    return client


def test_save_and_get_organization_profile(fake_firestore):
    saved = firestore_store.save_organization_profile(
        "org-123",
        "Acme Data",
        "acme-data",
    )

    loaded = firestore_store.get_organization_profile("org-123")

    assert saved["organization_id"] == "org-123"
    assert loaded["name"] == "Acme Data"
    assert loaded["slug"] == "acme-data"


def test_update_organization_profile(fake_firestore):
    firestore_store.save_organization_profile(
        "org-123",
        "Acme Data",
        "acme-data",
    )

    updated = firestore_store.save_organization_profile(
        "org-123",
        "Acme Analytics",
        "acme-analytics",
    )

    loaded = firestore_store.get_organization_profile("org-123")

    assert updated["name"] == "Acme Analytics"
    assert loaded["name"] == "Acme Analytics"


def test_missing_organization_returns_none(fake_firestore):
    assert (
        firestore_store.get_organization_profile("missing-org")
        is None
    )


@pytest.mark.parametrize(
    "organization_id,name,slug",
    [
        ("", "Acme", "acme"),
        ("org-123", "", "acme"),
        ("org-123", "A" * 101, "acme"),
        ("org-123", "Acme", ""),
    ],
)
def test_invalid_organization_profile_is_rejected(
    fake_firestore,
    organization_id,
    name,
    slug,
):
    with pytest.raises(ValueError):
        firestore_store.save_organization_profile(
            organization_id,
            name,
            slug,
        )

def test_sync_organization_profile_from_sqlite(fake_firestore, monkeypatch):
    from app import saas_store

    monkeypatch.setattr(
        saas_store,
        "get_org",
        lambda email, organization_id: {
            "id": organization_id,
            "name": "Acme Data",
            "slug": "acme-data",
            "role": "owner",
        } if email == "owner@example.com" else None,
    )

    result = firestore_store.sync_organization_profile(
        "owner@example.com",
        "org-123",
    )

    assert result["organization_id"] == "org-123"
    assert firestore_store.get_organization_profile("org-123")["name"] == "Acme Data"


def test_sync_rejects_unauthorized_organization(fake_firestore, monkeypatch):
    from app import saas_store

    monkeypatch.setattr(
        saas_store,
        "get_org",
        lambda email, organization_id: None,
    )

    with pytest.raises(PermissionError):
        firestore_store.sync_organization_profile(
            "outsider@example.com",
            "org-123",
        )
