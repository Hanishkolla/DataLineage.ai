"""Keep API tests deterministic regardless of developer shell environment."""
import pytest
from app.config import settings


@pytest.fixture(autouse=True)
def auth_disabled_unless_test_enables_it(monkeypatch):
    # Individual auth tests explicitly enable auth and set test credentials.
    # This prevents DATALINEAGE_AUTH_ENABLED=true in a developer's shell from
    # unexpectedly turning all unauthenticated API tests into 401 responses.
    monkeypatch.setattr(settings, "auth_enabled", False)

@pytest.fixture(autouse=True)
def isolated_saas_database(tmp_path, monkeypatch):
    # Keep organization fixtures isolated from developer data and other tests.
    from app import saas_store
    monkeypatch.setattr(saas_store, "_path", lambda: tmp_path / "saas.sqlite3")
