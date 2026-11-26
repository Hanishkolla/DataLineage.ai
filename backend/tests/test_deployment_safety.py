"""Regression checks for low-information operational endpoints."""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_liveness_endpoint_returns_minimal_status():
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "secret" not in response.text.lower()
    assert "password" not in response.text.lower()


def test_readiness_failure_does_not_disclose_internal_exception(monkeypatch):
    import app.main as main_module

    def fail_store_check():
        raise RuntimeError("private database path and secret value")

    monkeypatch.setattr(main_module, "check_store", fail_store_check)
    response = client.get("/ready")
    assert response.status_code == 503
    assert response.json() == {"detail": "Analysis history store is unavailable"}
    assert "private database path" not in response.text
    assert "secret value" not in response.text
