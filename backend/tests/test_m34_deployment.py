from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_liveness_probe_returns_alive():
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


def test_readiness_probe_has_safe_response_shape():
    response = client.get("/health/ready")
    assert response.status_code in (200, 503)
    assert response.json()["status"] in ("ready", "not_ready")
    assert "checks" in response.json()
