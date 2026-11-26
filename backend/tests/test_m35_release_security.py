from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_response_has_security_headers():
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers.get("content-security-policy", "")


def test_response_has_request_id():
    response = client.get("/health/live")
    assert response.headers.get("x-request-id")


def test_client_request_id_is_preserved_when_valid():
    response = client.get("/health/live", headers={"X-Request-ID": "pilot-smoke-123"})
    assert response.headers.get("x-request-id") == "pilot-smoke-123"


def test_invalid_client_request_id_is_replaced():
    response = client.get("/health/live", headers={"X-Request-ID": "bad\nid"})
    assert response.headers.get("x-request-id")
    assert response.headers.get("x-request-id") != "bad\nid"
