from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_health() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_analyze_suspicious_content() -> None:
    payload = {
        "url": "https://example-fake-login.com/security/verify",
        "text": "Your account will be suspended. Verify now with your password and OTP.",
        "links": [{"text": "Verify account", "url": "https://example-fake-login.com/security/verify"}],
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in {"suspicious", "high_risk"}
    assert data["risk_score"] >= 35
    assert "indicators" in data


def test_analyze_benign_content() -> None:
    payload = {
        "url": "https://example.com/blog",
        "text": "This article explains how to keep a home office organized.",
        "links": [{"text": "Read more", "url": "https://example.com/blog/office"}],
    }
    response = client.post("/api/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "no_suspicious_indicators_detected"


def test_invalid_payload_is_rejected() -> None:
    response = client.post("/api/analyze", json={"links": ["not-a-link"]})
    assert response.status_code in {400, 422}
