"""Unit tests for FastAPI endpoints."""
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True


def test_predict_phishing_url():
    payload = {"url": "http://192.168.1.100/paypal/login-verify-account.php"}
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] in ["PHISHING", "SUSPICIOUS"]
    assert data["risk_score"] > 50
    assert len(data["risk_factors"]) > 0
    assert data["latency_ms"] < 200


def test_predict_legitimate_url():
    payload = {"url": "https://www.google.com"}
    response = client.post("/api/v1/predict", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["verdict"] == "LEGITIMATE"
    assert data["risk_score"] < 40


def test_metrics_endpoint():
    response = client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "champion_model" in data
    assert "feature_importances" in data


def test_threat_intel_report():
    report_payload = {
        "url": "http://fake-banking-portal-test.xyz/login",
        "report_type": "phishing",
        "comments": "Phishing test report"
    }
    response = client.post("/api/v1/report", json=report_payload)
    assert response.status_code == 200
    assert response.json()["status"] == "success"
