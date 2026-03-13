from fastapi.testclient import TestClient
from unittest.mock import patch
import pytest

# Mock the heavy NLP model so pytest doesn't try to download it
with patch("models.nlp_summarizer.AlertSummarizer._load"):
    from main import app, cache

client = TestClient(app)

def test_api_stats_with_data():
    cache["latest_threats"] = [
        {"severity": "Critical", "source": "ThreatFox", "threat_type": "botnet"},
        {"severity": "Low", "source": "URLhaus", "threat_type": "unknown"}
    ]
    cache["status"] = "idle"

    response = client.get("/api/v1/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["total_threats"] == 2
    assert data["severities"]["Critical"] == 1
    assert data["severities"]["Low"] == 1
    assert data["sources"]["ThreatFox"] == 1

def test_api_threats_returns_data():
    cache["latest_threats"] = [{"severity": "High", "source": "URLhaus", "threat_type": "malware"}]
    cache["status"] = "idle"
    response = client.get("/api/v1/threats")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] == 1
    assert data["data"][0]["severity"] == "High"

def test_api_trigger_update_idle():
    cache["status"] = "idle"
    response = client.get("/api/v1/update")
    assert response.status_code == 200
    assert "started" in response.json()["message"]

def test_api_trigger_update_busy():
    cache["status"] = "updating"
    response = client.get("/api/v1/update")
    assert response.status_code == 200
    assert "already" in response.json()["message"]
    cache["status"] = "idle"  # reset
