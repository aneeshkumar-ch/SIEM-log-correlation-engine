import pytest
from starlette.testclient import TestClient
from app import app
import config
import storage
from storage import MockElasticsearch, initialize_indices
import dashboard_service


@pytest.fixture
def mock_es_env(monkeypatch):
    """Sets up an isolated mock Elasticsearch instance for dashboard testing."""
    test_es = MockElasticsearch()
    initialize_indices(test_es)
    monkeypatch.setattr(storage, "_mock_instance", test_es)
    monkeypatch.setattr(config, "USE_MOCK_ES", True)
    return test_es


def test_dashboard_page_renders_html():
    client = TestClient(app)
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    text = response.text
    assert "SIEM Log Correlation Dashboard" in text
    assert "Severity over time" in text
    assert "Categories" in text
    assert "Top hosts" in text
    assert "Recent alerts" in text
    assert "Log sources" in text
    assert "#2B2F7E" in text  # TAG_COLOR
    assert "#8E0000" in text  # Critical color
    assert "#E7664C" in text  # High color
    assert "#FEC514" in text  # Medium color
    assert "#F1EFE8" in text  # Total bg


def test_api_dashboard_data_empty(mock_es_env):
    client = TestClient(app)
    response = client.get("/api/dashboard-data")
    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]
    data = response.json()

    assert data["has_data"] is False
    assert data["counts"]["total"] == 0
    assert data["counts"]["critical"] == 0
    assert data["counts"]["high"] == 0
    assert data["counts"]["medium"] == 0
    assert data["counts"]["low"] == 0
    assert data["severity_over_time"] == []
    assert data["event_categories"] == []
    assert data["top_hosts"] == []
    assert data["recent_alerts"] == []
    assert data["log_sources"] == []


def test_api_dashboard_data_populated(mock_es_env):
    # Ingest mock events
    events = [
        {
            "event_id": "ev-1",
            "timestamp": "2026-10-14T10:00:00Z",
            "source": "Windows",
            "event_type": "process_create",
            "host": "WIN-SRV01",
            "user": "alice",
            "severity": "medium"
        },
        {
            "event_id": "ev-2",
            "timestamp": "2026-10-14T10:01:00Z",
            "source": "Linux",
            "event_type": "logon_failure",
            "host": "srv-linux01",
            "user": "root",
            "severity": "high"
        }
    ]
    for ev in events:
        mock_es_env.index(index=config.INDEX_EVENTS, id=ev["event_id"], document=ev)

    # Ingest mock alerts
    alerts = [
        {
            "alert_id": "alt-1",
            "rule_name": "Suspicious Process Execution",
            "severity": "high",
            "first_seen": "2026-10-14T10:00:00Z",
            "last_seen": "2026-10-14T10:00:00Z",
            "user": "alice",
            "host": ["WIN-SRV01"],
            "src_ip": "10.0.0.50",
            "mitre_technique": "T1059.001"
        },
        {
            "alert_id": "alt-2",
            "rule_name": "SSH Brute Force",
            "severity": "critical",
            "first_seen": "2026-10-14T10:01:00Z",
            "last_seen": "2026-10-14T10:01:00Z",
            "user": "root",
            "host": ["srv-linux01"],
            "src_ip": "198.51.100.25",
            "mitre_technique": "T1110.001"
        }
    ]
    for alt in alerts:
        mock_es_env.index(index=config.INDEX_ALERTS, id=alt["alert_id"], document=alt)

    client = TestClient(app)
    response = client.get("/api/dashboard-data")
    assert response.status_code == 200
    data = response.json()

    assert data["has_data"] is True
    assert data["counts"]["total"] == 2
    assert data["counts"]["critical"] == 1
    assert data["counts"]["high"] == 1
    assert len(data["recent_alerts"]) == 2
    assert len(data["event_categories"]) == 2
    assert len(data["top_hosts"]) == 2
    assert len(data["log_sources"]) == 2

    # Check color definitions
    assert data["colors"]["count_cards"]["total"]["bg"] == dashboard_service.COUNT_CARD_TOTAL_BG
    assert data["colors"]["count_cards"]["critical"]["bg"] == dashboard_service.COUNT_CARD_CRITICAL_BG
    assert data["colors"]["count_cards"]["high"]["bg"] == dashboard_service.COUNT_CARD_HIGH_BG
    assert data["colors"]["count_cards"]["medium"]["bg"] == dashboard_service.COUNT_CARD_MEDIUM_BG
    assert data["colors"]["tag"] == dashboard_service.TAG_COLOR
