import pytest
from unittest.mock import patch
import app as siem_app

@pytest.fixture(autouse=True)
def isolate_visible_text_pipeline(request, monkeypatch):
    if "test_visible_text" in request.node.nodeid:
        def mock_get_pipeline_state(es):
            return {
                "es_connected": True,
                "es_mode": "Connected (Elasticsearch 8.13)",
                "events_count": 0,
                "alerts_count": 0,
                "alerts": [],
                "sev_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "top_ips": [],
                "suspicious_hosts": [],
                "kibana_url": "http://127.0.0.1:5601"
            }
        monkeypatch.setattr(siem_app, "get_pipeline_state", mock_get_pipeline_state)
    yield
