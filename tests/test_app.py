import pytest
import io
import os
from pathlib import Path
from starlette.testclient import TestClient

import config
from storage import MockElasticsearch, initialize_indices
import storage
from app import app


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Ensures test client uses MockElasticsearch and isolated state."""
    test_es = MockElasticsearch()
    initialize_indices(test_es)
    monkeypatch.setattr(storage, "_mock_instance", test_es)
    monkeypatch.setattr(config, "USE_MOCK_ES", True)
    yield test_es


def test_get_root():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "SIEM Log Correlation Engine" in response.text
    assert "Ingest Log File" in response.text
    assert "Run Correlation Rules" in response.text
    assert "Clear Data" in response.text


def test_upload_linux_auth():
    client = TestClient(app)
    content = b"""Oct 13 10:00:00 srv01 sshd[101]: Failed password for invalid user admin from 198.51.100.10 port 4001 ssh2
Oct 13 10:00:30 srv01 sshd[102]: Failed password for invalid user root from 198.51.100.10 port 4002 ssh2
Oct 13 10:01:00 srv01 sshd[103]: Failed password for invalid user test from 198.51.100.10 port 4003 ssh2
Oct 13 10:01:30 srv01 sshd[104]: Failed password for invalid user oracle from 198.51.100.10 port 4004 ssh2
Oct 13 10:02:00 srv01 sshd[105]: Failed password for invalid user guest from 198.51.100.10 port 4005 ssh2
"""
    files = {"file": ("auth.log", content, "text/plain")}
    data = {"source_type": "linux_auth"}

    response = client.post("/upload", files=files, data=data)
    assert response.status_code == 200
    assert "Ingestion complete" in response.text
    assert "Brute Force Suspected" in response.text
    assert "5 event(s) parsed" in response.text

    # Verify file was saved under a generated UUID filename, not auth.log
    saved_files = list(config.UPLOADS_DIR.glob("*.log"))
    assert len(saved_files) >= 1
    assert not (config.UPLOADS_DIR / "auth.log").exists()


def test_upload_disallowed_extension():
    client = TestClient(app)
    files = {"file": ("malicious.exe", b"MZdummy", "application/octet-stream")}
    data = {"source_type": "windows_security"}

    response = client.post("/upload", files=files, data=data)
    assert response.status_code == 400
    assert "Rejected: File extension" in response.text
    assert ".exe" in response.text


def test_upload_reupload_no_duplicates():
    client = TestClient(app)
    csv_bytes = b"""EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
4624,2026-10-13T10:30:00Z,WIN-FINANCE,david,192.168.1.88,
4688,2026-10-13T10:31:10Z,WIN-FINANCE,david,,powershell.exe
"""
    files1 = {"file": ("events.csv", csv_bytes, "text/csv")}
    data = {"source_type": "windows_security"}

    # First upload
    res1 = client.post("/upload", files=files1, data=data)
    assert res1.status_code == 200

    # Status check
    st1 = client.get("/api/status").json()
    assert st1["events_count"] == 2
    assert st1["alerts_count"] == 1

    # Second upload of identical file
    files2 = {"file": ("events.csv", csv_bytes, "text/csv")}
    res2 = client.post("/upload", files=files2, data=data)
    assert res2.status_code == 200

    st2 = client.get("/api/status").json()
    assert st2["events_count"] == 2
    assert st2["alerts_count"] == 1


def test_clear_pipeline_data():
    client = TestClient(app)
    # Populate data
    csv_bytes = b"""EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
4624,2026-10-13T10:30:00Z,WIN-FINANCE,david,192.168.1.88,
"""
    client.post("/upload", files={"file": ("events.csv", csv_bytes, "text/csv")}, data={"source_type": "windows_security"})

    st_before = client.get("/api/status").json()
    assert st_before["events_count"] >= 1

    # Clear
    res = client.post("/clear")
    assert res.status_code == 200
    assert "Pipeline data successfully cleared" in res.text

    st_after = client.get("/api/status").json()
    assert st_after["events_count"] == 0
    assert st_after["alerts_count"] == 0


def test_investigation_page_and_save():
    client = TestClient(app)
    # 1. GET /investigation
    res = client.get("/investigation?scenario=scenario_1")
    assert res.status_code == 200
    assert "Student Investigation Workspace" in res.text
    assert "Brute Force Authentication" in res.text
    assert "8-Step Investigation Workflow" in res.text

    # 2. POST /investigation/save
    post_data = {
        "scenario_key": "scenario_1",
        "analyst_name": "Test Analyst",
        "verdict": "True Positive",
        "impacted_hosts": "WIN-SRV01",
        "threat_ip": "198.51.100.25",
        "mitre_technique": "T1110.001",
        "timeline_summary": "Attacker attempted 5 failed logons followed by success.",
        "evidence_ids": "ev-001, ev-002",
        "recommendations": "Block IP 198.51.100.25 and reset credentials."
    }
    save_res = client.post("/investigation/save", data=post_data)
    assert save_res.status_code == 200
    assert "Findings for Scenario 1 successfully recorded" in save_res.text

    # 3. GET /investigation/export/scenario_1
    export_res = client.get("/investigation/export/scenario_1")
    assert export_res.status_code == 200
    assert "text/markdown" in export_res.headers.get("content-type", "")
    assert "# SOC Incident Investigation Report" in export_res.text
    assert "198.51.100.25" in export_res.text


def test_generate_samples_route():
    client = TestClient(app)
    res = client.post("/generate-samples")
    assert res.status_code == 200
    assert "Training dataset generated and ingested" in res.text

    status = client.get("/api/status").json()
    assert status["events_count"] > 0
    assert status["alerts_count"] > 0


def test_kibana_routes():
    client = TestClient(app)
    # /kibana and /kibana/ should redirect to /open/soc
    res1 = client.get("/kibana", follow_redirects=False)
    assert res1.status_code in (302, 307)
    assert res1.headers["location"] == "/open/soc"

    res2 = client.get("/kibana/", follow_redirects=False)
    assert res2.status_code in (302, 307)
    assert res2.headers["location"] == "/open/soc"

    # /kibana/app/dashboards should redirect to /app/dashboards
    res3 = client.get("/kibana/app/dashboards", follow_redirects=False)
    assert res3.status_code in (302, 307)
    assert res3.headers["location"] == "/app/dashboards"


def test_open_routes():
    client = TestClient(app)
    res_soc = client.get("/open/soc", follow_redirects=False)
    assert res_soc.status_code in (302, 307)
    assert "soc-triage-board-dashboard" in res_soc.headers["location"]

    res_alt = client.get("/open/alerts", follow_redirects=False)
    assert res_alt.status_code in (302, 307)
    assert "alerts-dashboard" in res_alt.headers["location"]

    res_time = client.get("/open/timeline", follow_redirects=False)
    assert res_time.status_code in (302, 307)
    assert "timeline-analysis-dashboard" in res_time.headers["location"]

    res_disc = client.get("/open/discover", follow_redirects=False)
    assert res_disc.status_code in (302, 307)
    assert "events-search" in res_disc.headers["location"]

    res_events = client.get("/open/events", follow_redirects=False)
    assert res_events.status_code in (302, 307)
    assert "events-search" in res_events.headers["location"]


def test_kibana_proxy_allowlist_blocks_admin_and_dev_tools():
    client = TestClient(app)
    blocked_paths = [
        "/app/dev_tools",
        "/app/dev_tools#/console",
        "/app/management",
        "/app/management/kibana/objects",
        "/app/saved_objects",
        "/internal/console",
        "/api/console",
        "/api/console/proxy",
        "/kibana/app/dev_tools",
        "/kibana/app/management",
    ]
    for p in blocked_paths:
        res = client.get(p)
        assert res.status_code == 403, f"Expected 403 for {p}, got {res.status_code}"


def test_kibana_proxy_allowlist_blocks_mutating_methods():
    client = TestClient(app)
    # PUT, DELETE, PATCH must return 403
    for method in ["delete", "put", "patch"]:
        caller = getattr(client, method)
        res = caller("/api/saved_objects/index-pattern/123")
        assert res.status_code == 403, f"Expected 403 for {method.upper()} on saved_objects, got {res.status_code}"

    # POST to arbitrary unlisted API must return 403
    res_post = client.post("/api/unauthorized/write", json={"test": 1})
    assert res_post.status_code == 403


def test_kibana_proxy_allowlist_permits_safe_paths():
    from app import is_kibana_path_allowed
    # Static assets
    assert is_kibana_path_allowed("GET", "/2e3a5cd43e83/bundles/core/core.entry.js")
    assert is_kibana_path_allowed("GET", "/2e3a5cd43e83/ui/legacy_light_theme.min.css")
    assert is_kibana_path_allowed("GET", "/bootstrap.js")
    assert is_kibana_path_allowed("GET", "/translations/en.json")

    # App views
    assert is_kibana_path_allowed("GET", "/app/dashboards")
    assert is_kibana_path_allowed("GET", "/app/dashboards#/view/soc-triage-board-dashboard")
    assert is_kibana_path_allowed("GET", "/app/discover")
    assert is_kibana_path_allowed("GET", "/app/discover#/view/events-search")

    # Safe GET APIs
    assert is_kibana_path_allowed("GET", "/api/licensing/info")
    assert is_kibana_path_allowed("GET", "/internal/security/me")
    assert is_kibana_path_allowed("GET", "/internal/data_views/fields")
    assert is_kibana_path_allowed("GET", "/internal/spaces/_active_space")

    # Safe POST APIs
    assert is_kibana_path_allowed("POST", "/internal/bsearch")
    assert is_kibana_path_allowed("POST", "/api/core/capabilities")
    assert is_kibana_path_allowed("POST", "/api/content_management/rpc/get")
    assert is_kibana_path_allowed("POST", "/api/content_management/rpc/search")
    assert is_kibana_path_allowed("POST", "/internal/data_views/_fields_for_wildcard")
