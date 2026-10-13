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
