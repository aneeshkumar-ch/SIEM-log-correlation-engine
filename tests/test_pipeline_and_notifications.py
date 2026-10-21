import pytest
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from starlette.testclient import TestClient

import config
import correlate
import collector
from storage import MockElasticsearch, initialize_indices
import storage
from app import app
from pipeline_manager import pipeline_manager, PipelineManager


@pytest.fixture(autouse=True)
def setup_test_env(monkeypatch):
    """Ensures test client uses MockElasticsearch and isolated state."""
    test_es = MockElasticsearch()
    initialize_indices(test_es)
    monkeypatch.setattr(storage, "_mock_instance", test_es)
    monkeypatch.setattr(config, "USE_MOCK_ES", True)
    pipeline_manager.reset_state()
    yield test_es


def test_pipeline_health_endpoint():
    client = TestClient(app)
    response = client.get("/api/pipeline-health")
    assert response.status_code == 200
    data = response.json()
    assert "collector_running" in data
    assert "scheduler_running" in data
    assert "collector_poll_seconds" in data
    assert "correlation_interval_seconds" in data
    assert "last_event_ingested_at" in data
    assert "last_correlation_at" in data
    assert "last_tick_at" in data
    assert "last_alert_raised_at" in data
    assert "elasticsearch_status" in data
    assert "events_count" in data
    assert "alerts_count" in data


def test_redirect_routes():
    client = TestClient(app)
    for route in ["/open/soc", "/open/alerts", "/open/timeline", "/open/discover", "/open/events"]:
        resp = client.get(route, follow_redirects=False)
        assert resp.status_code in (302, 307)
        loc = resp.headers.get("location")
        assert loc is not None
        assert "refreshInterval:(pause:!f,value:2000)" in loc
        assert "time:(from:now-7d,to:now%2B1d)" in loc


def test_alerts_contain_created_at(setup_test_env):
    test_es = setup_test_env
    # Index brute force failure events
    events = []
    for i in range(6):
        ts = f"2026-10-15T12:0{i}:00Z"
        events.append({
            "_id": f"ev-bf-{i}",
            "_source": {
                "timestamp": ts,
                "event_type": "logon_failure",
                "source_ip": "198.51.100.99",
                "src_ip": "198.51.100.99",
                "user": "root",
                "host": "srv01"
            }
        })
    storage.bulk_index_events(test_es, events, config.INDEX_EVENTS)
    alerts = correlate.run_correlation(test_es)
    assert len(alerts) >= 1
    for a in alerts:
        assert "created_at" in a
        assert a["created_at"] is not None
        # Verify valid ISO / UTC timestamp format
        dt = datetime.fromisoformat(a["created_at"].replace("Z", "+00:00"))
        assert dt.tzinfo is not None


def test_scheduler_skips_when_no_new_events():
    mgr = PipelineManager()
    mgr.new_events_since_last_run = False
    assert mgr.new_events_since_last_run is False

    # Simulate event ingestion
    mgr.record_event_ingest(count=5)
    assert mgr.new_events_since_last_run is True
    assert mgr.last_event_ingested_at is not None

    # Simulate correlation run
    mgr.record_correlation_run([{"rule_name": "Test Alert", "severity": "high"}])
    assert mgr.new_events_since_last_run is False
    assert mgr.last_correlation_at is not None
    assert mgr.last_alert_raised_at is not None


def test_collector_incoming_archives_file(tmp_path, monkeypatch, setup_test_env):
    test_es = setup_test_env
    incoming_dir = tmp_path / "incoming"
    incoming_dir.mkdir()
    monkeypatch.setattr(config, "INCOMING_DIR", incoming_dir)

    # Place a telemetry log in incoming
    test_log = incoming_dir / "auth.log"
    test_log.write_text("Oct 15 10:00:00 srv01 sshd[101]: Accepted password for root from 10.0.0.1 port 22 ssh2\n", encoding="utf-8")

    results = collector.collect_incoming(incoming_dir, es=test_es)
    assert len(results) == 1
    assert results[0]["events_parsed"] == 1

    # Verify original file was archived into incoming/archive
    assert not (incoming_dir / "auth.log").exists()
    assert (incoming_dir / "archive" / "auth.log").exists()


def test_collector_incoming_rejects_unclassifiable_files(tmp_path, monkeypatch, setup_test_env, caplog):
    import logging
    test_es = setup_test_env
    incoming_dir = tmp_path / "incoming"
    incoming_dir.mkdir()
    monkeypatch.setattr(config, "INCOMING_DIR", incoming_dir)

    # Place an unclassifiable log file and a disallowed extension file
    unclassifiable = incoming_dir / "random_dump.log"
    unclassifiable.write_text("some random content\n", encoding="utf-8")
    disallowed = incoming_dir / "script.sh"
    disallowed.write_text("#!/bin/bash\necho hello\n", encoding="utf-8")

    # Also place a valid file
    valid = incoming_dir / "sshd.log"
    valid.write_text("Oct 15 10:00:00 srv01 sshd[101]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        results = collector.collect_incoming(incoming_dir, es=test_es)

    assert len(results) == 1
    assert results[0]["file_name"] == "sshd.log"

    # Valid file moved to archive
    assert not (incoming_dir / "sshd.log").exists()
    assert (incoming_dir / "archive" / "sshd.log").exists()

    # Rejected files moved to incoming/rejected
    assert not (incoming_dir / "random_dump.log").exists()
    assert not (incoming_dir / "script.sh").exists()
    assert (incoming_dir / "rejected" / "random_dump.log").exists()
    assert (incoming_dir / "rejected" / "script.sh").exists()

    # Verify log output: counts only, no file contents
    warning_logs = [rec.message for rec in caplog.records if rec.levelno >= logging.WARNING]
    assert any("Collector rejected 2 unclassifiable file(s)" in m for m in warning_logs)
    for m in warning_logs:
        assert "some random content" not in m
        assert "#!/bin/bash" not in m


def test_webhook_dispatched_for_critical_alerts(monkeypatch):
    mgr = PipelineManager()
    dispatched = []

    def mock_urlopen(req, timeout=3):
        data = req.data.decode("utf-8")
        dispatched.append(data)
        class MockResp:
            status = 200
        return MockResp()

    monkeypatch.setattr("urllib.request.urlopen", mock_urlopen)
    monkeypatch.setattr(config, "WEBHOOK_URL", "http://127.0.0.1:9999/webhook")

    alerts = [
        {"rule_name": "Successful Brute Force", "severity": "critical", "user": "admin", "host": "srv01", "created_at": "2026-10-15T12:00:00Z"},
        {"rule_name": "Unusual Process", "severity": "medium", "user": "alice", "host": "workstation"}
    ]
    mgr._dispatch_webhooks_for_critical_alerts(alerts)

    assert len(dispatched) == 1
    assert "Successful Brute Force" in dispatched[0]
    assert "critical" in dispatched[0]


def test_scheduler_cycle_updates_tick_and_correlation_when_skipped(monkeypatch):
    mgr = PipelineManager()
    mgr.new_events_since_last_run = False
    mgr.last_tick_at = "2020-01-01T00:00:00+00:00"
    mgr.last_correlation_at = "2020-01-01T00:00:00+00:00"

    async def _run():
        mgr._stop_event = asyncio.Event()

        async def stop_soon():
            await asyncio.sleep(0.05)
            mgr._stop_event.set()

        monkeypatch.setattr(config, "CORRELATION_INTERVAL_SECONDS", 0.01)
        asyncio.create_task(stop_soon())
        await mgr._correlation_scheduler_loop()

    asyncio.run(_run())

    assert mgr.last_tick_at != "2020-01-01T00:00:00+00:00"
    assert mgr.last_correlation_at != "2020-01-01T00:00:00+00:00"
    health = mgr.get_health()
    assert "last_tick_at" in health
    assert health["last_tick_at"] == mgr.last_tick_at
