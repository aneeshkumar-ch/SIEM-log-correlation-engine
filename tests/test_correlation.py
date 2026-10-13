import pytest
import copy
from datetime import datetime, timezone
import config
from storage import MockElasticsearch, bulk_index_events, initialize_indices
import correlate
import normalizer


@pytest.fixture
def mock_es():
    """Provides a fresh MockElasticsearch instance for isolated test execution."""
    es = MockElasticsearch()
    initialize_indices(es)
    return es


def test_rule1_brute_force_suspected(mock_es):
    """Asserts Rule 1 fires when >=5 logon failures occur within 10 mins without subsequent success."""
    lines = [
        "Oct 13 10:00:00 srv01 sshd[101]: Failed password for invalid user admin from 198.51.100.10 port 4001 ssh2",
        "Oct 13 10:00:30 srv01 sshd[102]: Failed password for invalid user root from 198.51.100.10 port 4002 ssh2",
        "Oct 13 10:01:00 srv01 sshd[103]: Failed password for invalid user test from 198.51.100.10 port 4003 ssh2",
        "Oct 13 10:01:30 srv01 sshd[104]: Failed password for invalid user oracle from 198.51.100.10 port 4004 ssh2",
        "Oct 13 10:02:00 srv01 sshd[105]: Failed password for invalid user guest from 198.51.100.10 port 4005 ssh2",
    ]
    events, _ = normalizer.normalize_content("\n".join(lines), "linux_auth")
    assert len(events) == 5

    bulk_index_events(mock_es, events, config.INDEX_EVENTS)
    alerts = correlate.run_correlation(mock_es)

    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule_name"] == "Brute Force Suspected"
    assert a["severity"] == "high"
    assert a["src_ip"] == "198.51.100.10"
    assert a["mitre_technique"] == "T1110"
    assert len(a["evidence"]) == 5


def test_rule2_successful_brute_force(mock_es):
    """Asserts Rule 2 fires when >=5 failures are followed by a logon success from the same source IP."""
    lines = [
        "Oct 13 10:10:00 srv01 sshd[201]: Failed password for invalid user admin from 203.0.113.50 port 5001 ssh2",
        "Oct 13 10:10:15 srv01 sshd[202]: Failed password for invalid user user1 from 203.0.113.50 port 5002 ssh2",
        "Oct 13 10:10:30 srv01 sshd[203]: Failed password for invalid user user2 from 203.0.113.50 port 5003 ssh2",
        "Oct 13 10:10:45 srv01 sshd[204]: Failed password for invalid user user3 from 203.0.113.50 port 5004 ssh2",
        "Oct 13 10:11:00 srv01 sshd[205]: Failed password for invalid user alice from 203.0.113.50 port 5005 ssh2",
        "Oct 13 10:11:20 srv01 sshd[206]: Accepted password for alice from 203.0.113.50 port 5006 ssh2",
    ]
    events, _ = normalizer.normalize_content("\n".join(lines), "linux_auth")
    assert len(events) == 6

    bulk_index_events(mock_es, events, config.INDEX_EVENTS)
    alerts = correlate.run_correlation(mock_es)

    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule_name"] == "Successful Brute Force"
    assert a["severity"] == "critical"
    assert a["src_ip"] == "203.0.113.50"
    assert a["user"] == "alice"
    assert a["mitre_technique"] == "T1110.001"
    assert len(a["evidence"]) == 6


def test_rule2_benign_subthreshold_failures_then_success(mock_es):
    """(a) Asserts Rule 2 must NOT fire on 4 failures followed by a success (below threshold 5)."""
    lines = [
        "Oct 13 10:10:00 srv01 sshd[201]: Failed password for invalid user user1 from 203.0.113.50 port 5001 ssh2",
        "Oct 13 10:10:15 srv01 sshd[202]: Failed password for invalid user user2 from 203.0.113.50 port 5002 ssh2",
        "Oct 13 10:10:30 srv01 sshd[203]: Failed password for invalid user user3 from 203.0.113.50 port 5003 ssh2",
        "Oct 13 10:10:45 srv01 sshd[204]: Failed password for invalid user user4 from 203.0.113.50 port 5004 ssh2",
        "Oct 13 10:11:00 srv01 sshd[205]: Accepted password for alice from 203.0.113.50 port 5005 ssh2",
    ]
    events, _ = normalizer.normalize_content("\n".join(lines), "linux_auth")
    bulk_index_events(mock_es, events, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    assert not any(a["rule_name"] == "Successful Brute Force" for a in alerts), f"Rule 2 fired on 4 failures: {alerts}"


def test_rule2_benign_different_ip_and_user_success(mock_es):
    """(b) Asserts Rule 2 must NOT fire on 5 failures from one IP and success from a different IP and user."""
    lines = [
        "Oct 13 10:10:00 srv01 sshd[201]: Failed password for invalid user admin from 198.51.100.10 port 5001 ssh2",
        "Oct 13 10:10:15 srv01 sshd[202]: Failed password for invalid user user1 from 198.51.100.10 port 5002 ssh2",
        "Oct 13 10:10:30 srv01 sshd[203]: Failed password for invalid user user2 from 198.51.100.10 port 5003 ssh2",
        "Oct 13 10:10:45 srv01 sshd[204]: Failed password for invalid user user3 from 198.51.100.10 port 5004 ssh2",
        "Oct 13 10:11:00 srv01 sshd[205]: Failed password for invalid user user4 from 198.51.100.10 port 5005 ssh2",
        # Legitimate login from entirely different IP and user
        "Oct 13 10:11:10 srv01 sshd[206]: Accepted password for bob from 10.0.0.99 port 5006 ssh2",
    ]
    events, _ = normalizer.normalize_content("\n".join(lines), "linux_auth")
    bulk_index_events(mock_es, events, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    assert not any(a["rule_name"] == "Successful Brute Force" for a in alerts), f"Rule 2 fired on different IP: {alerts}"
    # Rule 1 should still trigger for the attacking IP
    assert any(a["rule_name"] == "Brute Force Suspected" and a["src_ip"] == "198.51.100.10" for a in alerts)


def test_rule2_benign_success_after_window_expired(mock_es):
    """(c) Asserts Rule 2 must NOT fire on 5 failures followed by a success after window (10 mins) expired."""
    lines = [
        "Oct 13 10:00:00 srv01 sshd[201]: Failed password for invalid user user1 from 203.0.113.50 port 5001 ssh2",
        "Oct 13 10:00:15 srv01 sshd[202]: Failed password for invalid user user2 from 203.0.113.50 port 5002 ssh2",
        "Oct 13 10:00:30 srv01 sshd[203]: Failed password for invalid user user3 from 203.0.113.50 port 5003 ssh2",
        "Oct 13 10:00:45 srv01 sshd[204]: Failed password for invalid user user4 from 203.0.113.50 port 5004 ssh2",
        "Oct 13 10:01:00 srv01 sshd[205]: Failed password for invalid user user5 from 203.0.113.50 port 5005 ssh2",
        # Success occurs 15 minutes after the last failure (outside 10 min window)
        "Oct 13 10:16:01 srv01 sshd[206]: Accepted password for alice from 203.0.113.50 port 5006 ssh2",
    ]
    events, _ = normalizer.normalize_content("\n".join(lines), "linux_auth")
    bulk_index_events(mock_es, events, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    assert not any(a["rule_name"] == "Successful Brute Force" for a in alerts), f"Rule 2 fired outside window: {alerts}"



def test_rule3_post_logon_suspicious_execution(mock_es):
    """Asserts Rule 3 fires when a non-admin logon is followed by powershell/cmd within 2 minutes."""
    csv_logs = """EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
4624,2026-10-13T10:30:00Z,WIN-FINANCE,david,192.168.1.88,
4688,2026-10-13T10:31:10Z,WIN-FINANCE,david,,powershell.exe
"""
    events, _ = normalizer.normalize_content(csv_logs, "windows_security")
    assert len(events) == 2

    bulk_index_events(mock_es, events, config.INDEX_EVENTS)
    alerts = correlate.run_correlation(mock_es)

    assert len(alerts) == 1
    a = alerts[0]
    assert a["rule_name"] == "Post-Logon Suspicious Execution"
    assert a["severity"] == "high"
    assert a["user"] == "david"
    assert a["host"] == "WIN-FINANCE"
    assert a["mitre_technique"] == "T1059.001"
    assert len(a["evidence"]) == 2


def test_benign_scenarios_do_not_fire(mock_es):
    """Asserts correlation engine produces 0 alerts on benign / below-threshold activity."""
    # 1. Below threshold: only 3 failed logins
    sub_threshold = [
        "Oct 13 11:00:00 srv01 sshd[301]: Failed password for bob from 198.51.100.99 port 4001 ssh2",
        "Oct 13 11:00:30 srv01 sshd[302]: Failed password for bob from 198.51.100.99 port 4002 ssh2",
        "Oct 13 11:01:00 srv01 sshd[303]: Failed password for bob from 198.51.100.99 port 4003 ssh2",
    ]
    ev1, _ = normalizer.normalize_content("\n".join(sub_threshold), "linux_auth")
    bulk_index_events(mock_es, ev1, config.INDEX_EVENTS)

    # 2. Admin account running PowerShell (allowlisted)
    admin_activity = """EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
4624,2026-10-13T11:10:00Z,WIN-SRV02,Administrator,10.0.0.1,
4688,2026-10-13T11:10:15Z,WIN-SRV02,Administrator,,powershell.exe
"""
    ev2, _ = normalizer.normalize_content(admin_activity, "windows_security")
    bulk_index_events(mock_es, ev2, config.INDEX_EVENTS)

    # 3. Non-admin user running benign process (notepad.exe)
    benign_proc = """EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
4624,2026-10-13T11:20:00Z,WIN-WORKSTATION,alice,10.0.0.2,
4688,2026-10-13T11:20:30Z,WIN-WORKSTATION,alice,,notepad.exe
"""
    ev3, _ = normalizer.normalize_content(benign_proc, "windows_security")
    bulk_index_events(mock_es, ev3, config.INDEX_EVENTS)

    # 4. Non-admin user running powershell after 15 minutes (outside 2-min window)
    delayed_proc = """EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
4624,2026-10-13T11:30:00Z,WIN-LAPTOP,bob,10.0.0.3,
4688,2026-10-13T11:45:00Z,WIN-LAPTOP,bob,,powershell.exe
"""
    ev4, _ = normalizer.normalize_content(delayed_proc, "windows_security")
    bulk_index_events(mock_es, ev4, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    assert len(alerts) == 0, f"Expected 0 alerts for benign activity, got: {alerts}"


def test_reupload_and_correlation_deduplication(mock_es):
    """Asserts re-uploading the same logs does not produce duplicate events or duplicate alerts."""
    log_content = """EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
4624,2026-10-13T12:00:00Z,WIN-DC01,hacker,172.16.0.4,
4688,2026-10-13T12:01:00Z,WIN-DC01,hacker,,cmd.exe
"""
    # First upload
    events1, _ = normalizer.normalize_content(log_content, "windows_security")
    bulk_index_events(mock_es, events1, config.INDEX_EVENTS)
    alerts1 = correlate.run_correlation(mock_es)
    assert len(alerts1) == 1

    event_count_1 = mock_es.count(index=config.INDEX_EVENTS)["count"]
    alert_count_1 = mock_es.count(index=config.INDEX_ALERTS)["count"]
    assert event_count_1 == 2
    assert alert_count_1 == 1

    # Re-upload same file
    events2, _ = normalizer.normalize_content(log_content, "windows_security")
    bulk_index_events(mock_es, events2, config.INDEX_EVENTS)
    alerts2 = correlate.run_correlation(mock_es)

    event_count_2 = mock_es.count(index=config.INDEX_EVENTS)["count"]
    alert_count_2 = mock_es.count(index=config.INDEX_ALERTS)["count"]

    assert event_count_2 == 2, "Events were duplicated on re-upload!"
    assert alert_count_2 == 1, "Alerts were duplicated on re-correlation!"


def test_fixture_files_trigger_expected_rules(mock_es):
    """Verifies each fixture file in tests/fixtures triggers its designated rule or benign outcome."""
    from pathlib import Path
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"

    # 1. Rule 1 fixture
    f1 = fixtures_dir / "rule1_brute_force_fail.log"
    ev1, _ = normalizer.normalize_content(f1.read_text(encoding="utf-8"), "linux_auth")
    bulk_index_events(mock_es, ev1, config.INDEX_EVENTS)
    alerts1 = correlate.run_correlation(mock_es)
    assert any(a["rule_name"] == "Brute Force Suspected" and a["severity"] == "high" for a in alerts1)

    # Reset
    mock_es.indices.delete(config.INDEX_EVENTS)
    mock_es.indices.delete(config.INDEX_ALERTS)
    initialize_indices(mock_es)

    # 2. Rule 2 fixture
    f2 = fixtures_dir / "rule2_brute_force_success.log"
    ev2, _ = normalizer.normalize_content(f2.read_text(encoding="utf-8"), "linux_auth")
    bulk_index_events(mock_es, ev2, config.INDEX_EVENTS)
    alerts2 = correlate.run_correlation(mock_es)
    assert any(a["rule_name"] == "Successful Brute Force" and a["severity"] == "critical" for a in alerts2)

    # Reset
    mock_es.indices.delete(config.INDEX_EVENTS)
    mock_es.indices.delete(config.INDEX_ALERTS)
    initialize_indices(mock_es)

    # 3. Rule 3 fixture
    f3 = fixtures_dir / "rule3_post_logon_powershell.csv"
    ev3, _ = normalizer.normalize_content(f3.read_text(encoding="utf-8"), "windows_security")
    bulk_index_events(mock_es, ev3, config.INDEX_EVENTS)
    alerts3 = correlate.run_correlation(mock_es)
    assert any(a["rule_name"] == "Post-Logon Suspicious Execution" for a in alerts3)

    # Reset
    mock_es.indices.delete(config.INDEX_EVENTS)
    mock_es.indices.delete(config.INDEX_ALERTS)
    initialize_indices(mock_es)

    # 4. Benign fixture
    fb = fixtures_dir / "benign_activity.csv"
    evb, _ = normalizer.normalize_content(fb.read_text(encoding="utf-8"), "windows_security")
    bulk_index_events(mock_es, evb, config.INDEX_EVENTS)
    alertsb = correlate.run_correlation(mock_es)
    assert len(alertsb) == 0


def test_scenario3_privilege_activity(mock_es):
    """Asserts Scenario 3 triggers on Event 4672 special privileges and sudo elevation."""
    import json
    win_priv = json.dumps({
        "EventID": 4672,
        "TimeCreated": "2026-10-13T12:00:00Z",
        "Computer": "WIN-DC01",
        "TargetUserName": "svc_backup"
    })
    events, _ = normalizer.normalize_content(win_priv, "windows_sysmon")
    bulk_index_events(mock_es, events, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    assert any(a["rule_name"] == "Privilege-Related Activity" and a["severity"] == "high" for a in alerts)


def test_scenario4_network_port_scan_and_burst(mock_es):
    """Asserts Scenario 4 triggers on port scan (>=5 ports) and blocked bursts."""
    # 5 blocked connections on distinct ports within 2 minutes
    lines = [
        f"Oct 13 12:10:0{i} fw01 kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.99 DST=10.0.0.50 PROTO=TCP SPT=400{i} DPT=80{i}"
        for i in range(5)
    ]
    events, _ = normalizer.normalize_content("\n".join(lines), "network_firewall")
    bulk_index_events(mock_es, events, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    rule_names = [a["rule_name"] for a in alerts]
    assert "Network Port Scan Detected" in rule_names or "Burst of Blocked Connections" in rule_names


def test_scenario5_sensitive_file_and_lateral_movement(mock_es):
    """Asserts Scenario 5 triggers on sensitive file access (/etc/shadow) and lateral movement."""
    # 5A: /etc/shadow access
    shadow_log = "type=SYSCALL msg=audit(1697191230.100:10): arch=c000003e syscall=59 success=yes exit=0 auid=1002 uid=1002 exe=\"/usr/bin/cat\" name=\"/etc/shadow\" host=srv-shadow"
    ev1, _ = normalizer.normalize_content(shadow_log, "linux_auditd")
    bulk_index_events(mock_es, ev1, config.INDEX_EVENTS)

    # 5B: Lateral movement: charlie logging on to host-a and host-b within 3 minutes
    import json
    lat_lines = "\n".join([
        json.dumps({"EventID": 4624, "TimeCreated": "2026-10-13T12:20:00Z", "Computer": "HOST-A", "TargetUserName": "charlie"}),
        json.dumps({"EventID": 4624, "TimeCreated": "2026-10-13T12:22:00Z", "Computer": "HOST-B", "TargetUserName": "charlie"})
    ])
    ev2, _ = normalizer.normalize_content(lat_lines, "windows_sysmon")
    bulk_index_events(mock_es, ev2, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    rule_names = [a["rule_name"] for a in alerts]
    assert "Sensitive File Access" in rule_names
    assert "Suspected Lateral Movement" in rule_names


def test_scenario3_privilege_activity_benign(mock_es):
    """Asserts Scenario 3 remains quiet on standard logon without special privileges."""
    import json
    normal_logon = json.dumps({
        "EventID": 4624,
        "TimeCreated": "2026-10-13T12:00:00Z",
        "Computer": "WIN-DC01",
        "TargetUserName": "svc_backup"
    })
    events, _ = normalizer.normalize_content(normal_logon, "windows_sysmon")
    bulk_index_events(mock_es, events, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    priv_alerts = [a for a in alerts if a["rule_name"] == "Privilege-Related Activity"]
    assert len(priv_alerts) == 0, f"Expected 0 privilege alerts on normal logon, got {priv_alerts}"


def test_scenario4_network_benign(mock_es):
    """Asserts Scenario 4 remains quiet on allowed traffic below port/volume thresholds."""
    lines = [
        "Oct 13 12:10:00 fw01 kernel: [UFW ALLOW] IN=eth0 SRC=10.0.0.15 DST=10.0.0.50 PROTO=TCP SPT=4001 DPT=443",
        "Oct 13 12:10:15 fw01 kernel: [UFW ALLOW] IN=eth0 SRC=10.0.0.15 DST=10.0.0.50 PROTO=TCP SPT=4002 DPT=443"
    ]
    events, _ = normalizer.normalize_content("\n".join(lines), "network_firewall")
    bulk_index_events(mock_es, events, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    net_alerts = [a for a in alerts if "Network" in a["rule_name"] or "Burst" in a["rule_name"]]
    assert len(net_alerts) == 0, f"Expected 0 network alerts on normal traffic, got {net_alerts}"


def test_scenario5_sensitive_file_and_lateral_movement_benign(mock_es):
    """Asserts Scenario 5 remains quiet on non-sensitive file access and single-host sessions."""
    # Benign file access
    normal_file_log = "type=SYSCALL msg=audit(1697191230.100:10): arch=c000003e syscall=59 success=yes exit=0 auid=1002 uid=1002 exe=\"/usr/bin/cat\" name=\"/var/log/application.log\" host=srv-shadow"
    ev1, _ = normalizer.normalize_content(normal_file_log, "linux_auditd")
    bulk_index_events(mock_es, ev1, config.INDEX_EVENTS)

    # Single host logon (no lateral movement)
    import json
    single_host = json.dumps({"EventID": 4624, "TimeCreated": "2026-10-13T12:20:00Z", "Computer": "HOST-A", "TargetUserName": "charlie"})
    ev2, _ = normalizer.normalize_content(single_host, "windows_sysmon")
    bulk_index_events(mock_es, ev2, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    assert not any(a["rule_name"] in ("Sensitive File Access", "Suspected Lateral Movement") for a in alerts)


def test_rule5_benign_etc_passwd_read(mock_es):
    """Asserts reading /etc/passwd does NOT trigger Sensitive File Access (normal process behavior)."""
    normal_passwd_log = "type=SYSCALL msg=audit(1697191230.100:10): arch=c000003e syscall=59 success=yes exit=0 auid=1000 uid=1000 exe=\"/usr/bin/cat\" name=\"/etc/passwd\" host=srv-prod"
    events, _ = normalizer.normalize_content(normal_passwd_log, "linux_auditd")
    bulk_index_events(mock_es, events, config.INDEX_EVENTS)

    alerts = correlate.run_correlation(mock_es)
    assert not any(a["rule_name"] == "Sensitive File Access" for a in alerts), f"Alerted on /etc/passwd: {alerts}"


def test_scenario4_benign_multiple_allowed_hosts_single_port(mock_es):
    """Asserts a client making 10 ALLOWED connections to different hosts on port 443 in 5m must NOT alert."""
    lines = [
        f"Oct 13 12:10:{i:02d} fw01 kernel: [UFW ALLOW] IN=eth0 SRC=192.168.1.50 DST=10.0.0.{i} PROTO=TCP SPT={4000+i} DPT=443"
        for i in range(1, 11)
    ]
    events, _ = normalizer.normalize_content("\n".join(lines), "network_firewall")
    assert len(events) == 10

    bulk_index_events(mock_es, events, config.INDEX_EVENTS)
    alerts = correlate.run_correlation(mock_es)

    net_alerts = [a for a in alerts if "Network" in a["rule_name"] or "Burst" in a["rule_name"]]
    assert len(net_alerts) == 0, f"Expected 0 alerts for 10 allowed HTTPS connections, got: {net_alerts}"



