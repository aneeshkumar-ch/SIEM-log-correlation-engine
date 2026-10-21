import pytest
import json
import normalizer


def test_linux_auth_accepted():
    log = "Oct 13 10:15:30 debian sshd[12345]: Accepted password for alice from 192.168.1.105 port 45212 ssh2"
    events, skipped = normalizer.normalize_content(log, "linux_auth")
    assert len(events) == 1
    assert len(skipped) == 0
    ev = events[0]["_source"]
    assert ev["source_type"] == "linux_auth"
    assert ev["event_type"] == "logon_success"
    assert ev["user"] == "alice"
    assert ev["src_ip"] == "192.168.1.105"
    assert ev["host"] == "debian"
    assert ev["timestamp"].endswith("Z")
    assert "2026" in ev["timestamp"] or "10-13" in ev["timestamp"]


def test_linux_auth_failed():
    log = "Oct 13 10:15:32 debian sshd[12346]: Failed password for invalid user admin from 10.0.0.99 port 51234 ssh2"
    events, skipped = normalizer.normalize_content(log, "linux_auth")
    assert len(events) == 1
    assert len(skipped) == 0
    ev = events[0]["_source"]
    assert ev["source_type"] == "linux_auth"
    assert ev["event_type"] == "logon_failure"
    assert ev["user"] == "admin"
    assert ev["src_ip"] == "10.0.0.99"


def test_linux_auth_sudo():
    log = "Oct 13 10:16:00 debian sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash"
    events, skipped = normalizer.normalize_content(log, "linux_auth")
    assert len(events) == 1
    assert len(skipped) == 0
    ev = events[0]["_source"]
    assert ev["event_type"] == "process_create"
    assert ev["user"] == "alice"
    assert ev["process_name"] == "/bin/bash"


def test_windows_security_json():
    lines = "\n".join([
        json.dumps({
            "EventID": 4624,
            "TimeCreated": "2026-10-13T10:20:00Z",
            "Computer": "WIN-SRV01",
            "TargetUserName": "alice",
            "IpAddress": "192.168.1.50"
        }),
        json.dumps({
            "EventID": 4625,
            "TimeCreated": "2026-10-13T10:20:05Z",
            "Computer": "WIN-SRV01",
            "TargetUserName": "bob",
            "IpAddress": "192.168.1.60"
        }),
        json.dumps({
            "EventID": 4688,
            "TimeCreated": "2026-10-13T10:21:00Z",
            "Computer": "WIN-SRV01",
            "TargetUserName": "alice",
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        })
    ])

    events, skipped = normalizer.normalize_content(lines, "windows_security")
    assert len(events) == 3
    assert len(skipped) == 0

    assert events[0]["_source"]["event_type"] == "logon_success"
    assert events[0]["_source"]["user"] == "alice"

    assert events[1]["_source"]["event_type"] == "logon_failure"
    assert events[1]["_source"]["src_ip"] == "192.168.1.60"

    assert events[2]["_source"]["event_type"] == "process_create"
    assert events[2]["_source"]["process_name"] == "powershell.exe"


def test_windows_security_csv():
    csv_data = """EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
4624,2026-10-13T10:20:00Z,WIN-SRV01,john,10.0.0.15,
4688,2026-10-13T10:21:15Z,WIN-SRV01,john,,cmd.exe
"""
    events, skipped = normalizer.normalize_content(csv_data, "windows_security")
    assert len(events) == 2
    assert len(skipped) == 0
    assert events[0]["_source"]["user"] == "john"
    assert events[0]["_source"]["event_type"] == "logon_success"
    assert events[1]["_source"]["process_name"] == "cmd.exe"
    assert events[1]["_source"]["event_type"] == "process_create"


def test_firewall_normalization():
    log = "Oct 13 10:15:30 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.22 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22"
    events, skipped = normalizer.normalize_content(log, "firewall")
    assert len(events) == 1
    assert len(skipped) == 0
    ev = events[0]["_source"]
    assert ev["source_type"] == "firewall"
    assert ev["event_type"] == "network_connection"
    assert ev["src_ip"] == "198.51.100.22"
    assert ev["host"] == "fw01"


def test_skipped_bad_lines_do_not_fail_batch():
    content = """Oct 13 10:15:30 debian sshd[12345]: Accepted password for alice from 192.168.1.105 port 45212 ssh2
THIS IS A BAD UNPARSABLE CORRUPTED LOG LINE
Oct 13 10:15:32 debian sshd[12346]: Failed password for invalid user admin from 10.0.0.99 port 51234 ssh2
"""
    events, skipped = normalizer.normalize_content(content, "linux_auth")
    assert len(events) == 2
    assert len(skipped) == 1
    assert skipped[0]["line_number"] == 2
    assert "THIS IS A BAD" in skipped[0]["raw"]


def test_deterministic_id():
    log = "Oct 13 10:15:30 debian sshd[12345]: Accepted password for alice from 192.168.1.105 port 45212 ssh2"
    ev1, _ = normalizer.normalize_content(log, "linux_auth")
    ev2, _ = normalizer.normalize_content(log, "linux_auth")
    assert ev1[0]["_id"] == ev2[0]["_id"]


def test_windows_sysmon_events():
    events_raw = "\n".join([
        json.dumps({
            "EventID": 1,
            "UtcTime": "2026-10-13T10:30:00Z",
            "Computer": "WIN-SRV02",
            "User": "victim_user",
            "Image": "C:\\Windows\\System32\\cmd.exe"
        }),
        json.dumps({
            "EventID": 3,
            "UtcTime": "2026-10-13T10:30:05Z",
            "Computer": "WIN-SRV02",
            "SourceIp": "192.168.1.50",
            "DestinationIp": "10.0.0.99",
            "DestinationPort": 445
        }),
        json.dumps({
            "EventID": 4672,
            "TimeCreated": "2026-10-13T10:30:10Z",
            "Computer": "WIN-SRV02",
            "TargetUserName": "admin_user"
        })
    ])
    events, skipped = normalizer.normalize_content(events_raw, "windows_sysmon")
    assert len(events) == 3
    assert len(skipped) == 0

    e1 = events[0]["_source"]
    assert e1["source"] == "Windows"
    assert e1["event_type"] == "process_create"
    assert e1["process_name"] == "cmd.exe"
    assert e1["severity"] == "medium"

    e2 = events[1]["_source"]
    assert e2["source"] == "Windows"
    assert e2["event_type"] == "network_connection"
    assert e2["source_ip"] == "192.168.1.50"
    assert e2["destination_ip"] == "10.0.0.99"
    assert e2["destination_port"] == 445

    e3 = events[2]["_source"]
    assert e3["source"] == "Windows"
    assert e3["event_type"] == "privilege_escalation"
    assert e3["severity"] == "high"


def test_linux_auditd_syscall_and_file_access():
    audit_log = "type=SYSCALL msg=audit(1697191230.123:456): arch=c000003e syscall=59 success=yes exit=0 auid=1000 uid=0 euid=0 exe=\"/usr/bin/cat\" comm=\"cat\" name=\"/etc/shadow\" host=linux-prod"
    events, skipped = normalizer.normalize_content(audit_log, "linux_auditd")
    assert len(events) == 1
    assert len(skipped) == 0
    ev = events[0]["_source"]
    assert ev["source"] == "Linux"
    assert ev["event_type"] == "file_access"
    assert ev["process_name"] == "cat"
    assert ev["severity"] == "high"
    assert ev["file_path"] == "/etc/shadow"
    assert ev["host"] == "linux-prod"


def test_network_firewall_source_and_tagging():
    log = "Oct 13 10:15:30 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.5 DST=192.168.1.200 PROTO=TCP SPT=44321 DPT=80"
    events, skipped = normalizer.normalize_content(log, "network_firewall")
    assert len(events) == 1
    ev = events[0]["_source"]
    assert ev["source"] == "Network"
    assert ev["source_ip"] == "203.0.113.5"
    assert ev["destination_ip"] == "192.168.1.200"
    assert ev["destination_port"] == 80
    assert ev["severity"] == "medium"
    assert "public" in ev["ip_tags"]
    assert "external" in ev["ip_tags"]


def test_sample_log_generator_timestamps_within_last_24_hours(tmp_path):
    """Verifies that all generated sample logs use timestamps within the last 24 hours."""
    from datetime import datetime, timezone, timedelta
    import sample_log_generator

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    files = sample_log_generator.generate_sample_logs(output_dir=tmp_path)

    for stype, fpath in [("windows_sysmon", files["windows"]),
                         ("linux_auditd", files["linux"]),
                         ("network_firewall", files["network"])]:
        with open(fpath, "r", encoding="utf-8") as f:
            events, skipped = normalizer.normalize_content(f.read(), stype)
            assert len(skipped) == 0, f"Expected 0 skipped lines in {stype}, got {skipped}"
            assert len(events) > 0, f"Expected events in {stype}"
            for ev in events:
                src = ev["_source"]
                ts = src.get("timestamp") or src.get("@timestamp")
                assert ts is not None, f"Missing timestamp in normalized event: {src}"
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                assert cutoff <= dt <= (now + timedelta(minutes=5)), (
                    f"Generated timestamp {dt} for {stype} is not within the last 24 hours (cutoff: {cutoff})"
                )

