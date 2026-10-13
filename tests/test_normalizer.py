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
