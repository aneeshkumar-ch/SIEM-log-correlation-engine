"""
Sample Log Generator for SIEM Correlation Engine (BCSSL Lab 07).
Controlled, reproducible (seeded), writes synthetic Windows, Linux, and Network
sample files to ./sample_logs on demand only.
NEVER runs automatically and NEVER reads real system logs.
"""

import sys
import json
import random
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any

import config


def generate_sample_logs(output_dir: Path = config.SAMPLE_LOGS_DIR, seed: int = 42) -> Dict[str, str]:
    """Generates synthetic reproducible training log datasets for Windows, Linux, and Network.
    Returns mapping of log type to absolute file path.
    """
    rng = random.Random(seed)
    output_dir.mkdir(parents=True, exist_ok=True)

    base_time = datetime(2026, 10, 13, 10, 0, 0, tzinfo=timezone.utc)

    # -------------------------------------------------------------------------
    # 1. Windows Sysmon & Security Samples (JSONL)
    # -------------------------------------------------------------------------
    windows_file = output_dir / "windows_samples.json"
    win_events = []

    # Scenario 1 events: 5 Failed Logons from attacker 198.51.100.25 within 3 minutes
    for i in range(5):
        t = base_time + timedelta(seconds=i * 30)
        win_events.append({
            "EventID": 4625,
            "TimeCreated": t.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Computer": "WIN-SRV01",
            "TargetUserName": "admin",
            "IpAddress": "198.51.100.25",
            "LogonType": 3
        })

    # Followed by 1 Logon Success (Critical Brute Force)
    win_events.append({
        "EventID": 4624,
        "TimeCreated": (base_time + timedelta(seconds=180)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Computer": "WIN-SRV01",
        "TargetUserName": "admin",
        "IpAddress": "198.51.100.25",
        "LogonType": 3
    })

    # Scenario 2 events: Logon Success by alice, then PowerShell execution within 45s
    t_alice_logon = base_time + timedelta(minutes=15)
    win_events.append({
        "EventID": 4624,
        "TimeCreated": t_alice_logon.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Computer": "WIN-WS04",
        "TargetUserName": "alice",
        "IpAddress": "192.168.1.55",
        "LogonType": 2
    })
    win_events.append({
        "EventID": 4688,
        "TimeCreated": (t_alice_logon + timedelta(seconds=45)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Computer": "WIN-WS04",
        "TargetUserName": "alice",
        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\Temp\\script.ps1"
    })

    # Scenario 3 events: Event 4672 Special Privileges Assigned
    win_events.append({
        "EventID": 4672,
        "TimeCreated": (base_time + timedelta(minutes=25)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "Computer": "WIN-SRV01",
        "TargetUserName": "service_account",
        "PrivilegeList": "SeDebugPrivilege SeTcbPrivilege"
    })

    # Scenario 5 events: Lateral movement (user bob logs on to WIN-SRV01, WIN-SRV02, WIN-SRV03 in 5m)
    t_bob = base_time + timedelta(minutes=30)
    for idx, host in enumerate(["WIN-SRV01", "WIN-SRV02", "WIN-SRV03"]):
        win_events.append({
            "EventID": 4624,
            "TimeCreated": (t_bob + timedelta(seconds=idx * 60)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Computer": host,
            "TargetUserName": "bob",
            "IpAddress": "192.168.1.102"
        })

    with open(windows_file, "w", encoding="utf-8") as f:
        for ev in win_events:
            f.write(json.dumps(ev) + "\n")

    # -------------------------------------------------------------------------
    # 2. Linux Auditd & Auth Samples (Syslog / Auditd text format)
    # -------------------------------------------------------------------------
    linux_file = output_dir / "linux_samples.log"
    linux_lines = []

    # Scenario 1 (Linux): 6 Failed SSH password attempts from 203.0.113.88
    t_lx = base_time + timedelta(minutes=5)
    for i in range(6):
        t = t_lx + timedelta(seconds=i * 20)
        ts_str = t.strftime("%b %d %H:%M:%S")
        linux_lines.append(f"{ts_str} debian-srv sshd[220{i}]: Failed password for invalid user root from 203.0.113.88 port 421{i} ssh2")

    # Scenario 3 (Linux): Non-admin user elevating with sudo
    t_sudo = base_time + timedelta(minutes=18)
    ts_sudo_str = t_sudo.strftime("%b %d %H:%M:%S")
    linux_lines.append(f"{ts_sudo_str} debian-srv sudo:   charlie : TTY=pts/1 ; PWD=/home/charlie ; USER=root ; COMMAND=/bin/bash")

    # Scenario 5 (Linux): Auditd sensitive file access to /etc/shadow
    epoch_shadow = (base_time + timedelta(minutes=22)).timestamp()
    linux_lines.append(
        f"type=SYSCALL msg=audit({epoch_shadow:.3f}:789): arch=c000003e syscall=59 success=yes exit=0 "
        f"auid=1001 uid=1001 euid=0 exe=\"/usr/bin/cat\" comm=\"cat\" name=\"/etc/shadow\" host=debian-srv"
    )

    with open(linux_file, "w", encoding="utf-8") as f:
        f.write("\n".join(linux_lines) + "\n")

    # -------------------------------------------------------------------------
    # 3. Network Firewall Samples (UFW text format)
    # -------------------------------------------------------------------------
    network_file = output_dir / "network_samples.log"
    net_lines = []

    # Scenario 4: Port Scan (1 source IP 198.51.100.99 scanning ports 21, 22, 80, 443, 8080, 3389 in 2m)
    t_scan = base_time + timedelta(minutes=10)
    scan_ports = [21, 22, 80, 443, 8080, 3389]
    for idx, port in enumerate(scan_ports):
        t = t_scan + timedelta(seconds=idx * 15)
        ts_str = t.strftime("%b %d %H:%M:%S")
        net_lines.append(
            f"{ts_str} fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.99 DST=10.0.0.10 PROTO=TCP SPT=551{idx} DPT={port}"
        )

    # Bursts of blocked connections from 198.51.100.150
    t_burst = base_time + timedelta(minutes=35)
    for i in range(6):
        t = t_burst + timedelta(seconds=i * 10)
        ts_str = t.strftime("%b %d %H:%M:%S")
        net_lines.append(
            f"{ts_str} fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.150 DST=10.0.0.25 PROTO=TCP SPT=491{i} DPT=445"
        )

    with open(network_file, "w", encoding="utf-8") as f:
        f.write("\n".join(net_lines) + "\n")

    return {
        "windows": str(windows_file),
        "linux": str(linux_file),
        "network": str(network_file)
    }


if __name__ == "__main__":
    out = generate_sample_logs()
    print("=" * 60)
    print("  SAMPLE LOG GENERATION COMPLETED (Seed=42)")
    print("=" * 60)
    for k, v in out.items():
        print(f"  [+] {k.upper():<10} -> {v}")
    print("=" * 60)
