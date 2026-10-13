# BCSSL Lab 07: SIEM Log Correlation Engine & Investigation Platform
**7-Stage Enterprise SIEM Architecture & Threat Detection Engineering**  
*Location: `D:\PROJECTS\SIEM-CORRELATION-ENGINE`*

---

## 1. Overview & 7-Stage Architecture

This platform implements an enterprise-grade SIEM (Security Information and Event Management) system following the 7-stage lab architecture:

```
[ Stage 1: Log Sources ]
  • Windows Sysmon / Security (4624, 4625, 4688, 4672, Event ID 1/3/11)
  • Linux auditd (type=SYSCALL, type=USER_CMD, type=PATH) & sshd auth.log
  • Network Firewalls (iptables, UFW, Cisco ASA)
  • Sample Log Generator (sample_log_generator.py - controlled, seeded)
           │
           ▼
[ Stage 2: Collection & Ingestion ]
  • collector.py (Beats/Agent emulator: passive file ingestion)
  • ./incoming directory monitoring & /upload web portal
  • Deterministic SHA-256 _id generation & tolerant line-number skip reporting
           │
           ▼
[ Stage 3: Parsing & Normalization ]
  • Source-specific parsers: parse_windows_sysmon, parse_linux_auditd, parse_network_firewall
  • Canonical Schema: {timestamp, source, event_type, user, source_ip, destination_ip, process_name, severity, host, raw_log}
  • Offline local IP tagging: private/internal vs public/external (zero external network lookups)
           │
           ▼
[ Stage 4: Correlation Engine ]
  • Scenario 1: Brute Force Authentication (T1110 / T1110.001 - 10-min window)
  • Scenario 2: Suspicious Process Execution (T1059.001 / T1059 - post-logon & unusual parent)
  • Scenario 3: Privilege-Related Activity (T1548 / T1078 - Event 4672 & sudo elevation)
  • Scenario 4: Network-Based Suspicious Activity (T1046 - port scan >=5 ports & block bursts)
  • Scenario 5: Additional Security Event (T1003.008 sensitive file access & T1021 lateral movement)
           │
           ▼
[ Stage 5: Storage & Indexing (Elasticsearch 8.13) ]
  • security-events (normalized telemetry with date, keyword, ip mappings)
  • security-alerts (deduplicated scored alerts with MITRE techniques & evidence IDs)
           │
           ▼
[ Stage 6: Visualization & Investigation (Kibana 8.13 Lens) ]
  • SOC Triage Board (Security Overview: alerts over time, top IPs, suspicious execution hosts)
  • Alerts Dashboard (breakdown by rule, severity, and impacted source)
  • Timeline Analysis (events histogram, source distribution)
  • Events Search (Discover search across raw normalized security-events)
           │
           ▼
[ Stage 7: Student Investigation Workspace ]
  • /investigation portal with 5 Scenario Briefs & 8-Step Interactive SOC Playbook
  • Incident Findings Form stored in ./investigations and exportable as Markdown
```

### Operational Security & Integrity Constraints
* **No Host Collection:** Does not collect or scrape any live logs from the host PC (no Sysmon agent, no Windows Event Log reader, no auditd, no Filebeat).
* **Passive Ingestion:** Files are treated strictly as data; contents are never executed or evaluated.
* **Deterministic Deduplication:** Ingestion uses `sha256(source_type + raw_line)` as document `_id` to prevent duplicate events upon re-upload. Alerts use composite hashing for idempotent triage.
* **Strict Localhost Binding:** All services bind strictly to `127.0.0.1`. No external web lookups or third-party GeoIP calls.

---

## 2. Canonical Normalization Schema

All incoming logs are parsed and normalized to this unified schema:

| Canonical Field | Type | Description | Compatibility Alias |
| :--- | :--- | :--- | :--- |
| `timestamp` | `date` | UTC ISO8601 timestamp parsed from log line | - |
| `source` | `keyword` | Primary log source (`Windows`, `Linux`, `Network`) | - |
| `source_type` | `keyword` | Originating parser category (`windows_sysmon`, `linux_auditd`, etc.) | - |
| `event_type` | `keyword` | Normalized activity (`logon_success`, `logon_failure`, `process_create`, `network_connection`, `file_access`, `privilege_escalation`) | - |
| `user` | `keyword` | Target or executing account name | - |
| `source_ip` | `ip` | Originating IP address (valid IPv4/IPv6 or null) | `src_ip` |
| `destination_ip` | `ip` | Destination IP address (valid IPv4/IPv6 or null) | `dest_ip` |
| `destination_port`| `integer` | Destination port number | - |
| `process_name` | `keyword` | Executed executable name (e.g. `cmd.exe`, `powershell.exe`) | - |
| `severity` | `keyword` | Event baseline severity (`low`, `medium`, `high`, `critical`) | - |
| `host` | `keyword` | Hostname / endpoint device identifier | - |
| `raw_log` | `text` | Original raw log string | `raw` |
| `ip_tags` | `keyword` | Offline tags: `["private", "internal"]` vs `["public", "external"]` | - |

---

## 3. Five Correlation Scenarios

All detection rules, thresholds, and sliding windows are externalized in `config.py`:

| # | Detection Scenario | Trigger Conditions | Severity | MITRE Technique |
|---|---|---|---|---|
| **1** | **Brute Force Authentication** | >= 5 failed logons from same IP within 10 minutes (`config.BRUTE_FORCE_WINDOW_MINUTES = 10`) | High | `T1110` (Brute Force) |
| | *Successful Brute Force* | Followed by successful authentication from same IP within window | Critical | `T1110.001` (Password Guessing) |
| **2** | **Suspicious Process Execution** | Post-Logon execution of `powershell.exe`/`cmd.exe` by non-admin within 2m, or shell spawned from unusual parent (`winword.exe`, etc.) | High / Med | `T1059.001` (PowerShell) / `T1059` |
| **3** | **Privilege-Related Activity** | Windows Event 4672 (special privileges assigned), unauthorized `sudo`/`su` elevation, or auditd UID/EUID privilege changes | High | `T1548` (Abuse Elevation Control) / `T1078` |
| **4** | **Network-Based Suspicious Activity** | Single source IP probing >= 5 distinct ports on a destination host within 5 minutes, or bursts of >= 5 blocked connections | High / Med | `T1046` (Network Service Discovery) |
| **5** | **Additional Security Event** | Sensitive system file access (e.g. `/etc/shadow`, `SAM`, `ntds.dit`) or user lateral movement (>= 2 hosts within 10m) | High | `T1003.008` (Credential Dumping) / `T1021` (Remote Services) |


---

## 4. End-to-End Data Flow

```text
[ Raw Telemetry Ingestion ]
    ├── Web Upload (/upload)  ──┐
    └── Watched Folder (./incoming) ──┴──> [ collector.py ]
                                                │
                                                ▼
[ Parsing & Normalization ] <────── [ normalizer.py ]
    ├── Windows Sysmon Parser (JSON/CSV)
    ├── Linux auditd & SSH Parser (SYSCALL / auth.log)
    └── Network Firewall Parser (UFW / Cisco / iptables)
                                                │
                                                ▼ (Deterministic SHA-256 _id)
[ Storage & Indexing ] ────────────> [ storage.py ]
    ├── security-events  (Normalized telemetry with explicit date/ip/kw mappings)
    └── security-alerts  (Scored, deduplicated correlation alerts)
                                                │
                                                ▼
[ Correlation Engine ] <─────────── [ correlate.py ]
    ├── Rule 1: Brute Force (High / Critical)
    ├── Rule 2: Post-Logon Suspicious Process
    ├── Rule 3: Privilege Elevation (4672 / sudo)
    ├── Rule 4: Network Port Scan & Block Bursts
    └── Rule 5: Sensitive Files & Lateral Movement
                                                │
                                                ▼
[ Analyst & Student Investigation ]
    ├── Kibana 8.13 Dashboards (SOC Triage, Alerts Dashboard, Timeline Analysis)
    └── Web Incident Lab (/investigation with 8-Step Interactive Playbook)
```

---

## 5. Indices and Schema Mappings

Both indices use explicit, strictly typed mappings in Elasticsearch 8.13:

### Index: `security-events`
| Field | Type | Description |
|---|---|---|
| `timestamp` | `date` | UTC ISO8601 event occurrence time |
| `source` | `keyword` | High-level log source (`Windows`, `Linux`, `Network`) |
| `event_type` | `keyword` | Canonical event type (`logon_success`, `logon_failure`, `process_create`, etc.) |
| `user` | `keyword` | Authenticated account or process owner |
| `source_ip` | `ip` | Origin IPv4/IPv6 address (sanitized, null if absent) |
| `destination_ip` | `ip` | Target IPv4/IPv6 address (sanitized, null if absent) |
| `destination_port`| `integer` | Target network port (e.g. 22, 80, 443) |
| `process_name` | `keyword` | Executed binary basename (e.g. `powershell.exe`) |
| `severity` | `keyword` | Log severity rating (`low`, `medium`, `high`, `critical`) |
| `host` | `keyword` | Originating endpoint or system hostname |
| `raw_log` | `text` | Unmodified raw log string |
| `ip_tags` | `keyword` | Offline tags (`["private", "internal"]` vs `["public", "external"]`) |

### Index: `security-alerts`
| Field | Type | Description |
|---|---|---|
| `rule_name` | `keyword` | Detection scenario name |
| `severity` | `keyword` | Alert severity (`medium`, `high`, `critical`) |
| `source_ip` | `ip` | Attacker or originating IP |
| `user` | `keyword` | Impacted user account |
| `host` | `keyword` | Impacted endpoint or comma-separated target hosts |
| `evidence` | `keyword` | Array of deterministic `_id` values of triggering events |
| `first_seen` | `date` | Timestamp of first event in correlation window |
| `last_seen` | `date` | Timestamp of triggering event |
| `mitre_technique` | `keyword` | MITRE ATT&CK technique ID (e.g. `T1110`, `T1059.001`) |
| `description` | `text` | Human-readable alert summary |
| `created_at` | `date` | Alert creation timestamp |

---

## 6. Expected Input Formats & Examples

### 1. Windows Sysmon & Security Logs
- **Supported Formats:** JSON lines (`.json`, `.jsonl`) or comma-delimited CSV (`.csv`).
- **Expected Columns / Keys:** `EventID`, `TimeCreated`, `Computer`, `TargetUserName`, `IpAddress`, `NewProcessName`, `ParentProcessName`.
- **Example JSON:**
  ```json
  {"EventID": 4624, "TimeCreated": "2026-10-13T10:15:00Z", "Computer": "WIN-WS04", "TargetUserName": "alice", "IpAddress": "192.168.1.55"}
  {"EventID": 4688, "TimeCreated": "2026-10-13T10:15:45Z", "Computer": "WIN-WS04", "TargetUserName": "alice", "NewProcessName": "powershell.exe"}
  ```
- **Example CSV:**
  ```csv
  EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
  4624,2026-10-13T10:30:00Z,WIN-FINANCE,david,192.168.1.88,
  4688,2026-10-13T10:31:10Z,WIN-FINANCE,david,,powershell.exe
  ```

### 2. Linux auditd & Auth Logs
- **Supported Formats:** Linux syslog text (`.log`, `.txt`).
- **Expected Formats:**
  - `auditd` syscall events: `type=SYSCALL msg=audit(...) ... name="..." exe="..."`
  - `sshd` auth.log events: `Failed password for [user] from [ip] port [port] ssh2` / `Accepted password for [user] from [ip] port [port] ssh2`
- **Example Lines:**
  ```text
  Oct 13 10:10:00 srv01 sshd[201]: Failed password for invalid user admin from 203.0.113.50 port 5001 ssh2
  Oct 13 10:11:20 srv01 sshd[206]: Accepted password for alice from 203.0.113.50 port 5006 ssh2
  type=SYSCALL msg=audit(1697191230.100:10): arch=c000003e syscall=59 success=yes exit=0 auid=1002 uid=1002 exe="/usr/bin/cat" name="/etc/shadow" host=srv-shadow
  ```

### 3. Network Firewall Logs
- **Supported Formats:** UFW kernel logs, Cisco ASA connection messages, standard syslog (`.log`, `.txt`).
- **Expected Fields:** Timestamp, hostname, action (`[UFW BLOCK]`, `[UFW ALLOW]`, `%ASA-...`), `SRC=`, `DST=`, `SPT=`, `DPT=`, `PROTO=`.
- **Example Lines:**
  ```text
  Oct 13 10:10:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.99 DST=10.0.0.10 PROTO=TCP SPT=5510 DPT=22
  Oct 13 10:10:15 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.99 DST=10.0.0.10 PROTO=TCP SPT=5511 DPT=80
  Oct 13 10:10:30 fw01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=192.168.1.50 DST=10.0.0.1 PROTO=TCP SPT=4001 DPT=443
  ```

---

## 7. Setup and Quickstart

### Deployment Note: Portable Windows Stack
Elasticsearch 8.13.0 and Kibana 8.13.0 are installed as standalone portable Windows distributions located in `./stack` (`./stack/elasticsearch-8.13.0` and `./stack/kibana-8.13.0`). Docker Desktop was unavailable on this host PC. A standard `docker-compose.yml` is maintained in the root directory for containerized environments, but local execution uses the native portable stack scripts:

### Step 1: Start Datastore & Dashboards
```powershell
# Start Elasticsearch (127.0.0.1:9200) and Kibana (127.0.0.1:5601)
.\start_stack.ps1

# Start FastAPI Web Application (127.0.0.1:8000)
python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

### Step 2: Import & Verify Kibana Dashboards
```powershell
# Automatically imports Lens dashboards and data views into Kibana
python setup_kibana.py
```
This imports:
* **SOC Triage Board:** `http://127.0.0.1:5601/app/dashboards#/view/soc-triage-board-dashboard`
* **Alerts Dashboard:** `http://127.0.0.1:5601/app/dashboards#/view/alerts-dashboard`
* **Timeline Analysis:** `http://127.0.0.1:5601/app/dashboards#/view/timeline-analysis-dashboard`
* **Discover Events Search:** `http://127.0.0.1:5601/app/discover#/view/events-search`

### Step 3: Run Full Verification Suite
```powershell
# Run unit test suite (35 tests)
pytest tests/

# Run end-to-end integration test (runs on test-* indices; preserves live data)
python test_e2e.py
```

### Step 4: Access Student Investigation Lab
Open browser at `http://127.0.0.1:8000/investigation`:
1. Select an incident scenario brief.
2. Follow the interactive 8-step checklist.
3. Investigate events and alerts in Kibana using direct navigation links.
4. Record findings and export as a Markdown incident report.

---

## 8. Troubleshooting Guide

### 1. `vm.max_map_count` Insufficient (Docker / Linux Environments)
- **Symptom:** Elasticsearch fails to start in Docker with `max virtual memory areas vm.max_map_count [65530] is too low, increase to at least [262144]`.
- **Resolution:**
  - On Linux / WSL2: Run `sudo sysctl -w vm.max_map_count=262144`.
  - Persist permanently in `/etc/sysctl.conf` by adding `vm.max_map_count=262144`.

### 2. Correlation Rules Never Firing Because of Timezone Mismatch
- **Symptom:** Ingested logs contain local time strings (e.g. `Oct 13 10:00:00`) while system clock or queries use a different offset, causing events to fall outside sliding correlation windows.
- **Resolution:** The engine normalizes all parsed log timestamps into strict UTC ISO8601 strings (`parse_timestamp_to_utc_iso`). Correlation windows compare event timestamps relative to each other chronologically, rather than comparing against the host machine's system clock. Ensure log timestamps maintain consistent relative ordering.

### 3. Empty Kibana Panels Due to Default Time Filter
- **Symptom:** Dashboards open in Kibana showing "No results found" across all Lens panels.
- **Resolution:** Kibana defaults new sessions to `Last 15 minutes`. The dashboards exported in `soc_triage_board.ndjson` include `timeRestore: true` set to `now-30d` to `now+1d`. If panels appear blank after uploading historical log files, adjust the Kibana time picker in the top right to cover the date range of the uploaded logs.

---

## 9. File Structure Reference

```
D:\PROJECTS\SIEM-CORRELATION-ENGINE\
├── config.py                 # Central configuration: paths, thresholds, windows, subnets
├── normalizer.py             # Multi-source parsers, schema normalization, offline IP tagging
├── collector.py              # Agent-like file ingestion from /upload and ./incoming
├── correlate.py              # 5-scenario correlation engine with MITRE ATT&CK scoring
├── storage.py                # Elasticsearch client, explicit mappings (date/keyword/ip), mock fallback
├── sample_log_generator.py   # Seeded, reproducible synthetic training dataset generator
├── build_kibana_objects.py   # Generator for pure Lens saved objects (Kibana 8.13)
├── setup_kibana.py           # Automated import & verification script for Kibana objects
├── soc_triage_board.ndjson   # Saved objects package (Dashboards, Lens visuals, Data views)
├── app.py                    # FastAPI web server (port 8000): dashboard, ingestion, investigation lab
├── templates/
│   ├── index.html            # Main dashboard, upload UI, example raw logs, triage summary
│   └── investigation.html    # Student investigation lab, 8-step workflow, findings form
├── incoming/                 # Watched directory for passive log ingestion (ignored by git)
├── sample_logs/              # Output folder for generated synthetic sample logs (ignored by git)
├── investigations/           # Output folder for saved student findings (ignored by git)
├── tests/
│   ├── fixtures/             # Isolated test telemetry fixtures
│   ├── test_normalizer.py    # Unit tests for multi-source parsers and schema
│   ├── test_correlation.py   # Unit tests for all 5 correlation rules and edge cases
│   ├── test_app.py           # API and web route integration tests
│   └── fixtures/             # Seeded fixture log files for test verification
├── test_e2e.py               # E2E integration test runner (runs on test-* indices)
├── start_stack.bat / .ps1    # Portable stack launchers for Elasticsearch and Kibana
├── stop_stack.bat / .ps1     # Process termination scripts for portable stack
├── README.md                 # Project architecture, data flow, formats, quickstart
└── writeup.md                # Comprehensive technical report & operational writeup
```
