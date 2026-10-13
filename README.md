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
| **1** | **Brute Force Authentication** | $\ge 5$ failed logons from same IP within 10 minutes | High | `T1110` (Brute Force) |
| | *Successful Brute Force* | Followed by successful authentication within window | Critical | `T1110.001` (Password Guessing) |
| **2** | **Suspicious Process Execution** | Post-Logon execution of `powershell.exe`/`cmd.exe` by non-admin within 2m, or shell spawned from unusual parent (`winword.exe`, etc.) | High / Med | `T1059.001` (PowerShell) / `T1059` |
| **3** | **Privilege-Related Activity** | Windows Event 4672 (special privileges assigned), unauthorized `sudo`/`su` elevation, or auditd UID/EUID privilege changes | High | `T1548` (Abuse Elevation Control) / `T1078` |
| **4** | **Network-Based Suspicious Activity** | Single source IP probing $\ge 5$ destination ports/hosts within 5 minutes, or bursts of $\ge 5$ blocked connections | High / Med | `T1046` (Network Service Discovery) |
| **5** | **Additional Security Event** | Sensitive system file access (e.g. `/etc/shadow`, `SAM`) or user lateral movement ($\ge 2$ hosts within 10m) | High | `T1003.008` (Credential Dumping) / `T1021` (Remote Services) |

---

## 4. Setup and Quickstart

### Prerequisites
* Windows PC with Python 3.10+
* Portable Elasticsearch 8.13.0 and Kibana 8.13.0 in `./stack` (or Docker Desktop)

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
# Run unit test suite (27 tests)
pytest tests/

# Run end-to-end integration test against live Elasticsearch 8.13
python test_e2e.py
```

### Step 4: Access Student Investigation Lab
Open browser at `http://127.0.0.1:8000/investigation`:
1. Select an incident scenario brief.
2. Follow the interactive 8-step checklist.
3. Investigate events and alerts in Kibana using direct navigation links.
4. Record findings and export as a Markdown incident report.

---

## 5. File Structure Reference

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
│   └── test_app.py           # API and web route integration tests
└── test_e2e.py               # Live end-to-end verification against real Elasticsearch
```
