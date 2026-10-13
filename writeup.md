# SIEM Log Correlation Engine & Investigation Architecture
**BCSSL Lab 07 | Threat Detection Engineering & Security Operations**  
*Environment: Python 3.10+, Elasticsearch 8.13, Kibana 8.13, FastAPI*

---

## 1. Executive Summary & 7-Stage SIEM Architecture

Modern Security Operations Centers (SOCs) ingest massive volumes of heterogeneous security events from perimeter defenses, identity providers, and endpoints. To achieve actionable detection without overwhelming analysts with alert fatigue, the **SIEM Log Correlation Engine** implements a complete 7-stage pipeline:

```
[ Stage 1: Log Sources ] ──────────> [ Stage 2: Collection & Ingestion ]
  • Windows Sysmon & Security          • collector.py passive file watcher
  • Linux auditd & auth.log            • ./incoming directory monitoring
  • Perimeter Firewalls (UFW/Cisco)    • Web upload with format tolerance
  • sample_log_generator.py (seeded)   • Deterministic SHA-256 _id hashing
                │
                ▼
[ Stage 3: Parsing & Normalization ] ─> [ Stage 4: Correlation Engine ]
  • Source-specific parsers            • Scenario 1: Brute Force (T1110)
  • Canonical Schema (10 fields)       • Scenario 2: Suspicious Exec (T1059)
  • Offline IP subnet tagging          • Scenario 3: Privilege Activity (T1548)
  • UTC ISO8601 normalization          • Scenario 4: Network Probing (T1046)
                                       • Scenario 5: File/Lateral (T1003/T1021)
                │
                ▼
[ Stage 5: Storage & Indexing ] ──────> [ Stage 6: Visualization (Kibana) ]
  • security-events (telemetry)        • SOC Triage Board (Overview)
  • security-alerts (deduplicated)     • Alerts Dashboard (Rules/Severity)
  • Explicit mappings (date, kw, ip)   • Timeline Analysis & Discover Search
                │
                ▼
[ Stage 7: Student Investigation Workspace ]
  • /investigation portal with 5 Scenario Briefs
  • 8-Step Interactive SOC Playbook Workflow
  • Incident Findings Documentation & Markdown Export
```

### Core Integrity & Safety Principles
1. **Zero Host Log Collection:** No agents or telemetry hooks run on the host computer. Real Windows Event Logs, Sysmon drivers, and host auditd daemons are untouched.
2. **Passive Ingestion:** Files uploaded via web UI or placed in `./incoming` are treated strictly as passive structured text. Contents are never executed, evaluated, or compiled.
3. **Idempotent Storage:** Each normalized event receives an immutable `_id` computed via `sha256(source_type + raw_log)`. Re-ingesting identical files guarantees zero duplicate events.
4. **Localhost & Offline Security:** Services strictly bind to `127.0.0.1`. IP tagging uses internal CIDR lookups (RFC 1918) with zero external network or GeoIP requests.

---

## 2. Canonical Normalization Schema

Disparate log formats are unified into a canonical 10-field data model:

$$\{ \text{timestamp (UTC)}, \text{source}, \text{event\_type}, \text{user}, \text{source\_ip}, \text{destination\_ip}, \text{process\_name}, \text{severity}, \text{host}, \text{raw\_log} \}$$

### Field Definitions & Types:
* `timestamp` (`date`): Extracted directly from the log record (never system clock) and converted into ISO8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`).
* `source` (`keyword`): Categorical source identifier (`Windows`, `Linux`, `Network`).
* `event_type` (`keyword`): Normalized event category (`logon_success`, `logon_failure`, `process_create`, `network_connection`, `file_access`, `privilege_escalation`).
* `user` (`keyword`): Authenticating or executing account name.
* `source_ip` (`ip`): Originating IPv4/IPv6 address. Sanitized to `None` if absent or invalid to ensure Elasticsearch type safety.
* `destination_ip` (`ip`): Target network endpoint address.
* `process_name` (`keyword`): Executed binary basename (e.g. `cmd.exe`, `powershell.exe`).
* `severity` (`keyword`): Event-level risk rating (`low`, `medium`, `high`, `critical`).
* `host` (`keyword`): Impacted machine or device hostname.
* `raw_log` (`text`): Original unprocessed record preserved for forensic validation.
* `ip_tags` (`keyword`): Offline metadata tags: `["private", "internal"]` vs `["public", "external"]`.

---

## 3. Five Correlation Rule Scenarios

The correlation engine executes sliding-window evaluations across chronologically sorted events:

### Scenario 1: Brute Force Authentication (MITRE ATT&CK: T1110 / T1110.001)
* **High Severity (Brute Force Suspected):** Evaluates `logon_failure` events grouped by `source_ip`. When $\ge 5$ failures occur within a sliding 10-minute window ($600\text{s}$) without subsequent success, a High alert is raised.
* **Critical Severity (Successful Brute Force):** When $\ge 5$ failures within the 10-minute window are followed by a `logon_success` event from the same source IP/user, the alert escalates to Critical, capturing active credential compromise.

### Scenario 2: Suspicious Process Execution (MITRE ATT&CK: T1059.001 / T1059)
* **Pattern 2A (Post-Logon Execution):** A `logon_success` by a non-administrative user on an endpoint followed within 2 minutes ($120\text{s}$) by a `process_create` running command-line shells (`powershell.exe`, `cmd.exe`, `pwsh.exe`).
* **Pattern 2B (Unusual Process Execution):** Standalone execution of Living-off-the-Land reconnaissance/tampering utilities (`certutil.exe`, `vssadmin.exe`, `whoami.exe`, `bitsadmin.exe`) by non-admin users, or shells spawned from unexpected parent processes (`winword.exe`, `excel.exe`, `w3wp.exe`).

### Scenario 3: Privilege-Related Activity (MITRE ATT&CK: T1548 / T1078)
* **Logic:** Detects elevation of rights:
  - Windows Security Event 4672 (`SpecialPrivilegesAssigned` e.g., `SeDebugPrivilege`).
  - Linux `sudo` or `su` commands executed by non-administrative users.
  - Linux `auditd` `type=USER_CMD` or syscall elevation where `uid != euid` and `euid == 0`.
* **Severity:** High.

### Scenario 4: Network-Based Suspicious Activity (MITRE ATT&CK: T1046)
* **Pattern 4A (Port Scanning):** A single external `source_ip` hitting $\ge 5$ distinct destination ports or destination hosts within a 5-minute sliding window ($300\text{s}$). Severity: High.
* **Pattern 4B (Blocked Traffic Burst):** A single source IP generating $\ge 5$ blocked packet events within 5 minutes. Severity: Medium.

### Scenario 5: Additional Security Event (MITRE ATT&CK: T1003.008 / T1021)
* **Pattern 5A (Sensitive File Access):** Auditd or Sysmon events accessing sensitive credential storage (e.g. `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `SAM`, `ntds.dit`). Severity: High.
* **Pattern 5B (Suspected Lateral Movement):** The same non-admin user logging on to $\ge 2$ distinct internal hosts within a 10-minute sliding window ($600\text{s}$). Severity: High.

---

## 4. False-Positive Tuning & Operational Safeguards

1. **Sliding Window Calibration:**
   A threshold of 5 failures within 10 minutes distinguishes human mistyping (typically 1–3 attempts) from automated brute-force tools (Hydra, Medusa, spraying scripts).
2. **Administrator Allowlisting:**
   System administrators legitimately run PowerShell and batch files for routine maintenance. The `ADMIN_ACCOUNTS` filter (`Administrator`, `root`, `SYSTEM`, etc.) ensures that benign admin tasks do not trigger False Positives, focusing alerts on non-admin Living-off-the-Land abuse.
3. **Anti-Flooding Alert Deduplication:**
   Alerts use deterministic hashing on composite tuples:
   $$\text{alert\_id} = \text{sha256}(\text{rule\_name} + \text{source\_ip} + \text{host} + \text{first\_seen} + \text{last\_seen})$$
   Repeated correlation executions upsert on `_id`, updating evidence IDs without spamming redundant alert rows.

---

## 5. 8-Step Student Investigation Workflow

The web portal at `/investigation` provides an interactive 8-step playbook for incident response:

| Step | Action | Description |
|---|---|---|
| **Step 1** | Read Scenario Brief | Review attack scenario brief, target systems, and expected threat tactics. |
| **Step 2** | Search in Kibana | Query the `security-events*` Discover search using KQL filters. |
| **Step 3** | Filter Relevant Events | Narrow search by suspicious IP, target hostname, or anomalous username. |
| **Step 4** | Analyze Timeline | Examine the chronological sequence of events on the Timeline Analysis dashboard. |
| **Step 5** | Identify Pattern | Spot the specific anomaly: failure bursts, privilege shift, or unauthorized binary execution. |
| **Step 6** | Check Correlated Alert | Review the corresponding alert raised in `security-alerts*` on the SOC Triage Board. |
| **Step 7** | Document Evidence | Extract deterministic event IDs and log indicators into the investigation form. |
| **Step 8** | Reach Conclusion | Classify as True Positive or False Positive, document remediation, and export Markdown report. |

---

## 6. Verification & Test Evidence

### Test Suite Execution (`pytest tests/`)
* **Total Tests:** 27 passed (100% success rate)
* **Coverage:**
  - Multi-source parsers: `windows_sysmon`, `linux_auditd`, `network_firewall`, CSV/JSONL tolerance.
  - 5 Correlation scenarios: brute force, post-logon shell, privilege elevation, port scanning, sensitive file access, lateral movement.
  - Idempotent deduplication and false-positive suppression on benign activity.
  - Web UI routes: upload, correlation, clear, `/investigation`, `/investigation/save`, `/investigation/export`, and dataset generation.

### Live Datastore Verification (`test_e2e.py`)
Tested directly against portable **Elasticsearch 8.13.0** (`127.0.0.1:9200`) and **Kibana 8.13.0** (`127.0.0.1:5601`):
* **Events Indexed:** 49 events successfully parsed and stored in `security-events`.
* **Alerts Generated:** 13 scored alerts stored in `security-alerts` covering all 5 scenarios.
* **Deduplication:** Re-ingesting telemetry resulted in 0 duplicate events and 0 duplicate alerts.
* **Kibana Objects:** All 12 saved objects verified with HTTP 200 via Kibana Saved Objects API, using pure Lens visualizations with default time range covering the telemetry.
