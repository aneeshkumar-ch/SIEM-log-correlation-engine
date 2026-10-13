# SIEM Log Correlation Engine — Architecture & Tuning Write-Up
**BCSSL Lab 07 | Security Operations & Threat Detection Engineering**  
*Author: Security Engineering Team | Environment: Python 3.10+, Elasticsearch 8.13, Kibana 8.13*

---

## 1. Executive Summary & Engine Architecture

Modern enterprise environments generate millions of heterogeneous log entries daily across endpoints, network firewalls, and authentication servers. Without centralized normalization and correlation, security analysts face severe alert fatigue and fragmented context. 

The **SIEM Log Correlation Engine** implements a complete detection pipeline:
1. **Ingestion & Normalization:** Ingests disparate authentication logs (Linux `/var/log/auth.log`, Windows Security Event IDs 4624/4625/4688) and perimeter firewall logs, mapping them into a canonical Elastic Common Schema (ECS)-inspired data model:
   $$\{ \text{timestamp (UTC)}, \text{host}, \text{source\_type}, \text{event\_type}, \text{user}, \text{src\_ip}, \text{process\_name}, \text{raw} \}$$
2. **Deterministic Deduplication:** Generates document IDs using SHA-256 hashes of the raw record and source type (`sha256(source_type + raw)`). This guarantees idempotent ingestion, ensuring that re-ingesting duplicate log archives does not distort metric counts or trigger redundant alerts.
3. **Multi-Source Temporal Correlation:** Evaluates chronological event streams within sliding time windows to detect complex adversary attack paths spanning authentication anomalies and post-compromise execution.
4. **Scored Alert Dispatch:** Dispatches structured alerts into the dedicated `security-alerts` index, tagging MITRE ATT&CK techniques, forensic evidence IDs, and severity ratings for triage on the Kibana **SOC Triage Board**.

```
[ Raw Logs ] ──> [ Normalizer ] ──> [ normalized-events ] ──> [ Correlation Engine ] ──> [ security-alerts ] ──> [ Kibana Board ]
  • Linux SSH      • Common Schema    • Elasticsearch 8.13       • Rule 1: Brute Force     • High/Critical         • Triage Panels
  • Win Security   • UTC ISO8601      • Deterministic _id        • Rule 2: Successful BF   • Deduplicated          • Top IPs Table
  • Firewalls      • Type Tolerant                               • Rule 3: Suspicious Exec • MITRE Tagged          • Host Impact
```

---

## 2. Correlation Rule Logic & Detection Scenarios

### Rule 1: "Brute Force Suspected" (Severity: High | MITRE ATT&CK: T1110)
* **Objective:** Detect automated credential guessing or dictionary attacks targeting authentication interfaces before access is gained.
* **Logic:** Evaluates `logon_failure` events grouped by `src_ip`. If $\ge 5$ logon failures occur within a sliding 5-minute window ($300\text{s}$) with **no** subsequent `logon_success` from that IP within the window, a High severity alert is generated.
* **Evidence Collected:** The complete array of failed event document IDs and target usernames.

### Rule 2: "Successful Brute Force" (Severity: Critical | MITRE ATT&CK: T1110.001 / T1078)
* **Objective:** Detect an attacker who successfully compromised valid credentials following an active brute-force or password spraying burst.
* **Logic:** Extends Rule 1: when $\ge 5$ logon failures occur within 5 minutes and are followed by a `logon_success` event from the same source IP/user within the evaluation window, the incident is escalated to **Critical** severity.
* **Suppression of Redundant Alert:** When Rule 2 triggers, it absorbs the burst so that the analyst receives a single actionable Critical escalation rather than a redundant High alert.

### Rule 3: "Post-Logon Suspicious Execution" (Severity: High | MITRE ATT&CK: T1059.001 / T1059.003)
* **Objective:** Detect privilege escalation, discovery, or initial command execution following user authentication.
* **Logic:** Correlates across heterogeneous sources: identifies a `logon_success` by a non-administrative user, followed within 2 minutes ($120\text{s}$) on the **same host** by a `process_create` event executing command-line interpreters (`powershell.exe`, `cmd.exe`, `pwsh.exe`).
* **Evidence Collected:** The logon event ID paired with the child process creation event ID.

---

## 3. False-Positive Tuning Decisions & Operational Safeguards

In high-throughput SOC operations, overly sensitive rules blind analysts with false positives. The following tuning decisions were implemented:

### A. Threshold Selection (5 Failures in 5 Minutes)
* **Rationale:** Legitimate human users frequently mistype passwords 1 to 3 times due to keyboard layout issues or expired password sync delays. A threshold of 5 attempts within a strict 300-second window effectively separates human error from automated scripts (e.g., Hydra, Medusa, or automated spraying bots) while catching slow-and-low bursts without creating noise.
* **Configurability:** Thresholds (`BRUTE_FORCE_FAIL_THRESHOLD`, `BRUTE_FORCE_WINDOW_MINUTES`) are externalized in `config.py` for site-specific tuning.

### B. Timezone Synchronization & UTC Standard
* **Pitfall:** A frequent vulnerability in SIEM correlation occurs when log sources emit unstandardized timestamps (local time, EDT, UTC, or syslog without year), causing time comparisons to fail or window calculations to skew by hours.
* **Engine Solution:** The normalizer extracts the exact timestamp from the log line, infers leap-safe calendar years for standard syslog lines, converts all values to timezone-aware UTC ISO8601 objects (`datetime.fromisoformat`), and evaluates offsets in exact seconds ($\Delta t \le \text{window}\times 60$).

### C. Admin & Service Account Allowlisting (Rule 3 Tuning)
* **Rationale:** System administrators routinely log in and run administrative PowerShell scripts or batch maintenance tasks. Flagging every administrator running `cmd.exe` produces crippling false positive rates.
* **Tuning:** Rule 3 enforces an `ADMIN_ACCOUNTS` filter (`Administrator`, `admin`, `root`, `SYSTEM`, `NT AUTHORITY\SYSTEM`). Only logins by non-privileged accounts (e.g., standard employees, finance workers, developers) that subsequently spawn shells trigger the alert, capturing Living-off-the-Land (LotL) abuse.

### D. Network Scanners & Allowlisted IPs
* **Rationale:** Vulnerability management scanners (e.g., Tenable Nessus, Qualys, OpenVAS) routinely test credentials and generate hundreds of failed authentications as part of scheduled audits.
* **Tuning:** An `ALLOWLIST_IPS` configuration parameter suppresses brute-force alerts from authorized scanning ranges while retaining the raw logs in `normalized-events` for audit compliance.

### E. Alert Deduplication & Anti-Flooding
* **Rationale:** If an ongoing brute-force attack generates 100 failed attempts over 10 minutes, generating an alert for every single overlapping sliding sub-window floods the incident queue.
* **Tuning:** Alerts generate a deterministic composite hash:
  $$\text{alert\_id} = \text{sha256}(\text{rule\_name} + \text{src\_ip} + \text{host} + \text{first\_seen} + \text{last\_seen})$$
  Subsequent correlation runs perform upserts on `_id`, updating existing records without generating duplicate notifications.

---

## 4. Assessment & Extension Roadmap

| Component | Status | Verification |
| :--- | :--- | :--- |
| **Log Normalization** | Complete (3 Sources) | Tested with SSH, Sudo, Win Event IDs 4624/4625/4688, and Firewalls |
| **Rule 1: Brute Force Suspected** | Verified (High) | True positive verified; sub-threshold ($<5$) confirmed suppressed |
| **Rule 2: Successful Brute Force** | Verified (Critical) | Escalation verified with success follow-through |
| **Rule 3: Post-Logon Execution** | Verified (High) | Admin allowlisting verified; 2-min window enforced |
| **Deduplication & Storage** | Verified (Idempotent) | Re-upload tests confirm 0 duplicate events / 0 duplicate alerts |
| **Analyst Visualization** | Complete | Kibana **SOC Triage Board** NDJSON package exported |

**Future Enhancements:** Integration of Isolation Forest machine learning models to detect off-hours login anomalies, and automated webhook dispatch to incident management platforms (Jira / TheHive).
