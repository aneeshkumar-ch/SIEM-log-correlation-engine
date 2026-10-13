# SIEM Log Correlation Engine — Executive Summary

## 1. Architecture and Data Pipeline
The SIEM Log Correlation Engine ingests heterogeneous security telemetry across Windows Sysmon, Linux auditd, and network firewalls through a passive collection layer without host agent execution. Ingested records are parsed, normalized into a canonical 10-field schema, and tagged with offline internal network subnets. Telemetry and scored security alerts are indexed into Elasticsearch and visualized across three custom Kibana Lens dashboards. Analysts conduct incident triage through an 8-step investigation playbook that records findings and exports markdown reports. Because Docker was unavailable in the local environment, Elasticsearch 8.13.0 and Kibana 8.13.0 ran directly on localhost using portable Windows builds configured with single-node discovery and internal HTTP transports.

## 2. Detection Rules and Correlation Logic

### Rule 1: Brute Force Authentication (MITRE T1110 / T1110.001)
- Correlation Logic & Threshold: Evaluates failed logons grouped by source IP; alerts at High severity when >= 5 failures occur within 10 minutes, and escalates to Critical if followed by a successful logon from the same IP. (Note: The sliding window is 10 minutes, changed from the lab brief's initial 5 minutes to accommodate realistic slow brute-force and credential stuffing campaigns, configurable via BRUTE_FORCE_WINDOW_MINUTES in config.py).
- False-Positive Tuning: Enforcing a 5-attempt threshold prevents alerts from routine user typographical errors, while known vulnerability scanners and bastion jump hosts can be exempted via allowlists.

### Rule 2: Suspicious Process Execution (MITRE T1059.001 / T1059)
- Correlation Logic & Threshold: Flags command shells (powershell.exe, cmd.exe) executed by non-administrative users within 2 minutes of logon, or standalone executions of high-risk reconnaissance and tampering utilities (certutil, vssadmin, whoami).
- False-Positive Tuning: Administrative service accounts and root tasks are exempted via an administrator filter, and standard shells launched outside the post-logon window without suspicious parent processes are suppressed.

### Rule 3: Privilege-Related Activity (MITRE T1548 / T1078)
- Correlation Logic & Threshold: Detects elevation of rights, including Windows Event 4672 (special privileges assigned), unauthorized Linux sudo/su elevation to root, or auditd EUID privilege shifts.
- False-Positive Tuning: Core system services and approved administrative accounts that legitimately receive special privileges during routine startup and maintenance are filtered out.

### Rule 4: Network-Based Suspicious Activity (MITRE T1046)
- Correlation Logic & Threshold: Detects a single source IP probing >= 5 distinct destination ports on a single destination host within 5 minutes (High severity), or generating >= 5 blocked connections within 5 minutes (Medium severity).
- False-Positive Tuning: Destination ports are tracked per destination host rather than globally, ensuring client browsers opening parallel HTTPS connections across multiple sites never trigger false port-scan alerts; blocked traffic evaluation strictly isolates Network sources to avoid miscounting non-network medium events.

### Rule 5: Additional Security Events — Sensitive Files & Lateral Movement (MITRE T1003.008 / T1021)
- Correlation Logic & Threshold: Detects access to credential databases (/etc/shadow, SAM, ntds.dit) or a non-admin user logging on to >= 2 distinct hosts within 10 minutes.
- False-Positive Tuning: Standard system utilities continuously read /etc/passwd to resolve account identifiers, so /etc/passwd was explicitly excluded from alerting to eliminate severe alert fatigue. For lateral movement, requiring >= 2 distinct hosts prevents false alerts from reconnects to the same machine, and impacted hosts are stored as multi-value keyword lists for per-host SOC visibility.
