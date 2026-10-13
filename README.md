# BCSSL Lab 07: SIEM Log Correlation Engine
**Localhost Log Ingestion, Normalization, Correlation & Triage Platform**  
*Location: `D:\PROJECTS\SIEM-CORRELATION-ENGINE`*

---

## 1. Overview

This project implements a mini SIEM (Security Information and Event Management) platform designed for **BCSSL Lab 07**. It ingests uploaded authentication and security logs from multiple heterogeneous sources, normalizes them into a unified schema, indexes them into Elasticsearch, executes correlation detection rules across temporal windows, and visualizes prioritized alerts on a Kibana dashboard.

### Core Security & OpSec Rules
* **No Host Collection:** Does not collect or scrape any logs from the host PC (no Sysmon agent, no Windows Event Log collector, no auditd, no Filebeat).
* **Passive Ingestion:** Uploaded files are strictly treated as data; contents are never executed or evaluated.
* **Idempotent Ingestion:** Deterministic SHA-256 document hashing (`_id`) prevents duplicate events and duplicate alerts upon re-uploading files.
* **Strict Localhost Binding:** All services bind strictly to `127.0.0.1`.

---

## 2. Deliverables Checklist

| # | Deliverable | Location | Status |
|---|---|---|---|
| 1 | `docker-compose.yml` | [`docker-compose.yml`](file:///D:/PROJECTS/SIEM-CORRELATION-ENGINE/docker-compose.yml) | Ready (ES 8.13.0 + Kibana 8.13.0, localhost bound) |
| 2 | Normalizer Source | [`normalizer.py`](file:///D:/PROJECTS/SIEM-CORRELATION-ENGINE/normalizer.py) | Ready (`linux_auth`, `windows_security`, `firewall`) |
| 3 | 3 Correlation Rules | [`correlate.py`](file:///D:/PROJECTS/SIEM-CORRELATION-ENGINE/correlate.py) & [`tests/test_correlation.py`](file:///D:/PROJECTS/SIEM-CORRELATION-ENGINE/tests/test_correlation.py) | Ready (Rules 1, 2, 3 + benign tests) |
| 4 | Alerts Index (`security-alerts`) | [`correlate.py`](file:///D:/PROJECTS/SIEM-CORRELATION-ENGINE/correlate.py) & [`app.py`](file:///D:/PROJECTS/SIEM-CORRELATION-ENGINE/app.py) | Ready (Scored alerts with MITRE techniques & severities) |
| 5 | SOC Triage Board Dashboard | [`soc_triage_board.ndjson`](file:///D:/PROJECTS/SIEM-CORRELATION-ENGINE/soc_triage_board.ndjson) | Ready (Kibana 8.13 saved objects export) |
| 6 | Technical Write-Up | [`writeup.md`](file:///D:/PROJECTS/SIEM-CORRELATION-ENGINE/writeup.md) | Ready (One-page logic & tuning decisions) |

---

## 3. Expected Input Formats and Column Names

The normalizer accepts `.log`, `.txt`, `.json`, `.jsonl`, and `.csv` files up to 20 MB. It parses timestamps **from the log records** (never `datetime.now()`) and standardizes them into UTC ISO8601.

### A. Linux Authentication (`linux_auth`)
Supports standard Linux `/var/log/auth.log` and syslog text formats:
* **SSH Successful Login:**
  ```text
  Oct 13 10:15:30 debian sshd[12345]: Accepted password for alice from 192.168.1.105 port 45212 ssh2
  ```
* **SSH Failed Login:**
  ```text
  Oct 13 10:15:32 debian sshd[12346]: Failed password for invalid user admin from 10.0.0.99 port 51234 ssh2
  ```
* **Sudo Execution (Process Creation):**
  ```text
  Oct 13 10:16:00 debian sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash
  ```

### B. Windows Security (`windows_security`)
Supports JSON, JSONL, and CSV exports of Windows Security Event Logs.

#### Monitored Event IDs:
* **Event ID 4624:** Logon Success (`logon_success`)
* **Event ID 4625:** Logon Failure (`logon_failure`)
* **Event ID 4688:** Process Creation (`process_create`)

#### Tolerant Column / Key Mappings:
The parser recognizes common enterprise column variations case-insensitively:

| Target Field | Expected Column Names / JSON Keys |
| :--- | :--- |
| **Event ID** | `EventID`, `EventId`, `event_id`, `Id`, `EventCode`, `winlog.event_id` |
| **Timestamp** | `TimeCreated`, `timestamp`, `@timestamp`, `Time`, `Date`, `UtcTime`, `DateTime`, `SystemTime` |
| **Host** | `Computer`, `host`, `hostname`, `ComputerName`, `host.name` |
| **User** | `TargetUserName`, `user`, `username`, `AccountName`, `TargetUser`, `SubjectUserName` |
| **Source IP** | `IpAddress`, `src_ip`, `Ip`, `ClientAddress`, `SourceNetworkAddress`, `SourceIP` |
| **Process Name** | `NewProcessName`, `process_name`, `ProcessName`, `Image`, `process`, `CommandLine` |

**Example CSV Format (`windows_security`):**
```csv
EventID,TimeCreated,Computer,TargetUserName,IpAddress,NewProcessName
4625,2026-10-13T10:00:00Z,WIN-SRV01,admin,198.51.100.10,
4625,2026-10-13T10:00:30Z,WIN-SRV01,admin,198.51.100.10,
4624,2026-10-13T10:05:00Z,WIN-SRV01,david,198.51.100.50,
4688,2026-10-13T10:05:45Z,WIN-SRV01,david,,powershell.exe
```

### C. Firewall Logs (`firewall`)
Supports UFW / iptables syslog, Cisco ASA, pfSense, and generic key-value or JSON formats:
```text
Oct 13 10:15:30 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=198.51.100.22 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=22
```

---

## 4. Setup and Execution Steps

### Step 1: Start Elasticsearch & Kibana

#### Option A: Portable Standalone Stack (No Docker / WSL Required)
Run the automated startup script:
```powershell
cd D:\PROJECTS\SIEM-CORRELATION-ENGINE
.\start_stack.ps1
# Or: .\start_stack.bat
```
This launches portable Elasticsearch 8.13.0 (with 1 GB heap) on `http://127.0.0.1:9200` and Kibana 8.13.0 on `http://127.0.0.1:5601`.
To stop the stack:
```powershell
.\stop_stack.ps1
# Or: .\stop_stack.bat
```

#### Option B: Docker Desktop (WSL2)
If Docker Desktop is available:
```powershell
cd D:\PROJECTS\SIEM-CORRELATION-ENGINE
docker compose up -d
```
Verify services respond:
* Elasticsearch: `http://127.0.0.1:9200`
* Kibana: `http://127.0.0.1:5601`

*(Note: In offline or test mode where neither is active, all features and unit tests run with the built-in mock ES client by setting `USE_MOCK_ES=1`.)*

### Step 2: Start the SIEM FastAPI Web App
Launch the ingestion web interface on localhost:
```powershell
cd D:\PROJECTS\SIEM-CORRELATION-ENGINE
python app.py
```
Open your browser to:
**`http://127.0.0.1:8000`**

### Step 3: Ingest Logs & Run Correlation
1. Navigate to `http://127.0.0.1:8000`.
2. Select your log file type from the dropdown (`linux_auth`, `windows_security`, or `firewall`).
3. Pick your log file and click **"Upload & Correlate"**.
4. The web interface will display:
   * Total events parsed into `normalized-events`.
   * Skipped/unrecognized lines with exact line numbers and reasons (without failing the upload).
   * Prioritized alerts generated in `security-alerts`.
   * A direct link to Kibana.
5. Click **"Run Correlation Rules"** to re-evaluate detection rules on demand, or **"Clear Data"** to reset the indices.

### Step 4: Import Kibana Dashboard ("SOC Triage Board")
Once Kibana is running at `http://127.0.0.1:5601`, run the automated import script:
```powershell
python setup_kibana.py
```
Or import manually in Kibana:
1. Open **Kibana** (`http://127.0.0.1:5601`).
2. Go to **Management** &rarr; **Stack Management** &rarr; **Saved Objects**.
3. Click **Import** (top right) and select `D:\PROJECTS\SIEM-CORRELATION-ENGINE\soc_triage_board.ndjson`.
4. Open **Dashboard** &rarr; **SOC Triage Board**.

---

## 5. Automated Verification Tests

The test suite in [`tests/`](file:///D:/PROJECTS/SIEM-CORRELATION-ENGINE/tests/) contains fixtures verifying each rule fires on its attack scenario, does NOT fire on benign activity, handles skipped lines gracefully, and ensures re-uploading produces no duplicates:

```powershell
cd D:\PROJECTS\SIEM-CORRELATION-ENGINE
pytest tests -v
```

**Test Coverage Summary (18 Automated Tests):**
* `test_normalizer.py`: Tests SSH accepted/failed, sudo process creation, Windows JSON/CSV Event IDs 4624/4625/4688, firewall parsing, bad line isolation, deterministic IDs.
* `test_correlation.py`:
  * Rule 1 (Brute Force Suspected): $\ge 5$ failures within 5 mins &rarr; High alert.
  * Rule 2 (Successful Brute Force): $\ge 5$ failures followed by logon success &rarr; Critical alert.
  * Rule 3 (Post-Logon Suspicious Execution): Non-admin logon followed by `powershell.exe` within 2 mins &rarr; High alert.
  * Benign Scenarios: Below threshold ($<5$), spaced attempts ($>5$ mins), admin execution, benign executables (`notepad.exe`), delayed execution ($>2$ mins) &rarr; 0 alerts.
  * Deduplication: Identical re-upload causes 0 duplicate events and 0 duplicate alerts.
* `test_app.py`: Tests `GET /`, `POST /upload` (with generated UUID filename), file extension restrictions, and `POST /clear`.

---

## 6. Troubleshooting

* **Elasticsearch fails to start (`vm.max_map_count too low`):**
  If Docker reports that virtual memory mapping is insufficient, increase `vm.max_map_count` inside WSL:
  ```powershell
  wsl -d docker-desktop sysctl -w vm.max_map_count=262144
  ```
  *(To persist across reboots, add `vm.max_map_count = 262144` to `C:\Users\<user>\.wslconfig` or `/etc/sysctl.conf` inside WSL).*
* **Elasticsearch Connection Refused (`127.0.0.1:9200`):**
  Check that the container is running:
  ```powershell
  docker ps
  ```
  Check Elasticsearch container logs:
  ```powershell
  docker logs es
  ```
* **Kibana Shows "No data found":**
  Ensure you have uploaded at least one log file so that documents exist in `security-alerts` before querying the dashboard.
* **Testing without Docker:**
  Set `$env:USE_MOCK_ES="1"` in PowerShell to run the application in mock storage mode while preparing your environment.
