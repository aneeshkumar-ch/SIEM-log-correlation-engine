import re
from html.parser import HTMLParser
from starlette.testclient import TestClient
from app import app

client = TestClient(app)

class VisibleTextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.skip_tags = {'script', 'style'}
        self.current_skip = None
        self.in_pre = False
        self.pre_buffer = []
        self.tokens = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in self.skip_tags:
            self.current_skip = tag.lower()
            return
        if tag.lower() == 'pre':
            self.in_pre = True
            self.pre_buffer = []
        attr_dict = dict(attrs)
        if 'placeholder' in attr_dict:
            val = attr_dict['placeholder']
            self.tokens.append(f"[placeholder: {val}]")

    def handle_endtag(self, tag):
        if self.current_skip == tag.lower():
            self.current_skip = None
        if tag.lower() == 'pre':
            self.in_pre = False
            cleaned = re.sub(r'\s+', ' ', ''.join(self.pre_buffer)).strip()
            if cleaned:
                self.tokens.append(cleaned)
            self.pre_buffer = []

    def handle_data(self, data):
        if self.current_skip:
            return
        if self.in_pre:
            self.pre_buffer.append(data)
        else:
            cleaned = re.sub(r'\s+', ' ', data).strip()
            if cleaned:
                self.tokens.append(cleaned)

def extract_visible_tokens(html_content: str):
    extractor = VisibleTextExtractor()
    extractor.feed(html_content)
    return extractor.tokens

EXPECTED_INDEX_TOKENS = ['BCSSL Lab 07 - SIEM Log Correlation Engine', 'SIEM Log Correlation Engine', 'BCSSL Lab 07 • 7-Stage Pipeline • Detection & Investigation', '🔬 Investigation Lab', 'SOC Triage Board ↗', 'Discover Events ↗', 'Ingest Log File', 'Passive Ingestion', 'Log Source Type', 'Windows (Sysmon & Security IDs 4624/4625/4688/4672)', 'Linux (auditd type=SYSCALL & sshd/auth.log)', 'Network Firewall (UFW / iptables / Cisco)', 'Windows Security (Legacy alias)', 'Linux Auth (Legacy alias)', 'Firewall (Legacy alias)', 'Select File (.log, .txt, .json, .jsonl, .csv)', 'Upload & Correlate', 'Pipeline Control', 'Connected (Elasticsearch 8.13)', '0', 'Events Indexed', '0', 'Alerts Raised', 'Run Correlation Rules', 'Generate & Ingest Training Dataset', 'Clear Data (Indices Reset)', 'Example Raw Logs (Expected Formats)', 'Stage 1 Reference', 'Windows (Sysmon / Security JSONL)', '{"EventID": 4624, "TimeCreated": "2026-10-13T10:15:30Z", "Computer": "WIN-SRV01", "TargetUserName": "alice", "IpAddress": "192.168.1.50"} {"EventID": 4688, "TimeCreated": "2026-10-13T10:16:00Z", "Computer": "WIN-SRV01", "TargetUserName": "alice", "NewProcessName": "powershell.exe"}', 'Linux (auditd / auth.log)', 'Oct 13 10:15:30 srv01 sshd[123]: Failed password for invalid user root from 203.0.113.88 port 4210 ssh2 type=SYSCALL msg=audit(1697191230.123:456): arch=c000003e syscall=59 success=yes exit=0 exe="/usr/bin/cat" name="/etc/shadow" host=srv01', 'Network Firewall (UFW / iptables)', 'Oct 13 10:15:30 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.99 DST=10.0.0.10 PROTO=TCP SPT=5510 DPT=22 Oct 13 10:15:45 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=198.51.100.99 DST=10.0.0.10 PROTO=TCP SPT=5511 DPT=80', 'SOC Triage Board — Detection Overview', '3 Correlated Visualizations', '1. Alerts by Severity', '0', 'Critical', '0', 'High', 'Correlated across temporal sliding windows (5 min / 2 min).', '2. Top Attacking Source IPs', 'No active IP anomalies recorded.', '3. Suspicious Execution Hosts', 'No post-logon process executions detected.', 'Security Alerts (`security-alerts`)', '0 Total', 'No alerts detected. Upload sample logs or trigger correlation to evaluate detection rules.']

EXPECTED_INVESTIGATION_TOKENS = ['BCSSL Lab 07 - Student Investigation Workspace', 'Student Investigation Workspace', '← Main Engine', 'SOC Triage Board ↗', 'Discover Events ↗', 'Direct Kibana Navigation:', '📊 SOC Triage Board', '🚨 Alerts Dashboard', '⏱ Timeline Analysis', '🔍 Raw Events Discover', 'Incident Investigation Scenarios', '5 Briefs', '1. Brute Force Authentication', 'Critical / High', 'An external threat actor attempts rapid password guessing against SSH or Windows authentication, followed by potential successful access.', 'T1110', '/', 'T1110.001', 'Threshold: ≥5 failures in 10m', '2. Suspicious Process Execution', 'High', 'A non-admin user logs on and immediately launches an administrative interpreter (PowerShell / cmd.exe) or living-off-the-land utility within 2 minutes.', 'T1059.001', 'Window: 2m Post-Logon', '3. Privilege-Related Activity', 'High', 'Elevation of rights detected: Windows Event 4672 special privileges assigned or unauthorized Linux sudo/su execution by non-admin accounts.', 'T1548', '/', 'T1078', 'Indicators: Event 4672, sudo / su', '4. Network-Based Suspicious Activity', 'High / Med', 'Reconnaissance or probing detected via perimeter firewall: a single source IP probing ≥5 destination ports/hosts or generating high-volume blocked packet bursts.', 'T1046', 'Threshold: ≥5 ports in 5m', '5. Sensitive File Access & Lateral Movement', 'High', 'Credential dumping attempt on Linux system credentials (/etc/shadow) or same user pivoting across multiple endpoints in short succession.', 'T1003.008', '/', 'T1021', 'Targets: /etc/shadow, multi-host logons', '8-Step Investigation Workflow', 'SOC Playbook', 'Step 1', 'Read the scenario brief', 'Review attack vector, expected indicators, and baseline hypothesis.', 'Step 2', 'Search in Kibana', 'Query security-events* in Discover using KQL filters.', 'Step 3', 'Filter relevant events', 'Isolate events by suspicious source IP, impacted host, or specific username.', 'Step 4', 'Analyze timeline', 'Examine event sequence chronologically to track adversary progression.', 'Step 5', 'Identify pattern', 'Pinpoint anomalous frequency, abnormal execution, or privilege shift.', 'Step 6', 'Check correlated alert', 'Correlate with alerts in security-alerts* on the SOC Triage Board.', 'Step 7', 'Document evidence', 'Extract deterministic event IDs and log evidence into the findings record.', 'Step 8', 'Reach a conclusion', 'Classify true/false positive and outline remediation recommendations.', 'Incident Findings Documentation', 'Save & Export', 'Investigation Scenario', 'Scenario 1: Brute Force Authentication', 'Scenario 2: Suspicious Process Execution', 'Scenario 3: Privilege-Related Activity', 'Scenario 4: Network-Based Suspicious Activity', 'Scenario 5: Sensitive File Access & Lateral Movement', 'Investigator / Student', '[placeholder: e.g. SOC Analyst]', 'Incident Verdict', 'True Positive (Incident Confirmed)', 'False Positive (Benign Activity)', 'Inconclusive (Needs Further Telemetry)', 'Impacted Host(s)', '[placeholder: e.g. WIN-SRV01, debian-srv]', 'Attacker / Threat IP(s)', '[placeholder: e.g. 198.51.100.25, 203.0.113.88]', 'MITRE ATT&CK Technique', '[placeholder: e.g. T1110.001 (Password Guessing)]', 'Timeline Analysis & Sequence', '[placeholder: Describe chronological sequence of events (Step 4 & 5)...]', 'Attacker attempted 5 failed logons followed by success.', 'Evidence Event IDs (comma-separated)', '[placeholder: e.g. sha256 IDs from security-events or security-alerts...]', 'ev-001, ev-002', 'Remediation & Mitigation Action', '[placeholder: e.g. Block source IP at perimeter, rotate compromised credentials...]', 'Block IP 198.51.100.25 and reset credentials.', 'Save Findings Locally', 'Export as Markdown ↓']

def test_index_page_visible_text_unaltered():
    resp = client.get("/")
    assert resp.status_code == 200
    tokens = extract_visible_tokens(resp.text)
    assert tokens == EXPECTED_INDEX_TOKENS, f"Visible text in / changed! Diff: expected {len(EXPECTED_INDEX_TOKENS)} tokens, got {len(tokens)}"

def test_investigation_page_visible_text_unaltered():
    resp = client.get("/investigation")
    assert resp.status_code == 200
    tokens = extract_visible_tokens(resp.text)
    assert tokens == EXPECTED_INVESTIGATION_TOKENS, f"Visible text in /investigation changed! Diff: expected {len(EXPECTED_INVESTIGATION_TOKENS)} tokens, got {len(tokens)}"
