import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
UPLOADS_DIR = Path(os.getenv("UPLOADS_DIR", str(BASE_DIR / "uploads")))
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

INCOMING_DIR = Path(os.getenv("INCOMING_DIR", str(BASE_DIR / "incoming")))
INCOMING_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_LOGS_DIR = BASE_DIR / "sample_logs"
SAMPLE_LOGS_DIR.mkdir(exist_ok=True)

INVESTIGATIONS_DIR = BASE_DIR / "investigations"
INVESTIGATIONS_DIR.mkdir(exist_ok=True)

# Service URLs (Bind localhost only)
ES_HOST = os.getenv("ES_HOST", "http://127.0.0.1:9200")
KIBANA_HOST = os.getenv("KIBANA_HOST", "http://127.0.0.1:5601")

# Elasticsearch Indices (Migrated to security-events)
INDEX_EVENTS = os.getenv("INDEX_EVENTS", "security-events")
INDEX_ALERTS = os.getenv("INDEX_ALERTS", "security-alerts")
LEGACY_INDEX_EVENTS = "normalized-events"

# Background Pipeline Configuration
COLLECTOR_POLL_SECONDS = int(os.getenv("COLLECTOR_POLL_SECONDS", "2"))
CORRELATION_INTERVAL_SECONDS = int(os.getenv("CORRELATION_INTERVAL_SECONDS", "10"))
ENABLE_COLLECTOR = os.getenv("ENABLE_COLLECTOR", "true").lower() in ("true", "1", "yes")
ENABLE_SCHEDULER = os.getenv("ENABLE_SCHEDULER", "true").lower() in ("true", "1", "yes")
WEBHOOK_URL = os.getenv("WEBHOOK_URL", "")

# Switchable Mock ES flag (default is False: real Elasticsearch client)
USE_MOCK_ES = os.getenv("USE_MOCK_ES", "false").lower() in ("true", "1", "yes")

# Upload Configuration
MAX_UPLOAD_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB limit
ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".jsonl", ".csv"}

# ---------------------------------------------------------------------------
# Correlation Rule Thresholds & Windows (All configurable)
# ---------------------------------------------------------------------------

# Scenario 1: Brute Force Authentication
BRUTE_FORCE_FAIL_THRESHOLD = int(os.getenv("BRUTE_FORCE_FAIL_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW_MINUTES = int(os.getenv("BRUTE_FORCE_WINDOW_MINUTES", "10"))  # 10 min sliding window

# Scenario 2: Suspicious Process Execution
POST_LOGON_WINDOW_MINUTES = int(os.getenv("POST_LOGON_WINDOW_MINUTES", "2"))
UNUSUAL_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "wscript.exe",
    "cscript.exe",
    "whoami.exe",
    "vssadmin.exe",
    "certutil.exe",
    "net.exe",
    "bitsadmin.exe"
]
SUSPICIOUS_PROCESSES = UNUSUAL_PROCESSES

# Scenario 3: Privilege-Related Activity
PRIVILEGE_EVENT_IDS = ["4672"]
PRIVILEGE_COMMANDS = ["sudo", "su", "doas"]
ADMIN_ACCOUNTS = [
    "administrator",
    "admin",
    "root",
    "system",
    "local system",
    "network service",
    "local service",
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service"
]

# Scenario 4: Network-Based Suspicious Activity
NETWORK_SCAN_PORT_THRESHOLD = int(os.getenv("NETWORK_SCAN_PORT_THRESHOLD", "5"))
NETWORK_SCAN_WINDOW_MINUTES = int(os.getenv("NETWORK_SCAN_WINDOW_MINUTES", "5"))
BLOCKED_BURST_THRESHOLD = int(os.getenv("BLOCKED_BURST_THRESHOLD", "5"))
BLOCKED_BURST_WINDOW_MINUTES = int(os.getenv("BLOCKED_BURST_WINDOW_MINUTES", "5"))

# Scenario 5: Additional Security Event (Sensitive File Access & Lateral Movement)
SENSITIVE_FILES = [
    "/etc/shadow",
    "/etc/sudoers",
    "SAM",
    "ntds.dit"
]
LATERAL_MOVEMENT_HOST_THRESHOLD = int(os.getenv("LATERAL_MOVEMENT_HOST_THRESHOLD", "2"))
LATERAL_MOVEMENT_WINDOW_MINUTES = int(os.getenv("LATERAL_MOVEMENT_WINDOW_MINUTES", "10"))

# Known scanner IPs or allowlisted addresses
ALLOWLIST_IPS = []

# Offline Network Subnets for Local IP Tagging (No external GeoIP)
INTERNAL_SUBNETS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10"
]
