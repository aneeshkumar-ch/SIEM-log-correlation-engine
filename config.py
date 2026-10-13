import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent
UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)

# Service URLs (Bind localhost only)
ES_HOST = os.getenv("ES_HOST", "http://127.0.0.1:9200")
KIBANA_HOST = os.getenv("KIBANA_HOST", "http://127.0.0.1:5601")

# Elasticsearch Indices
INDEX_EVENTS = os.getenv("INDEX_EVENTS", "normalized-events")
INDEX_ALERTS = os.getenv("INDEX_ALERTS", "security-alerts")

# Switchable Mock ES flag (default is False: real Elasticsearch client)
USE_MOCK_ES = os.getenv("USE_MOCK_ES", "false").lower() in ("true", "1", "yes")

# Upload Configuration
MAX_UPLOAD_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB limit
ALLOWED_EXTENSIONS = {".log", ".txt", ".json", ".jsonl", ".csv"}

# Correlation Rule Thresholds & Config
BRUTE_FORCE_FAIL_THRESHOLD = int(os.getenv("BRUTE_FORCE_FAIL_THRESHOLD", "5"))
BRUTE_FORCE_WINDOW_MINUTES = int(os.getenv("BRUTE_FORCE_WINDOW_MINUTES", "5"))
POST_LOGON_WINDOW_MINUTES = int(os.getenv("POST_LOGON_WINDOW_MINUTES", "2"))

# Suspicious process names for Rule 3 (case-insensitive matching)
SUSPICIOUS_PROCESSES = [
    "powershell.exe",
    "cmd.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "wscript.exe",
    "cscript.exe"
]

# Admin accounts for Rule 3 (case-insensitive matching)
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

# Known scanner IPs or allowlisted addresses
ALLOWLIST_IPS = []
