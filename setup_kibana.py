"""
Utility script to import the SOC Triage Board, Alerts Dashboard, Timeline Analysis,
and Data Views into Kibana via the Saved Objects API, then verify every saved object.

Strict requirement: This script ONLY imports saved objects. It creates NO data and NO temporary indices.
"""

import sys
import time
import requests
from pathlib import Path
from typing import Dict, Any, List, Tuple

import config

KIBANA_URL = config.KIBANA_HOST.rstrip("/")
IMPORT_ENDPOINT = f"{KIBANA_URL}/api/saved_objects/_import?overwrite=true"
NDJSON_FILE = Path(__file__).resolve().parent / "soc_triage_board.ndjson"


def wait_for_kibana(timeout: int = 180) -> bool:
    print(f"Checking Kibana availability at {KIBANA_URL} (timeout {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{KIBANA_URL}/api/status", headers={"kbn-xsrf": "true"}, timeout=5)
            if r.status_code == 200:
                print("Kibana is ready!")
                return True
        except Exception:
            pass
        time.sleep(3)
        print(".", end="", flush=True)
    print("\nTimed out waiting for Kibana.")
    return False


def import_dashboard() -> bool:
    if not NDJSON_FILE.exists():
        print(f"Error: {NDJSON_FILE} not found.")
        return False

    print(f"\n[*] Importing saved objects from {NDJSON_FILE.name} into Kibana (overwrite=true)...")
    with open(NDJSON_FILE, "rb") as f:
        files = {"file": (NDJSON_FILE.name, f, "application/ndjson")}
        headers = {"kbn-xsrf": "true"}
        try:
            resp = requests.post(IMPORT_ENDPOINT, headers=headers, files=files, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                print("[+] Saved objects import successful!")
                print(f"    Success Count : {data.get('successCount')}")
                print(f"    Success       : {data.get('success')}")
                if data.get("warnings"):
                    print(f"    Warnings      : {data.get('warnings')}")
                if data.get("errors"):
                    print(f"    Errors        : {data.get('errors')}")
                return True
            else:
                print(f"[!] Import failed with status {resp.status_code}: {resp.text}")
                return False
        except Exception as e:
            print(f"[!] Connection error during import: {e}")
            return False


def verify_saved_objects() -> bool:
    print("\n" + "=" * 70)
    print("  KIBANA SAVED OBJECTS VERIFICATION REPORT (25 Saved Objects)")
    print("=" * 70)

    objects_to_check: List[Tuple[str, str, str]] = [
        ("index-pattern", "security-alerts-dataview", "Data View: security-alerts*"),
        ("index-pattern", "security-events-dataview", "Data View: security-events*"),
        ("lens", "metric-total-alerts", "Lens Metric: Total Alerts"),
        ("lens", "metric-critical-alerts", "Lens Metric: Critical Alerts"),
        ("lens", "metric-high-alerts", "Lens Metric: High Alerts"),
        ("lens", "metric-medium-alerts", "Lens Metric: Medium Alerts"),
        ("lens", "metric-unique-source-ips", "Lens Metric: Unique Source IPs"),
        ("lens", "metric-affected-hosts", "Lens Metric: Affected Hosts"),
        ("lens", "alerts-by-severity", "Lens: Alerts by Severity Over Time"),
        ("lens", "event-categories-pie", "Lens Pie: Event Categories"),
        ("lens", "top-hosts-by-events", "Lens: Top Hosts by Events (Horizontal Bar)"),
        ("lens", "events-by-source-donut", "Lens Donut: Events by Log Source"),
        ("lens", "top-source-ips", "Lens Data Table: Top Source IPs"),
        ("lens", "suspicious-execution-hosts", "Lens Data Table: Hosts with Post-Logon Suspicious Execution"),
        ("lens", "alerts-by-rule", "Lens: Alerts by Detection Rule (Horizontal Bar)"),
        ("lens", "alerts-by-mitre", "Lens: Alerts by MITRE Technique"),
        ("lens", "alerts-by-user", "Lens: Alerts by User"),
        ("lens", "alerts-by-host", "Lens: Alerts by Host"),
        ("lens", "recent-alerts-table", "Lens Data Table: Recent Security Alerts"),
        ("lens", "timeline-events-over-time", "Lens: Security Events Over Time"),
        ("lens", "events-by-source", "Lens: Events by Log Source"),
        ("search", "events-search", "Saved Search: Security Events Raw Search"),
        ("dashboard", "soc-triage-board-dashboard", "Dashboard: SOC Triage Board"),
        ("dashboard", "alerts-dashboard", "Dashboard: Alerts Dashboard"),
        ("dashboard", "timeline-analysis-dashboard", "Dashboard: Timeline Analysis")
    ]

    headers = {"kbn-xsrf": "true"}
    all_ok = True

    for obj_type, obj_id, label in objects_to_check:
        url = f"{KIBANA_URL}/api/saved_objects/{obj_type}/{obj_id}"
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code == 200:
                obj = r.json()
                attr = obj.get("attributes", {})
                title = attr.get("title", attr.get("name", "N/A"))
                print(f"  [OK] {label:<50} -> HTTP 200 (Title: '{title}')")
            else:
                print(f"  [FAIL] {label:<50} -> HTTP {r.status_code}")
                all_ok = False
        except Exception as e:
            print(f"  [ERROR] {label:<50} -> {e}")
            all_ok = False

    print("\n" + "=" * 70)
    print(f"  Saved objects verification status: {'ALL 25 OK' if all_ok else 'SOME FAILED'}")
    print(f"  Kibana Dashboards are live at:")
    print(f"  - SOC Triage Board  : {KIBANA_URL}/app/dashboards#/view/soc-triage-board-dashboard")
    print(f"  - Alerts Dashboard  : {KIBANA_URL}/app/dashboards#/view/alerts-dashboard")
    print(f"  - Timeline Analysis : {KIBANA_URL}/app/dashboards#/view/timeline-analysis-dashboard")
    print(f"  - Discover Events   : {KIBANA_URL}/app/discover#/view/events-search")
    print("=" * 70)

    return all_ok


if __name__ == "__main__":
    if wait_for_kibana(timeout=30):
        if import_dashboard():
            success = verify_saved_objects()
            sys.exit(0 if success else 1)
        else:
            sys.exit(1)
    else:
        print(f"\nKibana is not currently responding at {KIBANA_URL}.")
        sys.exit(1)
