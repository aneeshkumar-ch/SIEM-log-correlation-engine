"""
Utility script to import the SOC Triage Board dashboard and data views
into Kibana via the Kibana Saved Objects API once Kibana is running.
"""

import sys
import time
import requests
from pathlib import Path

import config

KIBANA_URL = config.KIBANA_HOST.rstrip("/")
IMPORT_ENDPOINT = f"{KIBANA_URL}/api/saved_objects/_import?overwrite=true"
NDJSON_FILE = Path(__file__).resolve().parent / "soc_triage_board.ndjson"


def wait_for_kibana(timeout: int = 180) -> bool:
    print(f"Checking Kibana availability at {KIBANA_URL} (timeout {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(f"{KIBANA_URL}/api/status", timeout=5)
            if r.status_code == 200:
                print("Kibana is ready!")
                return True
        except Exception:
            pass
        time.sleep(3)
        print(".", end="", flush=True)
    print("\nTimed out waiting for Kibana.")
    return False


def import_dashboard():
    if not NDJSON_FILE.exists():
        print(f"Error: {NDJSON_FILE} not found.")
        sys.exit(1)

    print(f"Importing saved objects from {NDJSON_FILE.name} into Kibana...")
    with open(NDJSON_FILE, "rb") as f:
        files = {"file": (NDJSON_FILE.name, f, "application/ndjson")}
        headers = {"kbn-xsrf": "true"}
        try:
            resp = requests.post(IMPORT_ENDPOINT, headers=headers, files=files, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                print("Dashboard import successful!")
                print(f"Success count: {data.get('successCount')}")
                if data.get("warnings"):
                    print(f"Warnings: {data.get('warnings')}")
                print(f"\nDashboard is available at: {KIBANA_URL}/app/dashboards#/view/soc-triage-board-dashboard")
            else:
                print(f"Import failed with status {resp.status_code}: {resp.text}")
        except Exception as e:
            print(f"Connection error during import: {e}")


if __name__ == "__main__":
    if wait_for_kibana(timeout=10):
        import_dashboard()
    else:
        print(f"\nKibana is not currently responding at {KIBANA_URL}.")
        print("Run this script ('python setup_kibana.py') after starting Kibana to automatically import the dashboard.")
