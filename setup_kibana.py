"""
Utility script to import the SOC Triage Board, Alerts Dashboard, Timeline Analysis,
and Data Views into Kibana via the Saved Objects API, then verify every object and panel data.
"""

import sys
import time
import requests
from pathlib import Path
from typing import Dict, Any

import config
from storage import get_es_client

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


def verify_saved_objects_and_data() -> bool:
    print("\n" + "=" * 70)
    print("  KIBANA SAVED OBJECTS VERIFICATION REPORT")
    print("=" * 70)

    objects_to_check = [
        ("index-pattern", "security-alerts-dataview", "Data View: security-alerts*"),
        ("index-pattern", "security-events-dataview", "Data View: security-events*"),
        ("lens", "alerts-by-severity", "Lens: Alerts by Severity Over Time"),
        ("lens", "top-source-ips", "Lens: Top Source IPs"),
        ("lens", "suspicious-execution-hosts", "Lens: Hosts with Post-Logon Suspicious Execution"),
        ("lens", "alerts-by-rule", "Lens: Alerts by Detection Rule"),
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

    # Verify panel datastore results
    print("\n" + "=" * 70)
    print("  PANEL DATA RETURN VERIFICATION")
    print("=" * 70)

    es = get_es_client()
    try:
        # Panel 1: Alerts by Severity
        res_sev = es.search(
            index=config.INDEX_ALERTS,
            query={"match_all": {}},
            size=0,
            aggs={"severities": {"terms": {"field": "severity"}}}
        )
        sev_buckets = res_sev.get("aggregations", {}).get("severities", {}).get("buckets", [])
        total_alerts = res_sev.get("hits", {}).get("total", {}).get("value", 0)
        print(f"  [Panel 1: Alerts by Severity Over Time] Total: {total_alerts} alerts across {len(sev_buckets)} severity levels.")
        for b in sev_buckets:
            print(f"           - {b['key'].upper():<10}: {b['doc_count']} alert(s)")

        # Panel 2: Top Source IPs
        res_ips = es.search(
            index=config.INDEX_ALERTS,
            query={"match_all": {}},
            size=0,
            aggs={"top_ips": {"terms": {"field": "src_ip", "size": 10}}}
        )
        ip_buckets = res_ips.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
        print(f"  [Panel 2: Top Source IPs] Found {len(ip_buckets)} distinct source IP(s):")
        for b in ip_buckets:
            print(f"           - {b['key']:<20}: {b['doc_count']} alert(s)")

        # Panel 3: Suspicious Execution Hosts
        res_hosts = es.search(
            index=config.INDEX_ALERTS,
            query={"term": {"rule_name": "Post-Logon Suspicious Execution"}},
            size=10
        )
        hits_hosts = res_hosts.get("hits", {}).get("hits", [])
        print(f"  [Panel 3: Hosts with Post-Logon Suspicious Execution] Hits: {len(hits_hosts)}")
        for h in hits_hosts:
            src = h["_source"]
            print(f"           - Host: {src.get('host')} | User: {src.get('user')} | Process: PowerShell | Severity: {src.get('severity')}")

        # Events telemetry check
        total_events = es.count(index=config.INDEX_EVENTS)["count"]
        print(f"\n  [Security Events Telemetry] Total indexed events in '{config.INDEX_EVENTS}': {total_events}")

    except Exception as e:
        print(f"  [!] Datastore query error: {e}")
        all_ok = False

    print("=" * 70)
    print(f"  Kibana Dashboards are live at:")
    print(f"  - SOC Triage Board  : {KIBANA_URL}/app/dashboards#/view/soc-triage-board-dashboard")
    print(f"  - Alerts Dashboard  : {KIBANA_URL}/app/dashboards#/view/alerts-dashboard")
    print(f"  - Timeline Analysis : {KIBANA_URL}/app/dashboards#/view/timeline-analysis-dashboard")
    print(f"  - Discover Events   : {KIBANA_URL}/app/discover#/view/events-search")
    print("=" * 70)

    return all_ok


if __name__ == "__main__":
    if wait_for_kibana(timeout=15):
        if import_dashboard():
            success = verify_saved_objects_and_data()
            sys.exit(0 if success else 1)
        else:
            sys.exit(1)
    else:
        print(f"\nKibana is not currently responding at {KIBANA_URL}.")
        sys.exit(1)
