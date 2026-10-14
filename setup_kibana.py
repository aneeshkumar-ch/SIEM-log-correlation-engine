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

    # Ingest temporary test data to verify all panels without touching live indices
    temp_events_idx = "test-render-events"
    temp_alerts_idx = "test-render-alerts"

    print("\n" + "=" * 70)
    print("  PANEL DATA RETURN VERIFICATION (Using Temporary Test Indices)")
    print(f"  Target: {temp_events_idx} & {temp_alerts_idx}")
    print("=" * 70)

    es = get_es_client()
    import normalizer
    import correlate
    from storage import initialize_indices, bulk_index_events

    try:
        # 1. Clean and initialize temp indices
        es.indices.delete(index=[temp_events_idx, temp_alerts_idx], ignore_unavailable=True)
        initialize_indices(es, events_index=temp_events_idx, alerts_index=temp_alerts_idx)

        # 2. Ingest test fixtures
        fixtures_dir = Path(__file__).resolve().parent / "tests" / "fixtures"
        for fix_file, src_type in [
            ("rule1_brute_force_fail.log", "linux_auth"),
            ("rule2_brute_force_success.log", "linux_auth"),
            ("rule3_post_logon_powershell.csv", "windows_security"),
            ("benign_activity.csv", "windows_security")
        ]:
            p = fixtures_dir / fix_file
            if p.exists():
                evs, _ = normalizer.normalize_content(p.read_text(encoding="utf-8"), src_type)
                bulk_index_events(es, evs, temp_events_idx)

        # Ingest multi-source sample dataset
        import sample_log_generator
        sample_files = sample_log_generator.generate_sample_logs()
        for s_type, p_str in [("windows_sysmon", sample_files["windows"]), ("linux_auditd", sample_files["linux"]), ("network_firewall", sample_files["network"])]:
            p = Path(p_str)
            if p.exists():
                evs, _ = normalizer.normalize_content(p.read_text(encoding="utf-8"), s_type)
                bulk_index_events(es, evs, temp_events_idx)

        # Correlate into temporary alerts index
        correlate.run_correlation(es, events_index=temp_events_idx, alerts_index=temp_alerts_idx)

        # Include a low severity alert to verify all 4 severity series colors
        import datetime
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        low_alert = {
            "alert_id": "temp-test-low-alert",
            "rule_name": "Low Severity Informational Notice",
            "severity": "low",
            "first_seen": now_iso,
            "last_seen": now_iso,
            "user": "analyst",
            "src_ip": "10.0.0.99",
            "host": ["WORKSTATION-01"],
            "event_count": 1,
            "summary": "Informational low severity test alert",
            "mitre_technique": "T1059",
            "contributing_events": []
        }
        es.index(index=temp_alerts_idx, document=low_alert, refresh=True)

        # Row 1 Metric Panels Verification:
        res_metrics = es.search(
            index=temp_alerts_idx,
            query={"match_all": {}},
            size=0,
            aggs={
                "unique_ips": {"cardinality": {"field": "src_ip"}},
                "unique_hosts": {"cardinality": {"field": "host"}},
                "critical_count": {"filter": {"term": {"severity": "critical"}}},
                "high_count": {"filter": {"term": {"severity": "high"}}}
            }
        )
        total_m = res_metrics.get("hits", {}).get("total", {}).get("value", 0)
        crit_m = res_metrics.get("aggregations", {}).get("critical_count", {}).get("doc_count", 0)
        high_m = res_metrics.get("aggregations", {}).get("high_count", {}).get("doc_count", 0)
        u_ips = res_metrics.get("aggregations", {}).get("unique_ips", {}).get("value", 0)
        u_hosts = res_metrics.get("aggregations", {}).get("unique_hosts", {}).get("value", 0)
        print(f"\n  [Top Metric Counters]")
        print(f"           - Total Alerts       : {total_m}")
        print(f"           - Critical Alerts    : {crit_m}")
        print(f"           - High Alerts        : {high_m}")
        print(f"           - Unique Source IPs  : {u_ips}")
        print(f"           - Affected Hosts     : {u_hosts}")

        # Panel 1: Alerts by Severity Over Time
        res_sev = es.search(
            index=temp_alerts_idx,
            query={"match_all": {}},
            size=0,
            aggs={"severities": {"terms": {"field": "severity"}}}
        )
        sev_buckets = res_sev.get("aggregations", {}).get("severities", {}).get("buckets", [])
        total_alerts = res_sev.get("hits", {}).get("total", {}).get("value", 0)
        print(f"\n  [Panel 1: Alerts by Severity Over Time] Total: {total_alerts} alert(s)")
        for b in sev_buckets:
            print(f"           - {b['key'].upper():<10}: {b['doc_count']} alert(s)")

        # Panel 2: Top Source IPs (Data Table)
        res_ips = es.search(
            index=temp_alerts_idx,
            query={"match_all": {}},
            size=0,
            aggs={"top_ips": {"terms": {"field": "src_ip", "size": 10}}}
        )
        ip_buckets = res_ips.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
        print(f"\n  [Panel 2: Top Source IPs (Data Table)] {len(ip_buckets)} row(s):")
        for b in ip_buckets:
            print(f"           - IP: {b['key']:<18} | Count: {b['doc_count']}")

        # Panel 3: Hosts with Post-Logon Suspicious Execution (Data Table)
        res_hosts = es.search(
            index=temp_alerts_idx,
            query={"term": {"rule_name": "Post-Logon Suspicious Execution"}},
            size=10
        )
        hits_hosts = res_hosts.get("hits", {}).get("hits", [])
        print(f"\n  [Panel 3: Hosts with Post-Logon Suspicious Execution (Data Table)] {len(hits_hosts)} hit(s):")
        for h in hits_hosts:
            src = h["_source"]
            print(f"           - Host: {src.get('host'):<15} | User: {src.get('user'):<10} | Severity: {src.get('severity')}")

        # Panel 4: Alerts by Detection Rule
        res_rules = es.search(
            index=temp_alerts_idx,
            query={"match_all": {}},
            size=0,
            aggs={"rules": {"terms": {"field": "rule_name", "size": 10}}}
        )
        rule_buckets = res_rules.get("aggregations", {}).get("rules", {}).get("buckets", [])
        print(f"\n  [Panel 4: Alerts by Detection Rule (Horizontal Bar)] {len(rule_buckets)} active rule(s):")
        for b in rule_buckets:
            print(f"           - {b['key']:<34}: {b['doc_count']} alert(s)")

        # Panel 4B: Alerts by MITRE Technique
        res_mitre = es.search(
            index=temp_alerts_idx,
            query={"match_all": {}},
            size=0,
            aggs={"mitre": {"terms": {"field": "mitre_technique", "size": 10}}}
        )
        mitre_buckets = res_mitre.get("aggregations", {}).get("mitre", {}).get("buckets", [])
        print(f"\n  [Panel 4B: Alerts by MITRE Technique] {len(mitre_buckets)} technique(s):")
        for b in mitre_buckets:
            print(f"           - {b['key']:<34}: {b['doc_count']} alert(s)")

        # Panel 5: Alerts by User
        res_users = es.search(
            index=temp_alerts_idx,
            query={"match_all": {}},
            size=0,
            aggs={"users": {"terms": {"field": "user", "size": 10}}}
        )
        user_buckets = res_users.get("aggregations", {}).get("users", {}).get("buckets", [])
        print(f"\n  [Panel 5: Alerts by User] {len(user_buckets)} user(s):")
        for b in user_buckets:
            print(f"           - User: {b['key']:<18} | Alerts: {b['doc_count']}")

        # Panel 6: Alerts by Host
        res_host_dist = es.search(
            index=temp_alerts_idx,
            query={"match_all": {}},
            size=0,
            aggs={"hosts": {"terms": {"field": "host", "size": 10}}}
        )
        host_buckets = res_host_dist.get("aggregations", {}).get("hosts", {}).get("buckets", [])
        print(f"\n  [Panel 6: Alerts by Host] {len(host_buckets)} host(s):")
        for b in host_buckets:
            print(f"           - Host: {b['key']:<22} | Alerts: {b['doc_count']}")

        # Panel 7: Recent Alerts Table (Data Table)
        res_recent = es.search(
            index=temp_alerts_idx,
            query={"match_all": {}},
            size=5,
            sort=[{"first_seen": {"order": "desc"}}]
        )
        recent_hits = res_recent.get("hits", {}).get("hits", [])
        print(f"\n  [Panel 7: Recent Security Alerts Table (Data Table)] Top {len(recent_hits)} recent entries:")
        for h in recent_hits:
            s = h["_source"]
            print(f"           - {s.get('first_seen')} | {s.get('rule_name'):<30} | {s.get('severity'):<8} | {str(s.get('user')):<10} | {str(s.get('src_ip')):<15} | {s.get('host')}")

        # Panel 8: Security Events Over Time
        total_evs = es.count(index=temp_events_idx)["count"]
        print(f"\n  [Panel 8: Security Events Over Time] Total events indexed: {total_evs}")

        # Panel 9: Events by Log Source
        res_src = es.search(
            index=temp_events_idx,
            query={"match_all": {}},
            size=0,
            aggs={"sources": {"terms": {"field": "source"}}}
        )
        src_buckets = res_src.get("aggregations", {}).get("sources", {}).get("buckets", [])
        print(f"\n  [Panel 9: Events by Log Source] Distribution:")
        for b in src_buckets:
            print(f"           - Source: {b['key']:<12} | Events: {b['doc_count']}")

        # Panel 10: Events Raw Search (Discover Search)
        res_search = es.search(index=temp_events_idx, query={"match_all": {}}, size=3)
        print(f"\n  [Panel 10: Events Raw Search (Discover)] Matches: {res_search.get('hits', {}).get('total', {}).get('value', 0)} total docs")

    except Exception as e:
        print(f"  [!] Panel query error: {e}")
        all_ok = False
    finally:
        # Clean up temporary test data
        es.indices.delete(index=[temp_events_idx, temp_alerts_idx], ignore_unavailable=True)
        print(f"\n[+] Cleaned up temporary test indices ({temp_events_idx}, {temp_alerts_idx}).")

    # Confirm live indices remain 0
    c_live_events = es.count(index=config.INDEX_EVENTS)["count"]
    c_live_alerts = es.count(index=config.INDEX_ALERTS)["count"]
    print(f"[+] Live index verification: '{config.INDEX_EVENTS}' count={c_live_events}, '{config.INDEX_ALERTS}' count={c_live_alerts}")

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

