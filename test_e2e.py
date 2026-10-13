"""
End-to-end verification test script for BCSSL Lab 07.
Runs end-to-end ingestion, normalization, storage, correlation, and deduplication.
Works against real Elasticsearch 8.13 (default) or Mock Elasticsearch (when USE_MOCK_ES=1).
"""

import sys
import os
from pathlib import Path
from datetime import datetime, timezone

import config
import normalizer
import correlate
from storage import get_es_client, initialize_indices, bulk_index_events, MockElasticsearch

import argparse

FIXTURES_DIR = Path(__file__).resolve().parent / "tests" / "fixtures"


def run_e2e_test(events_index: str = "test-security-events", alerts_index: str = "test-security-alerts", is_live: bool = False, reset: bool = False):
    print("=" * 70)
    print("  BCSSL LAB 07: SIEM LOG CORRELATION ENGINE — E2E VERIFICATION")
    print("=" * 70)

    es = get_es_client()
    is_mock = isinstance(es, MockElasticsearch)
    target_mode = "Mock Elasticsearch (in-memory)" if is_mock else f"Real Elasticsearch at {config.ES_HOST}"
    print(f"[*] Target Datastore : {target_mode}")
    print(f"[*] Events Index     : {events_index}")
    print(f"[*] Alerts Index     : {alerts_index}")

    # Ping ES
    try:
        if not es.ping():
            print(f"[!] Warning: Ping failed for {config.ES_HOST}.")
            if not is_mock:
                print("[!] Real Elasticsearch is not responding. Start Docker Desktop and 'docker compose up -d'.")
                return False
        else:
            print("[+] Datastore connectivity confirmed.")
    except Exception as e:
        print(f"[!] Connection error: {e}")
        if not is_mock:
            print("[!] Real Elasticsearch is not responding. Start Docker Desktop and 'docker compose up -d'.")
            return False

    # Initialize indices
    print(f"[*] Initializing '{events_index}' and '{alerts_index}' indices...")
    initialize_indices(es, events_index=events_index, alerts_index=alerts_index)

    # Clean indices for fresh test
    if is_live and not reset:
        print("[!] Safeguard: Running against live indices without --reset. Existing live data preserved.")
    else:
        try:
            es.indices.delete(index=events_index, ignore_unavailable=True)
            es.indices.delete(index=alerts_index, ignore_unavailable=True)
            initialize_indices(es, events_index=events_index, alerts_index=alerts_index)
            print("[+] Clean test state established.")
        except Exception as e:
            print(f"[!] Index reset warning: {e}")

    # 1. Ingest Rule 1 Fixture (Linux Auth Brute Force Failures)
    f1 = FIXTURES_DIR / "rule1_brute_force_fail.log"
    print(f"\n[1] Ingesting Linux Auth fixture ({f1.name})...")
    ev1, sk1 = normalizer.normalize_content(f1.read_text(encoding="utf-8"), "linux_auth")
    print(f"    Parsed: {len(ev1)} events | Skipped: {len(sk1)} lines")
    bulk_index_events(es, ev1, events_index)

    # 2. Ingest Rule 2 Fixture (Linux Auth Successful Brute Force)
    f2 = FIXTURES_DIR / "rule2_brute_force_success.log"
    print(f"\n[2] Ingesting Linux Auth fixture ({f2.name})...")
    ev2, sk2 = normalizer.normalize_content(f2.read_text(encoding="utf-8"), "linux_auth")
    print(f"    Parsed: {len(ev2)} events | Skipped: {len(sk2)} lines")
    bulk_index_events(es, ev2, events_index)

    # 3. Ingest Rule 3 Fixture (Windows Security 4624 -> PowerShell 4688)
    f3 = FIXTURES_DIR / "rule3_post_logon_powershell.csv"
    print(f"\n[3] Ingesting Windows Security CSV fixture ({f3.name})...")
    ev3, sk3 = normalizer.normalize_content(f3.read_text(encoding="utf-8"), "windows_security")
    print(f"    Parsed: {len(ev3)} events | Skipped: {len(sk3)} lines")
    bulk_index_events(es, ev3, events_index)

    # Ingest Benign Fixture
    fb = FIXTURES_DIR / "benign_activity.csv"
    print(f"\n[4] Ingesting Benign Activity fixture ({fb.name})...")
    evb, skb = normalizer.normalize_content(fb.read_text(encoding="utf-8"), "windows_security")
    print(f"    Parsed: {len(evb)} events | Skipped: {len(skb)} lines")
    bulk_index_events(es, evb, events_index)

    total_events = es.count(index=events_index)["count"]
    print(f"\n[+] Total normalized events indexed in '{events_index}': {total_events}")

    # Run Correlation
    print("\n[*] Executing correlation rules over all indexed events...")
    alerts = correlate.run_correlation(es, events_index=events_index, alerts_index=alerts_index)
    print(f"[+] Correlation cycle complete. Raised {len(alerts)} alerts.")

    # Validate generated alerts
    rule_names = {a["rule_name"]: a for a in alerts}
    print("\n" + "=" * 70)
    print(f"  {alerts_index.upper()} REPORT")
    print("=" * 70)
    print(f"{'SEVERITY':<10} | {'RULE NAME':<32} | {'MITRE':<10} | {'TARGET USER':<12} | {'SRC IP':<15}")
    print("-" * 90)
    for a in alerts:
        print(f"{a['severity'].upper():<10} | {a['rule_name']:<32} | {a['mitre_technique']:<10} | {str(a.get('user')):<12} | {str(a.get('src_ip')):<15}")

    assert "Brute Force Suspected" in rule_names, "FAIL: Rule 1 did not trigger!"
    assert rule_names["Brute Force Suspected"]["severity"] == "high", "FAIL: Rule 1 severity is not high!"

    assert "Successful Brute Force" in rule_names, "FAIL: Rule 2 did not trigger!"
    assert rule_names["Successful Brute Force"]["severity"] == "critical", "FAIL: Rule 2 severity is not critical!"

    assert "Post-Logon Suspicious Execution" in rule_names, "FAIL: Rule 3 did not trigger!"

    # Ingest comprehensive sample dataset generated by sample_log_generator.py
    import sample_log_generator
    print("\n[5] Generating and ingesting multi-source sample logs (Scenarios 3, 4, 5)...")
    sample_files = sample_log_generator.generate_sample_logs()

    win_samples = Path(sample_files["windows"]).read_text(encoding="utf-8")
    ev_win, _ = normalizer.normalize_content(win_samples, "windows_sysmon")
    bulk_index_events(es, ev_win, events_index)

    lx_samples = Path(sample_files["linux"]).read_text(encoding="utf-8")
    ev_lx, _ = normalizer.normalize_content(lx_samples, "linux_auditd")
    bulk_index_events(es, ev_lx, events_index)

    net_samples = Path(sample_files["network"]).read_text(encoding="utf-8")
    ev_net, _ = normalizer.normalize_content(net_samples, "network_firewall")
    bulk_index_events(es, ev_net, events_index)

    alerts_full = correlate.run_correlation(es, events_index=events_index, alerts_index=alerts_index)
    all_rules = {a["rule_name"]: a for a in alerts_full}

    print("\n" + "=" * 70)
    print("  ALL 5 SCENARIOS VERIFICATION")
    print("=" * 70)
    for a in alerts_full:
        print(f"  [ALERT] {a['severity'].upper():<10} | {a['rule_name']:<34} | MITRE: {a['mitre_technique']}")

    assert "Privilege-Related Activity" in all_rules, "FAIL: Scenario 3 (Privilege-Related Activity) did not trigger!"
    assert ("Network Port Scan Detected" in all_rules or "Burst of Blocked Connections" in all_rules), "FAIL: Scenario 4 did not trigger!"
    assert "Sensitive File Access" in all_rules, "FAIL: Scenario 5 (Sensitive File Access) did not trigger!"
    assert "Suspected Lateral Movement" in all_rules, "FAIL: Scenario 5 (Lateral Movement) did not trigger!"

    # Test Deduplication: Re-ingest Rule 3 fixture
    print("\n[*] Testing Deduplication: Re-ingesting Windows Security fixture...")
    total_events_before = es.count(index=events_index)["count"]
    total_alerts_before = es.count(index=alerts_index)["count"]

    bulk_index_events(es, ev3, events_index)
    alerts_after = correlate.run_correlation(es, events_index=events_index, alerts_index=alerts_index)
    total_events_after = es.count(index=events_index)["count"]
    total_alerts_after = es.count(index=alerts_index)["count"]

    assert total_events_after == total_events_before, f"FAIL: Event count increased ({total_events_after} != {total_events_before})!"
    assert total_alerts_after == total_alerts_before, f"FAIL: Alert count increased ({total_alerts_after} != {total_alerts_before})!"

    print(f"[+] Deduplication verified: Event count remains {total_events_after}, Alert count remains {total_alerts_after}.")

    print("\n" + "=" * 70)
    print("  ALL 5 END-TO-END SCENARIOS VERIFIED SUCCESSFULLY [PASSED]")
    print("=" * 70)
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="E2E Verification for SIEM Engine")
    parser.add_argument("--live", action="store_true", help="Run against live indices (security-events / security-alerts)")
    parser.add_argument("--reset", action="store_true", help="Explicitly wipe indices before running test")
    args = parser.parse_args()

    if args.live:
        target_events = config.INDEX_EVENTS
        target_alerts = config.INDEX_ALERTS
    else:
        target_events = "test-security-events"
        target_alerts = "test-security-alerts"

    success = run_e2e_test(
        events_index=target_events,
        alerts_index=target_alerts,
        is_live=args.live,
        reset=args.reset
    )
    sys.exit(0 if success else 1)
