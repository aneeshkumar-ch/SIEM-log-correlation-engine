"""
End-to-End Automated Pipeline Verification Script.
Tests:
1. Environment variable overrides for INDEX_EVENTS, INDEX_ALERTS, INCOMING_DIR, UPLOADS_DIR.
2. Background collector watcher: automatically ingests dropped log files and archives them to ./incoming/archive.
3. Background correlation scheduler: automatically detects newly ingested events, locks, and correlates alerts.
4. Total pipeline latency from file drop to alert generation (< 30 seconds requirement).
5. Pipeline health API status.
6. Zero impact on live indices (verifies live document counts before and after).
"""

import os
import sys
import time
import shutil
import asyncio
from pathlib import Path
from datetime import datetime, timezone

# Temporary environment variable configuration
TEMP_BASE = Path(__file__).resolve().parent / "temp_pipeline_test"
TEMP_INCOMING = TEMP_BASE / "incoming"
TEMP_UPLOADS = TEMP_BASE / "uploads"
TEMP_EVENTS_INDEX = "temp-test-pipeline-events"
TEMP_ALERTS_INDEX = "temp-test-pipeline-alerts"

os.environ["INDEX_EVENTS"] = TEMP_EVENTS_INDEX
os.environ["INDEX_ALERTS"] = TEMP_ALERTS_INDEX
os.environ["INCOMING_DIR"] = str(TEMP_INCOMING)
os.environ["UPLOADS_DIR"] = str(TEMP_UPLOADS)
os.environ["COLLECTOR_POLL_SECONDS"] = "2"
os.environ["CORRELATION_INTERVAL_SECONDS"] = "4"

import config
import storage
from storage import get_es_client, initialize_indices
import correlate
import collector
from pipeline_manager import PipelineManager


async def run_pipeline_test():
    print("=" * 70)
    print("  AUTONOMOUS END-TO-END PIPELINE VERIFICATION")
    print("=" * 70)

    es = get_es_client()
    if not es.ping():
        print("[!] Elasticsearch is not reachable. Aborting test.")
        return False

    # 1. Record live index counts before test
    live_events_before = es.count(index="security-events")["count"]
    live_alerts_before = es.count(index="security-alerts")["count"]
    print(f"[*] Live Indices Before Test: security-events={live_events_before}, security-alerts={live_alerts_before}")

    # 2. Setup clean temporary directory and indices
    if TEMP_BASE.exists():
        shutil.rmtree(TEMP_BASE)
    TEMP_INCOMING.mkdir(parents=True, exist_ok=True)
    TEMP_UPLOADS.mkdir(parents=True, exist_ok=True)

    es.indices.delete(index=[TEMP_EVENTS_INDEX, TEMP_ALERTS_INDEX], ignore_unavailable=True)
    initialize_indices(es, events_index=TEMP_EVENTS_INDEX, alerts_index=TEMP_ALERTS_INDEX)

    # 3. Instantiate an isolated PipelineManager
    mgr = PipelineManager()
    await mgr.start()
    print(f"[+] Started test pipeline manager: Collector polling every {config.COLLECTOR_POLL_SECONDS}s, Scheduler running every {config.CORRELATION_INTERVAL_SECONDS}s")

    # 4. Prepare test log fixture (Brute Force failure log with 6 events)
    test_log_content = """Oct 15 13:00:00 srv01 sshd[101]: Failed password for invalid user admin from 198.51.100.77 port 4001 ssh2
Oct 15 13:00:15 srv01 sshd[102]: Failed password for invalid user root from 198.51.100.77 port 4002 ssh2
Oct 15 13:00:30 srv01 sshd[103]: Failed password for invalid user test from 198.51.100.77 port 4003 ssh2
Oct 15 13:00:45 srv01 sshd[104]: Failed password for invalid user oracle from 198.51.100.77 port 4004 ssh2
Oct 15 13:01:00 srv01 sshd[105]: Failed password for invalid user guest from 198.51.100.77 port 4005 ssh2
Oct 15 13:01:15 srv01 sshd[106]: Failed password for invalid user admin from 198.51.100.77 port 4006 ssh2
"""
    drop_file = TEMP_INCOMING / "auth_brute_force.log"

    print(f"\n[*] Dropping telemetry file into: {drop_file}")
    start_time = time.perf_counter()
    drop_file.write_text(test_log_content, encoding="utf-8")

    # 5. Monitor pipeline execution (maximum timeout: 30 seconds)
    print("[*] Monitoring autonomous pipeline for ingestion, archive, and alert generation (< 30s)...")
    ingested = False
    archived = False
    alert_generated = False
    elapsed_total = 0

    while (time.perf_counter() - start_time) < 30:
        await asyncio.sleep(1)
        current_elapsed = time.perf_counter() - start_time

        # Check archiving
        archive_path = TEMP_INCOMING / "archive" / "auth_brute_force.log"
        if not archived and archive_path.exists() and not drop_file.exists():
            archived = True
            print(f"  [+] Step 1 (Archive): File automatically archived in {current_elapsed:.2f}s")

        # Check event ingestion
        if not ingested:
            try:
                cnt = es.count(index=TEMP_EVENTS_INDEX)["count"]
                if cnt >= 6:
                    ingested = True
                    print(f"  [+] Step 2 (Ingest):  {cnt} events indexed into {TEMP_EVENTS_INDEX} in {current_elapsed:.2f}s")
            except Exception:
                pass

        # Check alert generation
        if ingested and not alert_generated:
            try:
                a_cnt = es.count(index=TEMP_ALERTS_INDEX)["count"]
                if a_cnt >= 1:
                    alert_generated = True
                    elapsed_total = current_elapsed
                    print(f"  [+] Step 3 (Alert):   {a_cnt} alert(s) generated in {TEMP_ALERTS_INDEX} in {elapsed_total:.2f}s")
                    break
            except Exception:
                pass

    # 6. Stop pipeline manager
    await mgr.stop()

    # 7. Check Health API reporting
    health = mgr.get_health(es)
    print("\n[*] Pipeline Health Verification:")
    print(f"    Last Event Ingested At: {health.get('last_event_ingested_at')}")
    print(f"    Last Correlation At:    {health.get('last_correlation_at')}")
    print(f"    Last Alert Raised At:   {health.get('last_alert_raised_at')}")
    print(f"    Events Count:           {health.get('events_count')}")
    print(f"    Alerts Count:           {health.get('alerts_count')}")

    # 8. Clean up temporary indices and directory
    es.indices.delete(index=[TEMP_EVENTS_INDEX, TEMP_ALERTS_INDEX], ignore_unavailable=True)
    if TEMP_BASE.exists():
        shutil.rmtree(TEMP_BASE)
    print("[+] Cleaned up temporary test indices and directories.")

    # 9. Verify live indices were NOT modified
    live_events_after = es.count(index="security-events")["count"]
    live_alerts_after = es.count(index="security-alerts")["count"]
    print(f"[*] Live Indices After Test:  security-events={live_events_after}, security-alerts={live_alerts_after}")

    assert live_events_before == live_events_after, f"Live events changed from {live_events_before} to {live_events_after}!"
    assert live_alerts_before == live_alerts_after, f"Live alerts changed from {live_alerts_before} to {live_alerts_after}!"
    print("[OK] CONFIRMED: Live indices remained 100% untouched!")

    # 10. Summary result
    success = (ingested and archived and alert_generated and elapsed_total < 30)
    print("\n" + "=" * 70)
    if success:
        print(f"  PIPELINE VERIFICATION SUCCESSFUL (Total Time: {elapsed_total:.2f}s < 30s requirement)")
    else:
        print(f"  PIPELINE VERIFICATION FAILED (Ingested={ingested}, Archived={archived}, Alert={alert_generated})")
    print("=" * 70)
    return success


if __name__ == "__main__":
    ok = asyncio.run(run_pipeline_test())
    sys.exit(0 if ok else 1)
