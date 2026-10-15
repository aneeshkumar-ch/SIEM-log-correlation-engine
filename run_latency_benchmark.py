"""
Latency Benchmark Orchestrator.
Runs 3 benchmark cycles with DEFAULT intervals:
  - COLLECTOR_POLL_SECONDS = 2
  - CORRELATION_INTERVAL_SECONDS = 10
on temporary indices (temp-latency-events, temp-latency-alerts)
and temporary Kibana saved objects (prefixed 'temp-').

Measures seconds until:
  (a) events indexed
  (b) alert created
  (c) alert visible in /api/dashboard-data
  (d) alert visible on /dashboard with the toast
  (e) temp Kibana SOC Triage Board panels updated
all with NO manual refresh.

Cleans up only 'temp-' objects/indices and verifies live indices are untouched.
"""

import sys
import os
import json
import time
import shutil
import subprocess
from pathlib import Path
import requests

import config
from storage import get_es_client, initialize_indices
from verify_headless_render import generate_temp_saved_objects, delete_temporary_saved_objects

NODE_PATH = r"D:\PROJECTS\SIEM-CORRELATION-ENGINE\stack\kibana-8.13.0\node\node.exe"
NDJSON_FILE = Path(__file__).resolve().parent / "soc_triage_board.ndjson"
TEMP_EVENTS_IDX = "temp-latency-events"
TEMP_ALERTS_IDX = "temp-latency-alerts"
TEMP_INCOMING_DIR = Path(__file__).resolve().parent / "temp_latency_incoming"
SECOND_INSTANCE_PORT = 8001
KIBANA_URL = config.KIBANA_HOST.rstrip("/")


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    print("=" * 80)
    print("  SIEM LATENCY BENCHMARK: 3-RUN VERIFICATION (DEFAULT INTERVALS: 2s / 10s)")
    print("=" * 80)

    es = get_es_client()

    # Step 1: Record initial live index counts
    initial_events_count = es.count(index=config.INDEX_EVENTS)["count"]
    initial_alerts_count = es.count(index=config.INDEX_ALERTS)["count"]
    print(f"[*] Initial Live State (MUST REMAIN UNTOUCHED):")
    print(f"    '{config.INDEX_EVENTS}': {initial_events_count} documents")
    print(f"    '{config.INDEX_ALERTS}': {initial_alerts_count} documents")

    # Step 2: Initialize temporary indices
    print(f"\n[*] Resetting temporary indices: {TEMP_EVENTS_IDX}, {TEMP_ALERTS_IDX}...")
    es.indices.delete(index=[TEMP_EVENTS_IDX, TEMP_ALERTS_IDX], ignore_unavailable=True)
    initialize_indices(es, events_index=TEMP_EVENTS_IDX, alerts_index=TEMP_ALERTS_IDX)
    es.indices.refresh(index=TEMP_EVENTS_IDX)
    es.indices.refresh(index=TEMP_ALERTS_IDX)

    # Step 3: Setup temporary Kibana objects
    print(f"\n[*] Generating and importing temporary Kibana saved objects...")
    temp_objects = generate_temp_saved_objects(NDJSON_FILE, TEMP_EVENTS_IDX, TEMP_ALERTS_IDX)
    ndjson_payload = "\n".join(json.dumps(o) for o in temp_objects) + "\n"
    import_url = f"{KIBANA_URL}/api/saved_objects/_import?overwrite=true"
    resp = requests.post(
        import_url,
        headers={"kbn-xsrf": "true"},
        files={"file": ("temp.ndjson", ndjson_payload.encode("utf-8"), "application/ndjson")},
        timeout=30
    )
    if resp.status_code != 200 or not resp.json().get("success"):
        print(f"[!] Kibana temp import failed: {resp.status_code} {resp.text}")
        sys.exit(1)
    temp_object_ids = [o["id"] for o in temp_objects]
    print(f"[+] Successfully imported {len(temp_object_ids)} temp Kibana saved objects.")

    # Step 4: Setup temp incoming dir
    if TEMP_INCOMING_DIR.exists():
        shutil.rmtree(TEMP_INCOMING_DIR, ignore_errors=True)
    TEMP_INCOMING_DIR.mkdir(parents=True, exist_ok=True)
    (TEMP_INCOMING_DIR / "archive").mkdir(exist_ok=True)
    (TEMP_INCOMING_DIR / "rejected").mkdir(exist_ok=True)

    # Step 5: Start second FastAPI instance on port 8001
    env = os.environ.copy()
    env["INDEX_EVENTS"] = TEMP_EVENTS_IDX
    env["INDEX_ALERTS"] = TEMP_ALERTS_IDX
    env["COLLECTOR_POLL_SECONDS"] = "2"
    env["CORRELATION_INTERVAL_SECONDS"] = "10"
    env["INCOMING_DIR"] = str(TEMP_INCOMING_DIR)

    app_log_path = Path("second_instance.log")
    app_log_file = open(app_log_path, "w", encoding="utf-8")

    print(f"\n[*] Launching second app instance on port {SECOND_INSTANCE_PORT} (Collector=2s, Scheduler=10s)...", flush=True)
    app_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", str(SECOND_INSTANCE_PORT)],
        env=env,
        stdout=app_log_file,
        stderr=app_log_file,
        text=True
    )

    try:
        # Wait for second instance to be ready
        ready = False
        health_url = f"http://127.0.0.1:{SECOND_INSTANCE_PORT}/api/pipeline-health"
        print("[*] Waiting for second instance pipeline-health...", flush=True)
        for _ in range(30):
            try:
                r = requests.get(health_url, timeout=2)
                if r.status_code == 200:
                    data = r.json()
                    if data.get("collector_running") and data.get("scheduler_running"):
                        print(f"[+] Second instance ready! Health: {data}", flush=True)
                        ready = True
                        break
            except Exception:
                pass
            time.sleep(1)

        if not ready:
            print("[!] Second instance failed to start!", flush=True)
            sys.exit(1)

        # Step 6: Run browser runner via Node
        print("\n[*] Invoking Puppeteer browser runner (run_latency_browser.js)...", flush=True)
        node_proc = subprocess.Popen(
            [NODE_PATH, "run_latency_browser.js"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        for line in node_proc.stdout:
            print(line, end="", flush=True)
        node_proc.wait()

        if node_proc.returncode != 0:
            print(f"[!] Puppeteer benchmark runner exited with code {node_proc.returncode}", flush=True)
            sys.exit(1)

        # Step 7: Parse results
        results_file = Path("latency_results.json")
        if not results_file.exists():
            print("[!] latency_results.json not found!")
            sys.exit(1)

        results = json.loads(results_file.read_text(encoding="utf-8"))

        print("\n" + "=" * 80)
        print("  LATENCY BENCHMARK RESULTS (3 RUNS)")
        print("=" * 80)

        # Print detailed per-run table
        headers = [
            "Run",
            "Drop (T0)",
            "(a) Events Ingested",
            "(b) Alert Created",
            "(c) API Data (/api)",
            "(d) Dashboard Toast",
            "(e) Kibana Panels"
        ]

        print(f"{'Run':<5} | {'(a) Events':<12} | {'(b) Alert':<12} | {'(c) API Data':<12} | {'(d) Toast':<12} | {'(e) Kibana':<12} | {'Total Elapsed':<14}")
        print("-" * 86)

        step_a_vals = []
        step_b_vals = []
        step_c_vals = []
        step_d_vals = []
        step_e_vals = []

        for r in results:
            run_num = r["run"]
            a = r["step_a_sec"]
            b = r["step_b_sec"]
            c = r["step_c_sec"]
            d = r["step_d_sec"]
            e = r["step_e_sec"]

            if a is not None: step_a_vals.append(a)
            if b is not None: step_b_vals.append(b)
            if c is not None: step_c_vals.append(c)
            if d is not None: step_d_vals.append(d)
            if e is not None: step_e_vals.append(e)

            max_run = max(filter(None, [a, b, c, d, e]))
            print(f"{run_num:<5} | {f'{a:.2f}s':<12} | {f'{b:.2f}s':<12} | {f'{c:.2f}s':<12} | {f'{d:.2f}s':<12} | {f'{e:.2f}s':<12} | {f'{max_run:.2f}s':<14}")

        print("-" * 86)
        print(f"{'MIN':<5} | {f'{min(step_a_vals):.2f}s':<12} | {f'{min(step_b_vals):.2f}s':<12} | {f'{min(step_c_vals):.2f}s':<12} | {f'{min(step_d_vals):.2f}s':<12} | {f'{min(step_e_vals):.2f}s':<12} | {f'{min(step_e_vals):.2f}s':<14}")
        print(f"{'AVG':<5} | {f'{sum(step_a_vals)/len(step_a_vals):.2f}s':<12} | {f'{sum(step_b_vals)/len(step_b_vals):.2f}s':<12} | {f'{sum(step_c_vals)/len(step_c_vals):.2f}s':<12} | {f'{sum(step_d_vals)/len(step_d_vals):.2f}s':<12} | {f'{sum(step_e_vals)/len(step_e_vals):.2f}s':<12} | {f'{sum(step_e_vals)/len(step_e_vals):.2f}s':<14}")
        print(f"{'MAX':<5} | {f'{max(step_a_vals):.2f}s':<12} | {f'{max(step_b_vals):.2f}s':<12} | {f'{max(step_c_vals):.2f}s':<12} | {f'{max(step_d_vals):.2f}s':<12} | {f'{max(step_e_vals):.2f}s':<12} | {f'{max(step_e_vals):.2f}s':<14}")
        print("=" * 80)

        worst_case = max(step_e_vals)
        if worst_case <= 30.0:
            print(f"[PASS] Worst-case end-to-end latency was {worst_case:.2f}s, which is UNDER the 30-second requirement!")
        else:
            print(f"[FAIL / WARNING] Worst-case end-to-end latency was {worst_case:.2f}s, which EXCEEDS 30 seconds!")

    finally:
        # Step 8: Teardown and Cleanup
        print("\n" + "=" * 80)
        print("  CLEANUP & LIVE DATA INTEGRITY VERIFICATION")
        print("=" * 80)

        # Terminate second instance
        print("[*] Terminating second app instance...")
        app_proc.terminate()
        try:
            app_proc.wait(timeout=5)
        except Exception:
            app_proc.kill()
        try:
            app_log_file.close()
            if app_log_path.exists():
                app_log_path.unlink()
        except Exception:
            pass

        # Delete temp Kibana saved objects (strictly starting with 'temp-')
        print("[*] Deleting temporary Kibana saved objects (strictly prefixed 'temp-')...")
        deleted_objs = delete_temporary_saved_objects(KIBANA_URL, temp_object_ids)
        print(f"[+] Successfully removed {len(deleted_objs)} temporary saved object(s).")

        # Delete temporary indices
        print(f"[*] Deleting temporary indices: {TEMP_EVENTS_IDX}, {TEMP_ALERTS_IDX}...")
        es.indices.delete(index=[TEMP_EVENTS_IDX, TEMP_ALERTS_IDX], ignore_unavailable=True)
        print(f"[+] Deleted temporary indices.")

        # Clean incoming dir
        if TEMP_INCOMING_DIR.exists():
            shutil.rmtree(TEMP_INCOMING_DIR, ignore_errors=True)
            print(f"[+] Cleaned up temporary incoming directory.")

        if Path("latency_results.json").exists():
            Path("latency_results.json").unlink()

        # Check live indices
        final_events_count = es.count(index=config.INDEX_EVENTS)["count"]
        final_alerts_count = es.count(index=config.INDEX_ALERTS)["count"]
        print(f"\n[*] Final Live State Verification:")
        print(f"    '{config.INDEX_EVENTS}': {final_events_count} documents (initial: {initial_events_count})")
        print(f"    '{config.INDEX_ALERTS}': {final_alerts_count} documents (initial: {initial_alerts_count})")

        assert final_events_count == initial_events_count, f"LIVE EVENTS ALTERED: {final_events_count} != {initial_events_count}"
        assert final_alerts_count == initial_alerts_count, f"LIVE ALERTS ALTERED: {final_alerts_count} != {initial_alerts_count}"
        print("[+] SUCCESS: Live indices remained 100% untouched throughout all 3 benchmark runs.")
        print("=" * 80)


if __name__ == "__main__":
    main()
