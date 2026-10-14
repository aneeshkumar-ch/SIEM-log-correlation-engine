"""
Headless render verification script for Kibana dashboards and App /dashboard.
Uses TEMPORARY indices (test-render-events, test-render-alerts) and temporary saved objects.
Checks every panel across all 3 dashboards and the web app /dashboard.
Saves headless screenshots to ./screenshots.
Deletes all temporary objects and indices afterward.
Verifies live indices remain unchanged.
"""

import sys
import os
import json
import time
import datetime
import subprocess
from pathlib import Path
import requests

import config
from storage import get_es_client, initialize_indices, bulk_index_events
import normalizer
import correlate
import sample_log_generator

TEMP_EVENTS_IDX = "test-render-events"
TEMP_ALERTS_IDX = "test-render-alerts"
KIBANA_URL = config.KIBANA_HOST.rstrip("/")
APP_URL = "http://127.0.0.1:8000"
SCREENSHOTS_DIR = Path(__file__).resolve().parent / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)

NODE_PATH = r"D:\PROJECTS\SIEM-CORRELATION-ENGINE\stack\kibana-8.13.0\node\node.exe"
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
PUPPETEER_PATH = r"D:\PROJECTS\SIEM-CORRELATION-ENGINE\stack\kibana-8.13.0\node_modules\puppeteer-core"


def setup_temp_indices(es):
    print(f"\n[*] Initializing temporary indices: {TEMP_EVENTS_IDX} & {TEMP_ALERTS_IDX}...")
    es.indices.delete(index=[TEMP_EVENTS_IDX, TEMP_ALERTS_IDX], ignore_unavailable=True)
    initialize_indices(es, events_index=TEMP_EVENTS_IDX, alerts_index=TEMP_ALERTS_IDX)

    # Ingest test fixtures into temporary events index
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
            bulk_index_events(es, evs, TEMP_EVENTS_IDX)

    # Ingest multi-source sample logs into temporary events index
    sample_files = sample_log_generator.generate_sample_logs()
    for s_type, p_str in [
        ("windows_sysmon", sample_files["windows"]),
        ("linux_auditd", sample_files["linux"]),
        ("network_firewall", sample_files["network"])
    ]:
        p = Path(p_str)
        if p.exists():
            evs, _ = normalizer.normalize_content(p.read_text(encoding="utf-8"), s_type)
            bulk_index_events(es, evs, TEMP_EVENTS_IDX)

    # Correlate into temporary alerts index
    correlate.run_correlation(es, events_index=TEMP_EVENTS_IDX, alerts_index=TEMP_ALERTS_IDX)

    # Add low severity alert
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
    es.index(index=TEMP_ALERTS_IDX, document=low_alert, refresh=True)

    c_ev = es.count(index=TEMP_EVENTS_IDX)["count"]
    c_al = es.count(index=TEMP_ALERTS_IDX)["count"]
    print(f"[+] Populated temporary indices: {TEMP_EVENTS_IDX} ({c_ev} events), {TEMP_ALERTS_IDX} ({c_al} alerts).")


def setup_temp_kibana_objects():
    print("\n[*] Creating temporary Kibana saved objects pointing to temporary indices...")
    ndjson_file = Path(__file__).resolve().parent / "soc_triage_board.ndjson"
    temp_objects = []

    with open(ndjson_file, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            obj = json.loads(line_str)
            orig_id = obj["id"]
            obj_type = obj["type"]

            if obj_type == "index-pattern":
                if orig_id == "security-alerts-dataview":
                    obj["id"] = "temp-alerts-dataview"
                    obj["attributes"]["title"] = TEMP_ALERTS_IDX
                elif orig_id == "security-events-dataview":
                    obj["id"] = "temp-events-dataview"
                    obj["attributes"]["title"] = TEMP_EVENTS_IDX
            elif obj_type in ("lens", "search"):
                obj["id"] = "temp-" + orig_id
                for r in obj.get("references", []):
                    if r["id"] == "security-alerts-dataview":
                        r["id"] = "temp-alerts-dataview"
                    elif r["id"] == "security-events-dataview":
                        r["id"] = "temp-events-dataview"
            elif obj_type == "dashboard":
                obj["id"] = "temp-" + orig_id
                for r in obj.get("references", []):
                    if r["type"] in ("lens", "search"):
                        r["id"] = "temp-" + r["id"]

            temp_objects.append(obj)

    # Import temporary saved objects
    ndjson_payload = "\n".join(json.dumps(o) for o in temp_objects) + "\n"
    import_url = f"{KIBANA_URL}/api/saved_objects/_import?overwrite=true"
    headers = {"kbn-xsrf": "true"}
    resp = requests.post(
        import_url,
        headers=headers,
        files={"file": ("temp_objects.ndjson", ndjson_payload.encode("utf-8"), "application/ndjson")},
        timeout=30
    )
    if resp.status_code == 200:
        data = resp.json()
        print(f"[+] Temporary Kibana saved objects imported: {data.get('successCount')} objects (success={data.get('success')}).")
        return [o["id"] for o in temp_objects]
    else:
        print(f"[!] Temporary saved objects import failed: {resp.status_code} {resp.text}")
        return []


def run_puppeteer_verification():
    print("\n" + "=" * 75)
    print("  HEADLESS BROWSER RENDER VERIFICATION")
    print("=" * 75)

    js_code = rf"""
const puppeteer = require({json.dumps(PUPPETEER_PATH)});
const path = require('path');
const fs = require('fs');

const CHROME_PATH = {json.dumps(CHROME_PATH)};
const KIBANA_BASE = {json.dumps(KIBANA_URL)};
const APP_BASE = {json.dumps(APP_URL)};
const SCREENSHOTS_DIR = {json.dumps(str(SCREENSHOTS_DIR))};

async function verifyKibanaDashboard(browser, dashboardId, dashboardName, takeScreenshot = false, screenshotFile = "") {{
    const page = await browser.newPage();
    await page.setViewport({{ width: 1920, height: 1080, deviceScaleFactor: 1 }});

    const url = `${{KIBANA_BASE}}/app/dashboards#/view/${{dashboardId}}?_g=(time:(from:now-7d,to:now%2B1d))`;
    console.log(`\n--- Inspecting Kibana Dashboard: ${{dashboardName}} ---`);
    console.log(`URL: ${{url}}`);

    await page.goto(url, {{ waitUntil: 'networkidle2', timeout: 50000 }});
    // Allow Lens panels to finish internal rendering
    await new Promise(r => setTimeout(r, 7000));

    const result = await page.evaluate(() => {{
        const panels = [];
        const panelElements = document.querySelectorAll('[data-test-subj="embeddablePanel"]');
        panelElements.forEach((el, idx) => {{
            const titleEl = el.querySelector('[data-test-subj="embeddablePanelHeading-title"], .embPanel__title');
            const title = titleEl ? titleEl.innerText.trim() : `Panel ${{idx + 1}}`;

            const issues = [];
            const text = el.innerText || '';
            const lower = text.toLowerCase();

            // Detect warnings and errors
            if (lower.includes("wrong type") || lower.includes("wrong data type")) {{
                issues.push("Found 'wrong type' warning");
            }}
            if (lower.includes("cannot")) {{
                issues.push("Found 'Cannot' error text");
            }}
            if (lower.includes("no results found")) {{
                issues.push("Found 'No results found'");
            }}
            if (el.querySelector('.euiCallOut--danger, .kbnErrorPanel, [data-test-subj="error-warning"], [data-test-subj="embeddablePanelError"]')) {{
                issues.push("Found danger/error callout element");
            }}

            // Preview content
            let preview = "";
            const rows = el.querySelectorAll('tr, .euiDataGridRow');
            if (rows.length > 0) {{
                preview = `${{rows.length}} row(s)`;
            }} else {{
                const metricVal = el.querySelector('.lnsXYMetricView__primaryValue, .euiStat__title, .euiTitle');
                if (metricVal) {{
                    preview = `Value: ${{metricVal.innerText.trim()}}`;
                }} else {{
                    const canvas = el.querySelector('canvas, svg');
                    if (canvas) {{
                        preview = "Chart rendered (Canvas/SVG present)";
                    }} else {{
                        preview = text.slice(0, 80).replace(/\n/g, ' ');
                    }}
                }}
            }}

            panels.push({{ title, issues, preview }});
        }});
        return panels;
    }});

    console.log(`Panels Detected: ${{result.length}}`);
    let dashboardOk = true;
    for (const p of result) {{
        if (p.issues.length === 0) {{
            console.log(`  [OK]   ${{p.title.padEnd(45)}} | Preview: ${{p.preview}}`);
        }} else {{
            console.log(`  [FAIL] ${{p.title.padEnd(45)}} | ISSUES: ${{p.issues.join('; ')}}`);
            dashboardOk = false;
        }}
    }}

    if (takeScreenshot && screenshotFile) {{
        const dest = path.join(SCREENSHOTS_DIR, screenshotFile);
        await page.screenshot({{ path: dest, fullPage: true }});
        console.log(`[+] Headless screenshot saved: ${{dest}}`);
    }}

    await page.close();
    return dashboardOk;
}}

async function verifyAppDashboard(browser) {{
    const page = await browser.newPage();
    await page.setViewport({{ width: 1920, height: 1080, deviceScaleFactor: 1 }});

    const url = `${{APP_BASE}}/dashboard?events_index=test-render-events&alerts_index=test-render-alerts`;
    console.log(`\n--- Inspecting App Web Page: /dashboard (Analyst Board) ---`);
    console.log(`URL: ${{url}}`);

    await page.goto(url, {{ waitUntil: 'networkidle2', timeout: 30000 }});
    await new Promise(r => setTimeout(r, 2000));

    const result = await page.evaluate(() => {{
        const checks = [];

        // Check Count Cards
        const total = document.getElementById('card-val-total')?.innerText.trim();
        const critical = document.getElementById('card-val-critical')?.innerText.trim();
        const high = document.getElementById('card-val-high')?.innerText.trim();
        const medium = document.getElementById('card-val-medium')?.innerText.trim();
        checks.push({{
            name: "Count Cards (Total, Critical, High, Medium)",
            ok: (total !== "0" && total !== ""),
            preview: `Total: ${{total}}, Critical: ${{critical}}, High: ${{high}}, Medium: ${{medium}}`
        }});

        // Check Panel 1: Severity over time
        const p1 = document.getElementById('panel-severity-over-time');
        const p1Svg = p1?.querySelector('svg rect');
        checks.push({{
            name: "Panel: Severity over time (Stacked Bars)",
            ok: !!p1Svg,
            preview: p1Svg ? "Inline SVG with stacked rects rendered" : "Empty or failed"
        }});

        // Check Panel 2: Event categories
        const p2 = document.getElementById('panel-event-categories');
        const p2Pie = p2?.querySelector('svg path, svg circle');
        checks.push({{
            name: "Panel: Event categories (Pie)",
            ok: !!p2Pie,
            preview: p2Pie ? "Inline SVG pie slices and labels rendered" : "Empty or failed"
        }});

        // Check Panel 3: Top hosts
        const p3 = document.getElementById('panel-top-hosts');
        const p3Bars = p3?.querySelectorAll('svg rect');
        checks.push({{
            name: "Panel: Top hosts (Horizontal Bars)",
            ok: (p3Bars && p3Bars.length > 0),
            preview: p3Bars ? `${{p3Bars.length}} horizontal bar(s) rendered` : "Empty or failed"
        }});

        // Check Panel 4: Recent alerts
        const p4 = document.getElementById('panel-recent-alerts');
        const p4Rows = p4?.querySelectorAll('.alert-row');
        checks.push({{
            name: "Panel: Recent alerts (List/Table)",
            ok: (p4Rows && p4Rows.length > 0),
            preview: p4Rows ? `${{p4Rows.length}} recent alert row(s) rendered` : "Empty or failed"
        }});

        // Check Panel 5: Log sources
        const p5 = document.getElementById('panel-log-sources');
        const p5Radar = p5?.querySelector('svg polygon');
        checks.push({{
            name: "Panel: Log sources (Radar Chart)",
            ok: !!p5Radar,
            preview: p5Radar ? "Inline SVG radar polygon rendered" : "Empty or failed"
        }});

        return checks;
    }});

    let appOk = true;
    for (const c of result) {{
        if (c.ok) {{
            console.log(`  [OK]   ${{c.name.padEnd(45)}} | Preview: ${{c.preview}}`);
        }} else {{
            console.log(`  [FAIL] ${{c.name.padEnd(45)}} | ISSUES: Failed to render`);
            appOk = false;
        }}
    }}

    const shotPath = path.join(SCREENSHOTS_DIR, "analyst_dashboard.png");
    await page.screenshot({{ path: shotPath, fullPage: true }});
    console.log(`[+] Headless screenshot saved: ${{shotPath}}`);

    await page.close();
    return appOk;
}}

async function main() {{
    const browser = await puppeteer.launch({{
        executablePath: CHROME_PATH,
        headless: 'new',
        args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu',
            '--window-size=1920,1080'
        ]
    }});

    let allSuccess = true;

    // 1. Verify SOC Triage Board (temp copy)
    const socOk = await verifyKibanaDashboard(
        browser,
        "temp-soc-triage-board-dashboard",
        "SOC Triage Board",
        true,
        "soc_triage_board.png"
    );
    if (!socOk) allSuccess = false;

    // 2. Verify Alerts Dashboard (temp copy)
    const alertsOk = await verifyKibanaDashboard(
        browser,
        "temp-alerts-dashboard",
        "Alerts Dashboard",
        false
    );
    if (!alertsOk) allSuccess = false;

    // 3. Verify Timeline Analysis (temp copy)
    const timelineOk = await verifyKibanaDashboard(
        browser,
        "temp-timeline-analysis-dashboard",
        "Timeline Analysis",
        false
    );
    if (!timelineOk) allSuccess = false;

    // 4. Verify App Dashboard (/dashboard)
    const appOk = await verifyAppDashboard(browser);
    if (!appOk) allSuccess = false;

    await browser.close();
    process.exit(allSuccess ? 0 : 1);
}}

main().catch(err => {{
    console.error("Fatal Puppeteer error:", err);
    process.exit(1);
}});
"""

    temp_js_path = Path(__file__).resolve().parent / "temp_headless_check.js"
    temp_js_path.write_text(js_code, encoding="utf-8")

    try:
        proc = subprocess.run(
            [NODE_PATH, str(temp_js_path)],
            capture_output=True,
            text=True,
            timeout=180
        )
        print(proc.stdout)
        if proc.stderr:
            print(proc.stderr)
        return proc.returncode == 0
    finally:
        if temp_js_path.exists():
            temp_js_path.unlink()


def cleanup(es, temp_object_ids):
    print("\n" + "=" * 75)
    print("  CLEANUP TEMPORARY OBJECTS & INDICES")
    print("=" * 75)

    # 1. Delete temp Kibana saved objects
    headers = {"kbn-xsrf": "true"}
    for obj_id in temp_object_ids:
        for obj_type in ["dashboard", "lens", "index-pattern", "search"]:
            try:
                requests.delete(f"{KIBANA_URL}/api/saved_objects/{obj_type}/{obj_id}", headers=headers, timeout=5)
            except Exception:
                pass
    print(f"[+] Cleaned up temporary Kibana saved objects.")

    # 2. Delete temporary indices
    es.indices.delete(index=[TEMP_EVENTS_IDX, TEMP_ALERTS_IDX], ignore_unavailable=True)
    print(f"[+] Deleted temporary indices: {TEMP_EVENTS_IDX}, {TEMP_ALERTS_IDX}.")

    # 3. Verify live indices
    live_events_cnt = es.count(index=config.INDEX_EVENTS)["count"]
    live_alerts_cnt = es.count(index=config.INDEX_ALERTS)["count"]
    print(f"[+] Confirmed LIVE indices are UNTOUCHED: '{config.INDEX_EVENTS}' = {live_events_cnt}, '{config.INDEX_ALERTS}' = {live_alerts_cnt}.")
    print("=" * 75)


def main():
    es = get_es_client()

    initial_live_events = es.count(index=config.INDEX_EVENTS)["count"]
    initial_live_alerts = es.count(index=config.INDEX_ALERTS)["count"]
    print(f"[*] Starting live index state: '{config.INDEX_EVENTS}' = {initial_live_events}, '{config.INDEX_ALERTS}' = {initial_live_alerts}")

    temp_object_ids = []
    try:
        setup_temp_indices(es)
        temp_object_ids = setup_temp_kibana_objects()
        success = run_puppeteer_verification()
    finally:
        cleanup(es, temp_object_ids)

    final_live_events = es.count(index=config.INDEX_EVENTS)["count"]
    final_live_alerts = es.count(index=config.INDEX_ALERTS)["count"]
    assert initial_live_events == final_live_events, "Error: live events count altered!"
    assert initial_live_alerts == final_live_alerts, "Error: live alerts count altered!"

    print(f"\n[FINAL STATUS] Verification {'PASSED' if success else 'FAILED'}.")
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
