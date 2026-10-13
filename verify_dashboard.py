"""
Verification script for BCSSL Lab 07 - SOC Triage Board
1. Fetches each saved object via the Kibana Saved Objects API
2. Executes the exact data queries used by all 3 dashboard panels
"""

import json
import requests

KIBANA_URL = "http://127.0.0.1:5601"
HEADERS = {"kbn-xsrf": "true"}

SAVED_OBJECTS = [
    ("index-pattern", "e564ba96-307a-4b36-8644-9879c743b51a", "Data View (Security Alerts)"),
    ("lens", "alerts-by-severity", "Panel 1: Alerts by Severity Over Time (Lens)"),
    ("visualization", "top-source-ips", "Panel 2: Top Source IPs Table"),
    ("visualization", "suspicious-execution-hosts", "Panel 3: Hosts with Post-Logon Suspicious Execution"),
    ("dashboard", "soc-triage-board-dashboard", "Dashboard: SOC Triage Board")
]

def verify_saved_objects():
    print("=" * 80)
    print("1. FETCHING SAVED OBJECTS FROM KIBANA API")
    print("=" * 80)
    for obj_type, obj_id, label in SAVED_OBJECTS:
        url = f"{KIBANA_URL}/api/saved_objects/{obj_type}/{obj_id}"
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 200:
            data = resp.json()
            attrs = data.get("attributes", {})
            print(f"\n[OK] {label}")
            print(f"     Type: {data.get('type')}, ID: {data.get('id')}")
            print(f"     Title: {attrs.get('title') or attrs.get('name')}")
            if obj_type == "index-pattern":
                print(f"     timeFieldName: {attrs.get('timeFieldName')}")
                print(f"     Pattern: {attrs.get('title')}")
            elif obj_type == "lens":
                print(f"     visualizationType: {attrs.get('visualizationType')}")
                vis = attrs.get("state", {}).get("visualization", {})
                print(f"     Chart shape: {vis.get('shape')}, isStacked: {vis.get('isStacked')}")
                layers = attrs.get("state", {}).get("datasourceStates", {}).get("formBased", {}).get("layers", {}).get("layer_1", {})
                cols = layers.get("columns", {})
                for col_id, col_def in cols.items():
                    print(f"       Column '{col_id}': op={col_def.get('operationType')}, field={col_def.get('sourceField')}, label={col_def.get('label')}")
            elif obj_type == "visualization":
                vis_state = json.loads(attrs.get("visState", "{}"))
                print(f"     Vis Type: {vis_state.get('type')}")
                search_src = json.loads(attrs.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON", "{}"))
                print(f"     Query: {search_src.get('query')}")
            elif obj_type == "dashboard":
                print(f"     Time Range: {attrs.get('timeFrom')} to {attrs.get('timeTo')} (timeRestore: {attrs.get('timeRestore')})")
                panels = json.loads(attrs.get("panelsJSON", "[]"))
                print(f"     Panels configured: {len(panels)}")
                for ref in data.get("references", []):
                    print(f"       Ref: {ref.get('name')} -> {ref.get('type')}/{ref.get('id')}")
        else:
            print(f"\n[FAIL] {label} - HTTP {resp.status_code}: {resp.text}")

def verify_panel_data():
    print("\n" + "=" * 80)
    print("2. QUERYING DATA FOR ALL 3 DASHBOARD PANELS (time window: now-7d to now+1d)")
    print("=" * 80)

    bsearch_url = f"{KIBANA_URL}/internal/bsearch"
    bsearch_headers = {
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
        "elastic-api-version": "1"
    }

    # Panel 1: Alerts by Severity Over Time (Date histogram by first_seen, split by severity)
    p1_payload = {
        "batch": [{
            "request": {
                "params": {
                    "index": "security-alerts*",
                    "body": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "filter": [
                                    {"range": {"first_seen": {"gte": "now-7d", "lte": "now+1d", "format": "strict_date_optional_time"}}}
                                ]
                            }
                        },
                        "aggs": {
                            "date_histogram": {
                                "date_histogram": {
                                    "field": "first_seen",
                                    "fixed_interval": "1h",
                                    "min_doc_count": 1
                                },
                                "aggs": {
                                    "severity_breakdown": {
                                        "terms": {"field": "severity", "size": 5}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }]
    }

    r1 = requests.post(bsearch_url, headers=bsearch_headers, json=p1_payload).json()
    p1_buckets = r1["result"]["rawResponse"]["aggregations"]["date_histogram"]["buckets"]
    print(f"\nPanel 1: 'Alerts by Severity Over Time' (Lens stacked bar chart)")
    print(f"Total time buckets returned: {len(p1_buckets)}")
    for b in p1_buckets:
        print(f"  Bucket Timestamp: {b['key_as_string']} | Total Alerts: {b['doc_count']}")
        for sb in b["severity_breakdown"]["buckets"]:
            print(f"    - Severity [{sb['key']}]: {sb['doc_count']} alert(s)")

    # Panel 2: Top Source IPs Table
    p2_payload = {
        "batch": [{
            "request": {
                "params": {
                    "index": "security-alerts*",
                    "body": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "filter": [
                                    {"range": {"first_seen": {"gte": "now-7d", "lte": "now+1d", "format": "strict_date_optional_time"}}}
                                ]
                            }
                        },
                        "aggs": {
                            "top_ips": {
                                "terms": {"field": "src_ip", "size": 10}
                            }
                        }
                    }
                }
            }
        }]
    }

    r2 = requests.post(bsearch_url, headers=bsearch_headers, json=p2_payload).json()
    p2_buckets = r2["result"]["rawResponse"]["aggregations"]["top_ips"]["buckets"]
    print(f"\nPanel 2: 'Top Source IPs Table'")
    print(f"Total unique IPs returned: {len(p2_buckets)}")
    for b in p2_buckets:
        print(f"  - Source IP: {b['key']:<18} | Alert Count: {b['doc_count']}")

    # Panel 3: Hosts with Post-Logon Suspicious Execution
    p3_payload = {
        "batch": [{
            "request": {
                "params": {
                    "index": "security-alerts*",
                    "body": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "must": [
                                    {"term": {"rule_name": "Post-Logon Suspicious Execution"}}
                                ],
                                "filter": [
                                    {"range": {"first_seen": {"gte": "now-7d", "lte": "now+1d", "format": "strict_date_optional_time"}}}
                                ]
                            }
                        },
                        "aggs": {
                            "by_host": {
                                "terms": {"field": "host", "size": 10},
                                "aggs": {
                                    "by_user": {"terms": {"field": "user", "size": 10}}
                                }
                            }
                        }
                    }
                }
            }
        }]
    }

    r3 = requests.post(bsearch_url, headers=bsearch_headers, json=p3_payload).json()
    p3_buckets = r3["result"]["rawResponse"]["aggregations"]["by_host"]["buckets"]
    print(f"\nPanel 3: 'Hosts with Post-Logon Suspicious Execution'")
    print(f"Total impacted hosts returned: {len(p3_buckets)}")
    for b in p3_buckets:
        users = [f"{u['key']} ({u['doc_count']})" for u in b["by_user"]["buckets"]]
        print(f"  - Host: {b['key']:<15} | Users: {', '.join(users)} | Total Alerts: {b['doc_count']}")

    assert len(p1_buckets) > 0, "Panel 1 returned no data!"
    assert len(p2_buckets) > 0, "Panel 2 returned no data!"
    assert len(p3_buckets) > 0, "Panel 3 returned no data!"
    print("\n" + "=" * 80)
    print("VERIFICATION COMPLETE: ALL 3 PANELS RETURN REAL DATA!")
    print("=" * 80)

if __name__ == "__main__":
    verify_saved_objects()
    verify_panel_data()
