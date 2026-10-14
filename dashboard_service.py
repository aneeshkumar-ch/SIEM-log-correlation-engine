"""
Dashboard service module for SIEM Log Correlation Engine.
Provides read-only aggregation queries against Elasticsearch (or MockElasticsearch)
to power the Analyst Board dashboard (/dashboard and /api/dashboard-data).
"""

from typing import Dict, Any, List
import logging
from datetime import datetime, timezone
from storage import MockElasticsearch
import config

logger = logging.getLogger(__name__)

# ===========================================================================
# CONSTANTS: DEFINED ONCE AS REQUIRED
# ===========================================================================
# Count cards
COUNT_CARD_TOTAL_BG = "#F1EFE8"
COUNT_CARD_TOTAL_TEXT = "#2C2C2A"
COUNT_CARD_CRITICAL_BG = "#8E0000"
COUNT_CARD_CRITICAL_TEXT = "#FFFFFF"
COUNT_CARD_HIGH_BG = "#E7664C"
COUNT_CARD_HIGH_TEXT = "#4A1B0C"
COUNT_CARD_MEDIUM_BG = "#FEC514"
COUNT_CARD_MEDIUM_TEXT = "#412402"

# Severity series everywhere
SEVERITY_CRITICAL = "#8E0000"
SEVERITY_HIGH = "#E7664C"
SEVERITY_MEDIUM = "#FEC514"
SEVERITY_LOW = "#54B399"

# Chart palette (reds with lavender accents)
CHART_PALETTE = [
    "#E8483B",
    "#C21807",
    "#F28B82",
    "#F6B5AE",
    "#FBDAD6",
    "#6C73D6",
    "#C9CCF2"
]

# Panel label tags
TAG_COLOR = "#2B2F7E"  # navy, white text


def get_dashboard_analytics(
    es: Any,
    events_index: str = config.INDEX_EVENTS,
    alerts_index: str = config.INDEX_ALERTS
) -> Dict[str, Any]:
    """
    Queries Elasticsearch for real aggregations across events and alerts.
    Supports both real Elasticsearch 8.13 and MockElasticsearch.
    Returns structured data for the Analyst Board.
    """
    is_mock = isinstance(es, MockElasticsearch)

    # Base response structure
    result: Dict[str, Any] = {
        "colors": {
            "count_cards": {
                "total": {"bg": COUNT_CARD_TOTAL_BG, "text": COUNT_CARD_TOTAL_TEXT},
                "critical": {"bg": COUNT_CARD_CRITICAL_BG, "text": COUNT_CARD_CRITICAL_TEXT},
                "high": {"bg": COUNT_CARD_HIGH_BG, "text": COUNT_CARD_HIGH_TEXT},
                "medium": {"bg": COUNT_CARD_MEDIUM_BG, "text": COUNT_CARD_MEDIUM_TEXT}
            },
            "severity": {
                "critical": SEVERITY_CRITICAL,
                "high": SEVERITY_HIGH,
                "medium": SEVERITY_MEDIUM,
                "low": SEVERITY_LOW
            },
            "palette": CHART_PALETTE,
            "tag": TAG_COLOR
        },
        "counts": {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "severity_over_time": [],
        "event_categories": [],
        "top_hosts": [],
        "recent_alerts": [],
        "log_sources": [],
        "total_events": 0,
        "has_data": False
    }

    try:
        # Check index existence
        has_events = es.indices.exists(index=events_index)
        has_alerts = es.indices.exists(index=alerts_index)
    except Exception as e:
        logger.warning("Error checking index existence: %s", e)
        return result

    # -----------------------------------------------------------------------
    # 1. PROCESS ALERTS (Counts, Severity Over Time, Recent Alerts Table)
    # -----------------------------------------------------------------------
    if has_alerts:
        try:
            if is_mock:
                # Mock Elasticsearch evaluation
                docs = list(es.indices_data.get(alerts_index, {}).values())
                # Counts
                sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                time_buckets: Dict[str, Dict[str, int]] = {}
                sorted_docs = sorted(docs, key=lambda x: str(x.get("first_seen", "")), reverse=True)

                for doc in docs:
                    sev = str(doc.get("severity", "")).lower()
                    if sev in sev_counts:
                        sev_counts[sev] += 1

                    # Date bucket (hourly / minute string)
                    raw_ts = str(doc.get("first_seen", doc.get("created_at", "")))
                    bucket_key = raw_ts[:13].replace("T", " ") + ":00" if len(raw_ts) >= 13 else "Recent"
                    if bucket_key not in time_buckets:
                        time_buckets[bucket_key] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
                    if sev in time_buckets[bucket_key]:
                        time_buckets[bucket_key][sev] += 1
                    time_buckets[bucket_key]["total"] += 1

                result["counts"]["total"] = len(docs)
                result["counts"]["critical"] = sev_counts["critical"]
                result["counts"]["high"] = sev_counts["high"]
                result["counts"]["medium"] = sev_counts["medium"]
                result["counts"]["low"] = sev_counts["low"]

                # Sorted buckets
                sorted_buckets = sorted(time_buckets.items(), key=lambda x: x[0])
                result["severity_over_time"] = [
                    {"time": k, **v} for k, v in sorted_buckets
                ]

                # Top 8 newest alerts
                recent_alerts = []
                for d in sorted_docs[:8]:
                    h = d.get("host")
                    host_str = ", ".join(h) if isinstance(h, list) else str(h or "N/A")
                    recent_alerts.append({
                        "severity": str(d.get("severity", "medium")).lower(),
                        "rule_name": str(d.get("rule_name", "Unknown Alert")),
                        "user": str(d.get("user") or "N/A"),
                        "host": host_str,
                        "src_ip": str(d.get("src_ip") or d.get("source_ip") or "N/A"),
                        "mitre_technique": str(d.get("mitre_technique") or "N/A"),
                        "first_seen": str(d.get("first_seen", "")).replace("T", " ")[:19]
                    })
                result["recent_alerts"] = recent_alerts

            else:
                # Real Elasticsearch aggregations & search
                aggs_query = {
                    "severity_counts": {
                        "terms": {"field": "severity", "size": 10}
                    },
                    "severity_over_time": {
                        "date_histogram": {
                            "field": "first_seen",
                            "fixed_interval": "1h",
                            "min_doc_count": 1
                        },
                        "aggs": {
                            "by_severity": {"terms": {"field": "severity", "size": 5}}
                        }
                    }
                }

                alert_res = es.search(
                    index=alerts_index,
                    size=8,
                    sort=[{"first_seen": {"order": "desc"}}],
                    aggs=aggs_query
                )

                # Total count
                total_alerts = alert_res.get("hits", {}).get("total", {}).get("value", 0)
                result["counts"]["total"] = total_alerts

                # Severity breakdown
                sev_aggs = alert_res.get("aggregations", {}).get("severity_counts", {}).get("buckets", [])
                for b in sev_aggs:
                    sev = str(b.get("key", "")).lower()
                    if sev in result["counts"]:
                        result["counts"][sev] = b.get("doc_count", 0)

                # Severity over time buckets
                hist_aggs = alert_res.get("aggregations", {}).get("severity_over_time", {}).get("buckets", [])
                s_over_time = []
                for b in hist_aggs:
                    raw_time = b.get("key_as_string", str(b.get("key", "")))
                    formatted_time = raw_time.replace("T", " ")[:16]
                    bucket_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                    for sub in b.get("by_severity", {}).get("buckets", []):
                        sub_sev = str(sub.get("key", "")).lower()
                        if sub_sev in bucket_counts:
                            bucket_counts[sub_sev] = sub.get("doc_count", 0)
                    s_over_time.append({
                        "time": formatted_time,
                        "critical": bucket_counts["critical"],
                        "high": bucket_counts["high"],
                        "medium": bucket_counts["medium"],
                        "low": bucket_counts["low"],
                        "total": b.get("doc_count", 0)
                    })
                result["severity_over_time"] = s_over_time

                # Recent alerts list (up to 8)
                recent_alerts = []
                for hit in alert_res.get("hits", {}).get("hits", []):
                    src = hit.get("_source", {})
                    h = src.get("host")
                    host_str = ", ".join(h) if isinstance(h, list) else str(h or "N/A")
                    recent_alerts.append({
                        "severity": str(src.get("severity", "medium")).lower(),
                        "rule_name": str(src.get("rule_name", "Unknown Alert")),
                        "user": str(src.get("user") or "N/A"),
                        "host": host_str,
                        "src_ip": str(src.get("src_ip") or src.get("source_ip") or "N/A"),
                        "mitre_technique": str(src.get("mitre_technique") or "N/A"),
                        "first_seen": str(src.get("first_seen", "")).replace("T", " ")[:19]
                    })
                result["recent_alerts"] = recent_alerts

        except Exception as e:
            logger.warning("Error querying alerts aggregations: %s", e)

    # -----------------------------------------------------------------------
    # 2. PROCESS EVENTS (Event Categories, Top Hosts, Log Sources)
    # -----------------------------------------------------------------------
    if has_events:
        try:
            if is_mock:
                ev_docs = list(es.indices_data.get(events_index, {}).values())
                result["total_events"] = len(ev_docs)

                cat_counter: Dict[str, int] = {}
                host_counter: Dict[str, int] = {}
                src_counter: Dict[str, int] = {}

                for edoc in ev_docs:
                    cat = edoc.get("event_type")
                    if cat:
                        cat_counter[cat] = cat_counter.get(cat, 0) + 1

                    h = edoc.get("host")
                    if isinstance(h, list):
                        for host_item in h:
                            if host_item:
                                host_counter[host_item] = host_counter.get(host_item, 0) + 1
                    elif h:
                        host_counter[h] = host_counter.get(h, 0) + 1

                    s = edoc.get("source") or edoc.get("source_type")
                    if s:
                        src_counter[s] = src_counter.get(s, 0) + 1

                total_cats = sum(cat_counter.values())
                result["event_categories"] = [
                    {
                        "category": k,
                        "count": v,
                        "percent": round((v / total_cats * 100), 1) if total_cats > 0 else 0
                    }
                    for k, v in sorted(cat_counter.items(), key=lambda x: x[1], reverse=True)[:7]
                ]

                result["top_hosts"] = [
                    {"host": k, "count": v}
                    for k, v in sorted(host_counter.items(), key=lambda x: x[1], reverse=True)[:10]
                ]

                result["log_sources"] = [
                    {"source": k, "count": v}
                    for k, v in sorted(src_counter.items(), key=lambda x: x[1], reverse=True)[:6]
                ]

            else:
                events_aggs_query = {
                    "categories": {"terms": {"field": "event_type", "size": 7}},
                    "top_hosts": {"terms": {"field": "host", "size": 10}},
                    "sources": {"terms": {"field": "source", "size": 6}}
                }

                events_res = es.search(
                    index=events_index,
                    size=0,
                    aggs=events_aggs_query
                )

                total_ev = events_res.get("hits", {}).get("total", {}).get("value", 0)
                result["total_events"] = total_ev

                cat_buckets = events_res.get("aggregations", {}).get("categories", {}).get("buckets", [])
                sum_cat = sum(b.get("doc_count", 0) for b in cat_buckets)
                result["event_categories"] = [
                    {
                        "category": b.get("key"),
                        "count": b.get("doc_count", 0),
                        "percent": round((b.get("doc_count", 0) / sum_cat * 100), 1) if sum_cat > 0 else 0
                    }
                    for b in cat_buckets
                ]

                host_buckets = events_res.get("aggregations", {}).get("top_hosts", {}).get("buckets", [])
                result["top_hosts"] = [
                    {"host": b.get("key"), "count": b.get("doc_count", 0)}
                    for b in host_buckets
                ]

                src_buckets = events_res.get("aggregations", {}).get("sources", {}).get("buckets", [])
                result["log_sources"] = [
                    {"source": b.get("key"), "count": b.get("doc_count", 0)}
                    for b in src_buckets
                ]

        except Exception as e:
            logger.warning("Error querying events aggregations: %s", e)

    # Determine overall data presence
    result["has_data"] = (result["counts"]["total"] > 0 or result["total_events"] > 0)
    return result
