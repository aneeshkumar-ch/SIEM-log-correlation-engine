import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dateutil import parser as date_parser

import config
from storage import get_es_client, initialize_indices

logger = logging.getLogger(__name__)


def parse_iso_utc(ts_str: str) -> datetime:
    """Parses an ISO8601 string to a timezone-aware UTC datetime object."""
    dt = date_parser.parse(ts_str)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def compute_alert_id(rule_name: str, src_ip: Optional[str], host: Optional[str], first_seen: str, last_seen: str) -> str:
    """Computes a deterministic hash ID for deduplicating identical alerts."""
    key = f"{rule_name}:{src_ip or ''}:{host or ''}:{first_seen}:{last_seen}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def is_admin_user(username: Optional[str]) -> bool:
    """Checks if the user matches known administrative account names."""
    if not username:
        return False
    u = username.strip().lower()
    for admin in config.ADMIN_ACCOUNTS:
        if u == admin.lower() or u.endswith(f"\\{admin.lower()}"):
            return True
    return False


def is_suspicious_process(process_name: Optional[str]) -> bool:
    """Checks if the process is in the suspicious execution list."""
    if not process_name:
        return False
    p = process_name.strip().lower().replace("/", "\\").split("\\")[-1]
    return p in [sp.lower() for sp in config.SUSPICIOUS_PROCESSES]


def run_correlation(es: Any = None) -> List[Dict[str, Any]]:
    """Runs all correlation rules over events in 'normalized-events' index.
    Writes scored, deduplicated alerts into 'security-alerts' index.
    Returns list of generated alert documents.
    """
    if es is None:
        es = get_es_client()

    initialize_indices(es)

    # Fetch all normalized events
    res = es.search(
        index=config.INDEX_EVENTS,
        query={"match_all": {}},
        sort=[{"timestamp": {"order": "asc"}}],
        size=10000
    )
    raw_hits = res.get("hits", {}).get("hits", [])
    if not raw_hits:
        logger.info("No events found in %s to correlate", config.INDEX_EVENTS)
        return []

    events = []
    for hit in raw_hits:
        doc = hit.get("_source", {})
        doc_id = hit.get("_id")
        try:
            dt = parse_iso_utc(doc["timestamp"])
            events.append({
                "_id": doc_id,
                "dt": dt,
                **doc
            })
        except Exception as e:
            logger.warning("Failed to parse timestamp in event %s: %s", doc_id, e)

    # Sort strictly chronologically by parsed UTC datetime
    events.sort(key=lambda x: x["dt"])

    alerts = []

    # -------------------------------------------------------------
    # RULE 1 & 2: Brute Force Suspected (High) vs Successful Brute Force (Critical)
    # -------------------------------------------------------------
    # Group logon events by src_ip
    ip_events_map: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        ip = ev.get("src_ip")
        if not ip or ip in config.ALLOWLIST_IPS:
            continue
        if ev.get("event_type") in ("logon_failure", "logon_success"):
            ip_events_map.setdefault(ip, []).append(ev)

    for src_ip, ip_evs in ip_events_map.items():
        # Sliding window over failure bursts
        i = 0
        n = len(ip_evs)
        while i < n:
            if ip_evs[i]["event_type"] != "logon_failure":
                i += 1
                continue

            window_start_ev = ip_evs[i]
            window_start_time = window_start_ev["dt"]
            window_max_time = window_start_time.timestamp() + (config.BRUTE_FORCE_WINDOW_MINUTES * 60)

            # Collect failures within sliding window
            failures_in_window = []
            j = i
            while j < n and ip_evs[j]["dt"].timestamp() <= window_max_time:
                if ip_evs[j]["event_type"] == "logon_failure":
                    failures_in_window.append(ip_evs[j])
                j += 1

            if len(failures_in_window) >= config.BRUTE_FORCE_FAIL_THRESHOLD:
                # Check for successful logon afterward
                last_fail = failures_in_window[-1]
                subsequent_success = None

                # Look for success after last fail (within 5 mins)
                for cand in ip_evs:
                    if cand["event_type"] == "logon_success" and cand["dt"] >= last_fail["dt"]:
                        time_diff = (cand["dt"] - last_fail["dt"]).total_seconds()
                        if time_diff <= (config.BRUTE_FORCE_WINDOW_MINUTES * 60):
                            subsequent_success = cand
                            break

                target_host = last_fail.get("host", "unknown")
                target_user = subsequent_success.get("user") if subsequent_success else last_fail.get("user")
                evidence_ids = [f["_id"] for f in failures_in_window]

                first_seen_str = window_start_ev["timestamp"]

                if subsequent_success:
                    # RULE 2: Successful Brute Force (Critical)
                    evidence_ids.append(subsequent_success["_id"])
                    last_seen_str = subsequent_success["timestamp"]
                    alert_doc = {
                        "rule_name": "Successful Brute Force",
                        "severity": "critical",
                        "src_ip": src_ip,
                        "user": target_user,
                        "host": target_host,
                        "evidence": evidence_ids,
                        "first_seen": first_seen_str,
                        "last_seen": last_seen_str,
                        "mitre_technique": "T1110.001",
                        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                else:
                    # RULE 1: Brute Force Suspected (High)
                    last_seen_str = last_fail["timestamp"]
                    alert_doc = {
                        "rule_name": "Brute Force Suspected",
                        "severity": "high",
                        "src_ip": src_ip,
                        "user": target_user,
                        "host": target_host,
                        "evidence": evidence_ids,
                        "first_seen": first_seen_str,
                        "last_seen": last_seen_str,
                        "mitre_technique": "T1110",
                        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    }

                alerts.append(alert_doc)
                # Advance pointer to end of this evaluated burst
                i = j
            else:
                i += 1

    # -------------------------------------------------------------
    # RULE 3: Post-Logon Suspicious Execution
    # -------------------------------------------------------------
    # A process_create of powershell.exe or cmd.exe on the same host within 2 minutes after a logon_success by a non-admin user.
    # Group events by host
    host_events_map: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        h = ev.get("host")
        if h:
            host_events_map.setdefault(h, []).append(ev)

    for host_name, h_evs in host_events_map.items():
        m = len(h_evs)
        for idx, ev in enumerate(h_evs):
            if ev.get("event_type") == "logon_success":
                user = ev.get("user")
                # Non-admin user check
                if is_admin_user(user):
                    continue

                logon_dt = ev["dt"]
                logon_id = ev["_id"]
                logon_max_time = logon_dt.timestamp() + (config.POST_LOGON_WINDOW_MINUTES * 60)

                # Look forward for suspicious process_create on same host
                for post_idx in range(idx + 1, m):
                    post_ev = h_evs[post_idx]
                    post_dt = post_ev["dt"]

                    if post_dt.timestamp() > logon_max_time:
                        break

                    if post_ev.get("event_type") == "process_create":
                        proc = post_ev.get("process_name")
                        if is_suspicious_process(proc):
                            alert_doc = {
                                "rule_name": "Post-Logon Suspicious Execution",
                                "severity": "high",
                                "src_ip": ev.get("src_ip"),
                                "user": user,
                                "host": host_name,
                                "evidence": [logon_id, post_ev["_id"]],
                                "first_seen": ev["timestamp"],
                                "last_seen": post_ev["timestamp"],
                                "mitre_technique": "T1059.001",
                                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                            }
                            alerts.append(alert_doc)

    # -------------------------------------------------------------
    # Deduplicate and index alerts into security-alerts
    # -------------------------------------------------------------
    indexed_alerts = []
    seen_ids = set()

    for alert in alerts:
        a_id = compute_alert_id(
            alert["rule_name"],
            alert.get("src_ip"),
            alert.get("host"),
            alert["first_seen"],
            alert["last_seen"]
        )
        if a_id in seen_ids:
            continue
        seen_ids.add(a_id)

        # Index with deterministic ID
        es.index(
            index=config.INDEX_ALERTS,
            id=a_id,
            document=alert,
            refresh=True
        )
        alert["_id"] = a_id
        indexed_alerts.append(alert)

    try:
        es.indices.refresh(index=config.INDEX_ALERTS)
    except Exception:
        pass

    logger.info("Correlation cycle completed: %d alert(s) stored in %s", len(indexed_alerts), config.INDEX_ALERTS)
    return indexed_alerts
