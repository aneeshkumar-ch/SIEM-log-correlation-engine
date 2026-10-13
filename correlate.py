import logging
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dateutil import parser as date_parser

import config
from storage import get_es_client, initialize_indices, sanitize_doc_ips

logger = logging.getLogger(__name__)


def parse_iso_utc(ts_str: str) -> datetime:
    """Parses an ISO8601 string to a timezone-aware UTC datetime object."""
    dt = date_parser.parse(ts_str)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def compute_alert_id(rule_name: str, src_ip: Optional[str], host: Any, first_seen: str, last_seen: str) -> str:
    """Computes a deterministic hash ID for deduplicating identical alerts."""
    if isinstance(host, list):
        host_str = ",".join(sorted(str(h) for h in host))
    else:
        host_str = str(host) if host is not None else ""
    key = f"{rule_name}:{src_ip or ''}:{host_str}:{first_seen}:{last_seen}"
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


def run_correlation(es: Any = None, events_index: str = config.INDEX_EVENTS, alerts_index: str = config.INDEX_ALERTS) -> List[Dict[str, Any]]:
    """Runs all 5 correlation rules over events in events_index.
    Writes scored, deduplicated alerts into alerts_index.
    Returns list of generated alert documents.
    """
    if es is None:
        es = get_es_client()

    initialize_indices(es, events_index=events_index, alerts_index=alerts_index)

    # Fetch all normalized events from events_index
    res = es.search(
        index=events_index,
        query={"match_all": {}},
        sort=[{"timestamp": {"order": "asc"}}],
        size=10000
    )
    raw_hits = res.get("hits", {}).get("hits", [])
    if not raw_hits:
        logger.info("No events found in %s to correlate", events_index)
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

    alerts: List[Dict[str, Any]] = []

    # =========================================================================
    # SCENARIO 1: Brute Force Authentication (High) & Successful Brute Force (Critical)
    # =========================================================================
    # Group logon events by src_ip
    ip_events_map: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        ip = ev.get("source_ip") or ev.get("src_ip")
        if not ip or ip in config.ALLOWLIST_IPS:
            continue
        if ev.get("event_type") in ("logon_failure", "logon_success"):
            ip_events_map.setdefault(ip, []).append(ev)

    for src_ip, ip_evs in ip_events_map.items():
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
                last_fail = failures_in_window[-1]
                subsequent_success = None

                # Look for success after last fail (within BRUTE_FORCE_WINDOW_MINUTES)
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
                    evidence_ids.append(subsequent_success["_id"])
                    last_seen_str = subsequent_success["timestamp"]
                    alert_doc = {
                        "rule_name": "Successful Brute Force",
                        "severity": "critical",
                        "source_ip": src_ip,
                        "src_ip": src_ip,
                        "user": target_user,
                        "host": target_host,
                        "evidence": evidence_ids,
                        "first_seen": first_seen_str,
                        "last_seen": last_seen_str,
                        "mitre_technique": "T1110.001",
                        "description": f"Multiple failed logons followed by successful authentication from {src_ip}",
                        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                else:
                    last_seen_str = last_fail["timestamp"]
                    alert_doc = {
                        "rule_name": "Brute Force Suspected",
                        "severity": "high",
                        "source_ip": src_ip,
                        "src_ip": src_ip,
                        "user": target_user,
                        "host": target_host,
                        "evidence": evidence_ids,
                        "first_seen": first_seen_str,
                        "last_seen": last_seen_str,
                        "mitre_technique": "T1110",
                        "description": f"{len(failures_in_window)} failed logon attempts detected within {config.BRUTE_FORCE_WINDOW_MINUTES} minutes from {src_ip}",
                        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                    }

                alerts.append(alert_doc)
                i = j
            else:
                i += 1

    # =========================================================================
    # SCENARIO 2: Suspicious Process Execution
    # =========================================================================
    host_events_map: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        h = ev.get("host")
        if h:
            host_events_map.setdefault(h, []).append(ev)

    flagged_process_ids = set()

    # Pattern 2A: Post-Logon Suspicious Execution
    for host_name, h_evs in host_events_map.items():
        m = len(h_evs)
        for idx, ev in enumerate(h_evs):
            if ev.get("event_type") == "logon_success":
                user = ev.get("user")
                if is_admin_user(user):
                    continue

                logon_dt = ev["dt"]
                logon_id = ev["_id"]
                logon_max_time = logon_dt.timestamp() + (config.POST_LOGON_WINDOW_MINUTES * 60)

                for post_idx in range(idx + 1, m):
                    post_ev = h_evs[post_idx]
                    post_dt = post_ev["dt"]

                    if post_dt.timestamp() > logon_max_time:
                        break

                    if post_ev.get("event_type") == "process_create":
                        proc = post_ev.get("process_name")
                        if is_suspicious_process(proc):
                            flagged_process_ids.add(post_ev["_id"])
                            alert_doc = {
                                "rule_name": "Post-Logon Suspicious Execution",
                                "severity": "high",
                                "source_ip": ev.get("source_ip") or ev.get("src_ip"),
                                "src_ip": ev.get("source_ip") or ev.get("src_ip"),
                                "user": user,
                                "host": host_name,
                                "evidence": [logon_id, post_ev["_id"]],
                                "first_seen": ev["timestamp"],
                                "last_seen": post_ev["timestamp"],
                                "mitre_technique": "T1059.001",
                                "description": f"Suspicious process {proc} executed within {config.POST_LOGON_WINDOW_MINUTES}m after logon by user {user}",
                                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                            }
                            alerts.append(alert_doc)

    # Pattern 2B: Unusual Process Execution (e.g. cmd/powershell from unexpected parent, or high-risk LoLBas by non-admin)
    UNEXPECTED_PARENTS = [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "w3wp.exe", "httpd.exe", "nginx.exe", "tomcat.exe", "wmiprvse.exe"
    ]
    HIGH_RISK_LOB_BINS = [
        "certutil.exe", "vssadmin.exe", "whoami.exe", "bitsadmin.exe"
    ]

    for ev in events:
        if ev.get("event_type") == "process_create" and ev["_id"] not in flagged_process_ids:
            proc = str(ev.get("process_name", "")).lower()
            parent = str(ev.get("parent_process", "")).lower()
            user = ev.get("user")

            is_unusual = False
            reason = ""
            if any(p in proc for p in HIGH_RISK_LOB_BINS) and not is_admin_user(user):
                is_unusual = True
                reason = f"High-risk utility {proc} executed by non-admin user {user}"
            elif any(p in parent for p in UNEXPECTED_PARENTS) and (proc in ("cmd.exe", "powershell.exe", "pwsh.exe")):
                is_unusual = True
                reason = f"Shell {proc} spawned from unexpected parent process {parent}"

            if is_unusual:
                alert_doc = {
                    "rule_name": "Unusual Process Execution",
                    "severity": "medium",
                    "source_ip": ev.get("source_ip") or ev.get("src_ip"),
                    "src_ip": ev.get("source_ip") or ev.get("src_ip"),
                    "user": user,
                    "host": ev.get("host", "unknown"),
                    "evidence": [ev["_id"]],
                    "first_seen": ev["timestamp"],
                    "last_seen": ev["timestamp"],
                    "mitre_technique": "T1059",
                    "description": reason,
                    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                }
                alerts.append(alert_doc)

    # =========================================================================
    # SCENARIO 3: Privilege-Related Activity
    # =========================================================================
    for ev in events:
        is_priv_event = False
        reason = ""

        # Windows Event 4672 or explicit privilege_escalation
        if ev.get("event_type") == "privilege_escalation":
            is_priv_event = True
            reason = "Privilege escalation or special privileges assigned"
        elif ev.get("privilege") or str(ev.get("raw_log", "")).find("4672") != -1:
            is_priv_event = True
            reason = "Special privileges assigned (Event 4672)"

        # Linux sudo / su execution by non-admin user
        proc = str(ev.get("process_name", "")).lower()
        raw = str(ev.get("raw_log", "")).lower()
        user = ev.get("user")

        if any(cmd in proc for cmd in config.PRIVILEGE_COMMANDS) or "sudo:" in raw:
            if not is_admin_user(user):
                is_priv_event = True
                reason = f"Elevation command executed via sudo/su by non-admin user {user}"

        if is_priv_event:
            alert_doc = {
                "rule_name": "Privilege-Related Activity",
                "severity": "high",
                "source_ip": ev.get("source_ip") or ev.get("src_ip"),
                "src_ip": ev.get("source_ip") or ev.get("src_ip"),
                "user": user,
                "host": ev.get("host", "unknown"),
                "evidence": [ev["_id"]],
                "first_seen": ev["timestamp"],
                "last_seen": ev["timestamp"],
                "mitre_technique": "T1548",
                "description": reason,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            alerts.append(alert_doc)

    # =========================================================================
    # SCENARIO 4: Network-Based Suspicious Activity (Port Scan & Block Bursts)
    # =========================================================================
    net_events_by_src: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        if ev.get("source") == "Network" or ev.get("source_type") in ("network_firewall", "firewall"):
            s_ip = ev.get("source_ip") or ev.get("src_ip")
            if s_ip and s_ip not in config.ALLOWLIST_IPS:
                net_events_by_src.setdefault(s_ip, []).append(ev)

    for s_ip, net_evs in net_events_by_src.items():
        k = len(net_evs)
        i = 0
        while i < k:
            w_start = net_evs[i]["dt"]
            w_max = w_start.timestamp() + (config.NETWORK_SCAN_WINDOW_MINUTES * 60)

            window_net = []
            j = i
            while j < k and net_evs[j]["dt"].timestamp() <= w_max:
                window_net.append(net_evs[j])
                j += 1

            # 4A: Check port scan: many distinct destination ports from one source to one destination host
            ports_per_dest: Dict[str, set] = {}
            for w in window_net:
                dest = w.get("destination_ip") or w.get("dest_ip") or w.get("host") or "target"
                dport = w.get("destination_port")
                if dport is not None:
                    ports_per_dest.setdefault(str(dest), set()).add(dport)

            target_port_scan = None
            for dest, ports in ports_per_dest.items():
                if len(ports) >= config.NETWORK_SCAN_PORT_THRESHOLD:
                    target_port_scan = (dest, len(ports))
                    break

            if target_port_scan:
                target_dest, count_ports = target_port_scan
                alert_doc = {
                    "rule_name": "Network Port Scan Detected",
                    "severity": "high",
                    "source_ip": s_ip,
                    "src_ip": s_ip,
                    "user": None,
                    "host": net_evs[i].get("host", "firewall"),
                    "evidence": [w["_id"] for w in window_net],
                    "first_seen": net_evs[i]["timestamp"],
                    "last_seen": window_net[-1]["timestamp"],
                    "mitre_technique": "T1046",
                    "description": f"Source IP {s_ip} scanned {count_ports} distinct ports on destination {target_dest}",
                    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                }
                alerts.append(alert_doc)
                i = j
                continue

            # 4B: Bursts of blocked connections >= threshold (Network/Firewall events only)
            blocked_in_window = [
                w for w in window_net
                if (w.get("source") == "Network" or w.get("source_type") in ("network_firewall", "firewall"))
                and (str(w.get("action", "")).upper() == "BLOCK" or str(w.get("severity", "")).lower() == "medium")
            ]
            if len(blocked_in_window) >= config.BLOCKED_BURST_THRESHOLD:
                alert_doc = {
                    "rule_name": "Burst of Blocked Connections",
                    "severity": "medium",
                    "source_ip": s_ip,
                    "src_ip": s_ip,
                    "user": None,
                    "host": net_evs[i].get("host", "firewall"),
                    "evidence": [b["_id"] for b in blocked_in_window],
                    "first_seen": blocked_in_window[0]["timestamp"],
                    "last_seen": blocked_in_window[-1]["timestamp"],
                    "mitre_technique": "T1046",
                    "description": f"Burst of {len(blocked_in_window)} blocked connections detected from {s_ip}",
                    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                }
                alerts.append(alert_doc)
                i = j
                continue

            i += 1

    # =========================================================================
    # SCENARIO 5: Additional Security Event (Sensitive File Access & Lateral Movement)
    # =========================================================================
    # 5A: Sensitive File Access
    for ev in events:
        file_path = ev.get("file_path") or ""
        raw_str = str(ev.get("raw_log", "")).lower()

        is_sensitive = False
        target_file = ""
        for sf in config.SENSITIVE_FILES:
            if sf.lower() in file_path.lower() or sf.lower() in raw_str:
                is_sensitive = True
                target_file = sf
                break

        if is_sensitive:
            alert_doc = {
                "rule_name": "Sensitive File Access",
                "severity": "high",
                "source_ip": ev.get("source_ip") or ev.get("src_ip"),
                "src_ip": ev.get("source_ip") or ev.get("src_ip"),
                "user": ev.get("user"),
                "host": ev.get("host", "unknown"),
                "evidence": [ev["_id"]],
                "first_seen": ev["timestamp"],
                "last_seen": ev["timestamp"],
                "mitre_technique": "T1003.008",
                "description": f"Access or modification to sensitive system credential file {target_file}",
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            }
            alerts.append(alert_doc)

    # 5B: Lateral Movement (same user logging on to >= threshold distinct hosts within window)
    user_logons: Dict[str, List[Dict[str, Any]]] = {}
    for ev in events:
        if ev.get("event_type") == "logon_success":
            u = ev.get("user")
            if u and not is_admin_user(u):
                user_logons.setdefault(u, []).append(ev)

    for u, u_evs in user_logons.items():
        if len(u_evs) < config.LATERAL_MOVEMENT_HOST_THRESHOLD:
            continue
        n_u = len(u_evs)
        i = 0
        while i < n_u:
            start_t = u_evs[i]["dt"]
            max_t = start_t.timestamp() + (config.LATERAL_MOVEMENT_WINDOW_MINUTES * 60)
            window_evs = []
            j = i
            while j < n_u and u_evs[j]["dt"].timestamp() <= max_t:
                window_evs.append(u_evs[j])
                j += 1

            distinct_hosts = sorted(list({w.get("host") for w in window_evs if w.get("host")}))
            if len(distinct_hosts) >= config.LATERAL_MOVEMENT_HOST_THRESHOLD:
                alert_doc = {
                    "rule_name": "Suspected Lateral Movement",
                    "severity": "high",
                    "source_ip": u_evs[i].get("source_ip") or u_evs[i].get("src_ip"),
                    "src_ip": u_evs[i].get("source_ip") or u_evs[i].get("src_ip"),
                    "user": u,
                    "host": distinct_hosts,
                    "evidence": [w["_id"] for w in window_evs],
                    "first_seen": u_evs[i]["timestamp"],
                    "last_seen": window_evs[-1]["timestamp"],
                    "mitre_technique": "T1021",
                    "description": f"User {u} logged on to {len(distinct_hosts)} distinct hosts ({', '.join(distinct_hosts)}) within {config.LATERAL_MOVEMENT_WINDOW_MINUTES}m",
                    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                }
                alerts.append(alert_doc)
                i = j
            else:
                i += 1

    # =========================================================================
    # Deduplicate and index alerts into security-alerts
    # =========================================================================
    indexed_alerts = []
    seen_ids = set()

    for alert in alerts:
        a_id = compute_alert_id(
            alert["rule_name"],
            alert.get("source_ip") or alert.get("src_ip"),
            alert.get("host"),
            alert["first_seen"],
            alert["last_seen"]
        )
        if a_id in seen_ids:
            continue
        seen_ids.add(a_id)

        clean_alert = sanitize_doc_ips(alert)
        # Index with deterministic ID
        es.index(
            index=alerts_index,
            id=a_id,
            document=clean_alert,
            refresh=True
        )
        alert["_id"] = a_id
        indexed_alerts.append(alert)

    try:
        es.indices.refresh(index=alerts_index)
    except Exception:
        pass

    logger.info("Correlation cycle completed: %d alert(s) stored in %s", len(indexed_alerts), alerts_index)
    return indexed_alerts
