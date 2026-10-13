import re
import json
import csv
import io
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
from dateutil import parser as date_parser

import config

# Canonical common schema:
# {
#     "timestamp": "ISO8601 in UTC",
#     "source": "Windows | Linux | Network",
#     "source_type": "windows_sysmon | linux_auditd | network_firewall",  # compatibility
#     "event_type": "logon_success | logon_failure | process_creation | network_connection | file_access | privilege_escalation",
#     "user": "string | None",
#     "source_ip": "string | None",
#     "destination_ip": "string | None",
#     "destination_port": "int | None",
#     "process_name": "string | None",
#     "severity": "low | medium | high | critical",
#     "host": "string",
#     "raw_log": "string",
#     # Compatibility aliases:
#     "src_ip": "string | None",
#     "dest_ip": "string | None",
#     "raw": "string",
#     "ip_tags": ["private", "internal"] | ["public", "external"]
# }

# Expected Field Mappings for JSON / CSV tolerance
FIELD_ALIASES = {
    "event_id": [
        "eventid", "event_id", "id", "eventcode", "event_code", "event.id",
        "winlog.event_id", "winlog.record_id", "eventidentifier"
    ],
    "timestamp": [
        "timestamp", "@timestamp", "timecreated", "time", "date", "utctime",
        "datetime", "systemtime", "created_at", "time_generated", "event_time"
    ],
    "host": [
        "host", "hostname", "computer", "computername", "system", "device",
        "agent.name", "host.name", "destinationhostname"
    ],
    "user": [
        "user", "username", "targetusername", "accountname", "targetuser",
        "subjectusername", "account", "srcuser", "user.name", "destuser", "auid", "uid"
    ],
    "source_ip": [
        "source_ip", "src_ip", "srcip", "ipaddress", "ip", "clientaddress",
        "sourcenetworkaddress", "sourceip", "src", "client_ip", "remote_ip",
        "source_network_address", "rhost"
    ],
    "destination_ip": [
        "destination_ip", "dest_ip", "dst_ip", "destip", "dstip", "dst",
        "destinationip", "targetip", "destination_network_address"
    ],
    "destination_port": [
        "destination_port", "dest_port", "dst_port", "destport", "dstport",
        "dport", "dpt", "port"
    ],
    "process_name": [
        "process_name", "processname", "newprocessname", "image", "process",
        "commandline", "process.name", "process.executable", "new_process_name",
        "comm", "exe"
    ],
    "event_type": [
        "event_type", "eventtype", "action", "activity", "type"
    ],
    "severity": [
        "severity", "level", "log_level", "priority"
    ],
    "file_path": [
        "file_path", "filename", "path", "target_filename", "name"
    ]
}

SOURCE_CANONICAL_MAP = {
    "windows_sysmon": "Windows",
    "windows_security": "Windows",
    "linux_auditd": "Linux",
    "linux_auth": "Linux",
    "network_firewall": "Network",
    "firewall": "Network"
}


def compute_deterministic_id(source_type: str, raw_line: str) -> str:
    """Computes SHA-256 hash of source_type + raw line to guarantee idempotent ingestion."""
    clean_line = raw_line.strip()
    return hashlib.sha256(f"{source_type}:{clean_line}".encode("utf-8")).hexdigest()


_INTERNAL_NETWORKS = [ipaddress.ip_network(s) for s in config.INTERNAL_SUBNETS]


def tag_ip(ip_str: Optional[str]) -> List[str]:
    """Tag an IP as private/internal or public/external using offline local lookup."""
    if not ip_str:
        return []
    s = str(ip_str).strip()
    if not s or s in ("-", "unknown", "none"):
        return []
    try:
        ip = ipaddress.ip_address(s)
        if any(ip in net for net in _INTERNAL_NETWORKS):
            return ["private", "internal"]
        return ["public", "external"]
    except ValueError:
        return []


def sanitize_ip(ip_str: Optional[Any]) -> Optional[str]:
    """Sanitize IP address string. Returns valid IPv4/IPv6 string or None."""
    if ip_str is None:
        return None
    s = str(ip_str).strip()
    if not s or s in ("-", "::1", "127.0.0.1", "none", "unknown"):
        # Still parse loopbacks if valid IP
        if s in ("::1", "127.0.0.1"):
            return s
        return None
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        return None


def parse_timestamp_to_utc_iso(ts_str: Any) -> Optional[str]:
    """Parses a timestamp string or epoch number into UTC ISO8601 string.
    Never uses datetime.now().
    Handles syslog lines lacking a year by applying the current calendar year.
    Handles auditd epoch timestamps like msg=audit(1697191230.123:456).
    """
    if ts_str is None:
        return None

    # Handle numeric timestamp (epoch seconds / milliseconds)
    if isinstance(ts_str, (int, float)):
        try:
            val = float(ts_str)
            if val > 1e11:  # Milliseconds
                val /= 1000.0
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            return None

    s = str(ts_str).strip()
    if not s:
        return None

    # Check for auditd epoch format: msg=audit(1697191230.123:456) or 1697191230.123
    audit_m = re.search(r'(?:audit\(|msg=audit\()?(\d+(?:\.\d+)?)(?::\d+\)?)?', s)
    if audit_m and len(audit_m.group(1)) >= 9:
        try:
            val = float(audit_m.group(1))
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

    # Check numeric epoch in string form
    try:
        val = float(s)
        if val > 1e11:
            val /= 1000.0
        dt = datetime.fromtimestamp(val, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        pass

    # Regex test for syslog format: e.g. "Oct 13 10:15:30" or "Oct  5 09:12:00"
    syslog_match = re.match(r"^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})(?:\.\d+)?", s)
    if syslog_match:
        current_year = datetime.now(timezone.utc).year
        date_with_year = f"{current_year} {syslog_match.group(1)}"
        try:
            dt = datetime.strptime(date_with_year, "%Y %b %d %H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

    # Generic date parsing
    try:
        dt = date_parser.parse(s)
        if dt.tzinfo is None:
            # Assume UTC if not specified
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def extract_field_by_aliases(data: Dict[str, Any], field_key: str) -> Optional[Any]:
    """Finds a field from a dictionary using case-insensitive alias matching."""
    aliases = FIELD_ALIASES.get(field_key, [field_key])
    # Lowercase lookup map
    lookup = {str(k).lower().replace(" ", "").replace("_", "").replace("-", ""): v for k, v in data.items()}

    for alias in aliases:
        norm_alias = alias.lower().replace(" ", "").replace("_", "").replace("-", "")
        if norm_alias in lookup:
            val = lookup[norm_alias]
            if val is not None and str(val).strip() != "" and str(val).strip() != "-":
                return val
    return None


def clean_process_name(proc: Optional[str]) -> Optional[str]:
    """Extracts basename of process, e.g. C:\\Windows\\System32\\cmd.exe -> cmd.exe."""
    if not proc:
        return None
    p = str(proc).replace("\\", "/").strip().strip('"').strip("'")
    base = p.split("/")[-1].strip()
    return base.lower() if base else None


def assemble_normalized_doc(
    timestamp: str,
    source: str,
    source_type: str,
    event_type: str,
    user: Optional[str],
    source_ip: Optional[str],
    destination_ip: Optional[str],
    destination_port: Optional[int],
    process_name: Optional[str],
    severity: str,
    host: str,
    raw_log: str,
    extra_fields: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Constructs the canonical normalized document with backward compatibility fields."""
    s_ip = sanitize_ip(source_ip)
    d_ip = sanitize_ip(destination_ip)

    # Convert event_type synonyms
    if event_type == "process_create":
        canonical_event_type = "process_create"
    elif event_type in ("process_creation", "process_execute"):
        canonical_event_type = "process_create"
    else:
        canonical_event_type = event_type

    doc = {
        "timestamp": timestamp,
        "source": source,
        "source_type": source_type,
        "event_type": canonical_event_type,
        "user": str(user).strip() if user else None,
        "source_ip": s_ip,
        "src_ip": s_ip,
        "destination_ip": d_ip,
        "dest_ip": d_ip,
        "destination_port": destination_port,
        "process_name": process_name,
        "severity": severity.lower(),
        "host": str(host).strip() if host else "unknown",
        "raw_log": raw_log.strip(),
        "raw": raw_log.strip(),
        "ip_tags": tag_ip(s_ip)
    }

    if extra_fields:
        for k, v in extra_fields.items():
            if k not in doc:
                doc[k] = v

    return doc


# ---------------------------------------------------------------------------
# Source-Specific Parsers
# ---------------------------------------------------------------------------

def parse_windows_sysmon(data: Dict[str, Any], raw_line: str, source_type: str = "windows_sysmon") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parser for Windows Sysmon and Windows Security Events (4624, 4625, 4688, 4672, Sysmon 1/3/11)."""
    raw_event_id = extract_field_by_aliases(data, "event_id")
    if raw_event_id is None:
        return None, "Missing Windows Event ID"

    try:
        event_id = int(str(raw_event_id).strip())
    except ValueError:
        return None, f"Invalid non-integer Event ID: {raw_event_id}"

    raw_ts = extract_field_by_aliases(data, "timestamp")
    if not raw_ts:
        return None, "Missing timestamp field in Windows event"
    iso_ts = parse_timestamp_to_utc_iso(raw_ts)
    if not iso_ts:
        return None, f"Failed to parse timestamp '{raw_ts}'"

    host = extract_field_by_aliases(data, "host") or "WINDOWS-ENDPOINT"
    user = extract_field_by_aliases(data, "user")
    src_ip = extract_field_by_aliases(data, "source_ip")
    dst_ip = extract_field_by_aliases(data, "destination_ip")
    dst_port = extract_field_by_aliases(data, "destination_port")
    proc_name = clean_process_name(extract_field_by_aliases(data, "process_name"))

    event_type = None
    severity = "low"
    extra = {}

    # Windows Security IDs
    if event_id == 4624:
        event_type = "logon_success"
        severity = "low"
    elif event_id == 4625:
        event_type = "logon_failure"
        severity = "medium"
    elif event_id == 4688:
        event_type = "process_create"
        severity = "medium" if (proc_name and proc_name in [p.lower() for p in config.UNUSUAL_PROCESSES]) else "low"
    elif event_id == 4672:
        event_type = "privilege_escalation"
        severity = "high"
        extra["privilege"] = "SpecialPrivilegesAssigned"
    # Sysmon Event IDs
    elif event_id == 1:
        event_type = "process_create"
        severity = "medium" if (proc_name and proc_name in [p.lower() for p in config.UNUSUAL_PROCESSES]) else "low"
    elif event_id == 3:
        event_type = "network_connection"
        severity = "low"
    elif event_id == 11:
        event_type = "file_access"
        file_path = extract_field_by_aliases(data, "file_path")
        severity = "high" if (file_path and any(sf.lower() in file_path.lower() for sf in config.SENSITIVE_FILES)) else "medium"
        extra["file_path"] = file_path
    elif event_id == 5:
        event_type = "process_terminate"
        severity = "low"
    else:
        # Generic event
        event_type = extract_field_by_aliases(data, "event_type") or f"windows_event_{event_id}"
        severity = "low"

    # Port parsing
    port_val = None
    if dst_port is not None:
        try:
            port_val = int(dst_port)
        except ValueError:
            pass

    doc = assemble_normalized_doc(
        timestamp=iso_ts,
        source="Windows",
        source_type=source_type,
        event_type=event_type,
        user=user,
        source_ip=src_ip,
        destination_ip=dst_ip,
        destination_port=port_val,
        process_name=proc_name,
        severity=severity,
        host=str(host),
        raw_log=raw_line,
        extra_fields=extra
    )
    return doc, None


def parse_linux_auditd(line_or_dict: Any, raw_line: str, source_type: str = "linux_auditd") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parser for Linux auditd logs (type=SYSCALL, type=USER_CMD, type=PATH) and sshd/auth.log lines."""
    raw = raw_line.strip()
    if not raw:
        return None, "Empty line"

    # If already a dictionary (from JSON or CSV)
    if isinstance(line_or_dict, dict):
        raw_ts = extract_field_by_aliases(line_or_dict, "timestamp")
        iso_ts = parse_timestamp_to_utc_iso(raw_ts)
        if not iso_ts:
            return None, "Missing or invalid timestamp in Linux event dictionary"

        host = extract_field_by_aliases(line_or_dict, "host") or "linux-host"
        user = extract_field_by_aliases(line_or_dict, "user")
        src_ip = extract_field_by_aliases(line_or_dict, "source_ip")
        dst_ip = extract_field_by_aliases(line_or_dict, "destination_ip")
        proc_name = clean_process_name(extract_field_by_aliases(line_or_dict, "process_name"))
        ev_type = extract_field_by_aliases(line_or_dict, "event_type") or "system_activity"
        file_path = extract_field_by_aliases(line_or_dict, "file_path")
        sev = extract_field_by_aliases(line_or_dict, "severity") or "low"

        extra = {}
        if file_path:
            extra["file_path"] = file_path

        doc = assemble_normalized_doc(
            timestamp=iso_ts,
            source="Linux",
            source_type=source_type,
            event_type=ev_type,
            user=user,
            source_ip=src_ip,
            destination_ip=dst_ip,
            destination_port=None,
            process_name=proc_name,
            severity=str(sev),
            host=str(host),
            raw_log=raw,
            extra_fields=extra
        )
        return doc, None

    # Case A: Auditd format: "type=SYSCALL msg=audit(1697191230.123:456): arch=... exe=..."
    if "msg=audit(" in raw or raw.startswith("type="):
        # Extract audit timestamp
        ts_m = re.search(r'msg=audit\((\d+(?:\.\d+)?):', raw)
        if not ts_m:
            return None, "Auditd line missing msg=audit(epoch:id) timestamp"
        iso_ts = parse_timestamp_to_utc_iso(ts_m.group(1))
        if not iso_ts:
            return None, f"Failed to parse auditd epoch: {ts_m.group(1)}"

        # Extract type
        type_m = re.search(r'type=([A-Z_]+)', raw)
        audit_type = type_m.group(1) if type_m else "UNKNOWN"

        # Key-value extraction for auditd: k=v or k="v"
        matches = re.findall(r'(\b\w+)=(?:"([^"]*)"|(\S+))', raw)
        flat_kv = {m[0]: (m[1] if m[1] else m[2]) for m in matches}

        host = flat_kv.get("host", "linux-srv")
        user = flat_kv.get("auid") or flat_kv.get("uid") or flat_kv.get("user")
        if user in ("4294967295", "unset", "-1"):
            user = flat_kv.get("uid")

        exe = flat_kv.get("exe") or flat_kv.get("comm") or flat_kv.get("cmd")
        proc_name = clean_process_name(exe)
        file_path = flat_kv.get("name") or flat_kv.get("cwd")

        extra = {}
        if file_path:
            extra["file_path"] = file_path

        # Determine event_type and severity
        if audit_type in ("USER_AUTH", "USER_LOGIN"):
            res = flat_kv.get("res", "").lower()
            event_type = "logon_success" if res in ("success", "1") else "logon_failure"
            severity = "low" if event_type == "logon_success" else "medium"
        elif audit_type == "USER_CMD":
            event_type = "privilege_escalation"
            severity = "high"
            cmd_val = flat_kv.get("cmd", "")
            proc_name = clean_process_name(cmd_val.split()[0]) if cmd_val else proc_name
        elif audit_type == "PATH" or (file_path and any(sf.lower() in file_path.lower() for sf in config.SENSITIVE_FILES)):
            event_type = "file_access"
            severity = "high"
        elif audit_type in ("SYSCALL", "EXECVE"):
            event_type = "process_create"
            # Check privilege change
            uid = flat_kv.get("uid")
            euid = flat_kv.get("euid")
            if uid and euid and uid != euid and euid == "0":
                event_type = "privilege_escalation"
                severity = "high"
            else:
                severity = "medium" if (proc_name and proc_name in [p.lower() for p in config.UNUSUAL_PROCESSES]) else "low"
        else:
            event_type = "system_activity"
            severity = "low"

        doc = assemble_normalized_doc(
            timestamp=iso_ts,
            source="Linux",
            source_type=source_type,
            event_type=event_type,
            user=user,
            source_ip=flat_kv.get("rhost"),
            destination_ip=None,
            destination_port=None,
            process_name=proc_name,
            severity=severity,
            host=host,
            raw_log=raw,
            extra_fields=extra
        )
        return doc, None

    # Case B: Syslog auth.log format (sshd, sudo, pam)
    syslog_hdr = re.match(r"^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([^\s:]+)\s+([^:]+):\s*(.*)$", raw)
    if not syslog_hdr:
        iso_hdr = re.match(r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+([^\s:]+)\s+([^:]+):\s*(.*)$", raw)
        if iso_hdr:
            ts_str, host, service, msg = iso_hdr.groups()
        else:
            return None, "Line does not match auditd or standard syslog auth format"
    else:
        ts_str, host, service, msg = syslog_hdr.groups()

    iso_ts = parse_timestamp_to_utc_iso(ts_str)
    if not iso_ts:
        return None, f"Failed to parse timestamp from '{ts_str}'"

    # SSH Accepted password / publickey
    m_acc = re.search(r"Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+([0-9a-fA-F\.:]+)", msg)
    if m_acc:
        return assemble_normalized_doc(
            timestamp=iso_ts,
            source="Linux",
            source_type=source_type,
            event_type="logon_success",
            user=m_acc.group(1),
            source_ip=m_acc.group(2),
            destination_ip=None,
            destination_port=None,
            process_name=None,
            severity="low",
            host=host,
            raw_log=raw
        ), None

    # SSH Failed password
    m_fail = re.search(r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([0-9a-fA-F\.:]+)", msg)
    if m_fail:
        return assemble_normalized_doc(
            timestamp=iso_ts,
            source="Linux",
            source_type=source_type,
            event_type="logon_failure",
            user=m_fail.group(1),
            source_ip=m_fail.group(2),
            destination_ip=None,
            destination_port=None,
            process_name=None,
            severity="medium",
            host=host,
            raw_log=raw
        ), None

    # Sudo command execution -> process_create
    m_sudo_cmd = re.search(r"^\s*(\S+)\s*:\s*.*COMMAND=(.+)$", msg)
    if "sudo" in service.lower() and m_sudo_cmd:
        user = m_sudo_cmd.group(1)
        cmd = m_sudo_cmd.group(2).strip()
        proc = cmd.split()[0] if cmd else cmd
        # Check if privilege escalation
        is_priv = any(cmd.lower().startswith(c) for c in config.PRIVILEGE_COMMANDS) or "su " in cmd.lower()
        ev_type = "privilege_escalation" if is_priv else "process_create"
        sev = "high" if is_priv else "medium"
        return assemble_normalized_doc(
            timestamp=iso_ts,
            source="Linux",
            source_type=source_type,
            event_type=ev_type,
            user=user,
            source_ip=None,
            destination_ip=None,
            destination_port=None,
            process_name=proc,
            severity=sev,
            host=host,
            raw_log=raw
        ), None

    # Sudo / pam auth failure
    if "authentication failure" in msg.lower():
        m_u = re.search(r"user=(\S+)", msg)
        m_ip = re.search(r"rhost=([0-9a-fA-F\.:]+)", msg)
        user = m_u.group(1) if m_u else None
        src_ip = m_ip.group(1) if m_ip else None
        return assemble_normalized_doc(
            timestamp=iso_ts,
            source="Linux",
            source_type=source_type,
            event_type="logon_failure",
            user=user,
            source_ip=src_ip,
            destination_ip=None,
            destination_port=None,
            process_name=None,
            severity="medium",
            host=host,
            raw_log=raw
        ), None

    return None, f"Unrecognized Linux auth activity in message: '{msg[:60]}...'"


def parse_network_firewall(line_or_dict: Any, raw_line: str, source_type: str = "network_firewall") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Parser for Network Firewall logs (iptables, UFW, Cisco ASA, pfSense, JSON, CSV)."""
    raw = raw_line.strip()
    if not raw:
        return None, "Empty line"

    # If already a dictionary
    if isinstance(line_or_dict, dict):
        raw_ts = extract_field_by_aliases(line_or_dict, "timestamp")
        iso_ts = parse_timestamp_to_utc_iso(raw_ts)
        if not iso_ts:
            return None, "Missing or invalid timestamp in firewall dictionary"

        host = extract_field_by_aliases(line_or_dict, "host") or "firewall"
        src_ip = extract_field_by_aliases(line_or_dict, "source_ip")
        dst_ip = extract_field_by_aliases(line_or_dict, "destination_ip")
        dst_port_raw = extract_field_by_aliases(line_or_dict, "destination_port")
        action = str(extract_field_by_aliases(line_or_dict, "action") or "ALLOW").upper()

        port_val = None
        if dst_port_raw is not None:
            try:
                port_val = int(dst_port_raw)
            except ValueError:
                pass

        sev = "medium" if action in ("BLOCK", "DENY", "DROP", "REJECT") else "low"

        doc = assemble_normalized_doc(
            timestamp=iso_ts,
            source="Network",
            source_type=source_type,
            event_type="network_connection",
            user=extract_field_by_aliases(line_or_dict, "user"),
            source_ip=src_ip,
            destination_ip=dst_ip,
            destination_port=port_val,
            process_name=None,
            severity=sev,
            host=str(host),
            raw_log=raw,
            extra_fields={"action": action}
        )
        return doc, None

    # Text pattern: Syslog or key-value pattern (UFW, iptables, Cisco)
    # e.g.: "Oct 13 10:15:30 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=4432 DPT=22"
    m_ts = re.match(r"^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+([^\s:]+)", raw)
    if m_ts:
        ts_str = m_ts.group(1)
        host = m_ts.group(2)
        iso_ts = parse_timestamp_to_utc_iso(ts_str)
    else:
        m_tseq = re.search(r'(?:timestamp|time)=["\']?([^"\'\s]+)', raw, re.IGNORECASE)
        if m_tseq:
            iso_ts = parse_timestamp_to_utc_iso(m_tseq.group(1))
            host = "firewall"
        else:
            return None, "Could not extract timestamp from firewall log line"

    if not iso_ts:
        return None, "Failed to parse timestamp in firewall line"

    # Search for SRC IP
    m_src = re.search(r'(?:SRC|src|source_ip|src_ip)=([0-9a-fA-F\.:]+)', raw, re.IGNORECASE)
    src_ip = m_src.group(1) if m_src else None

    # Search for DST IP
    m_dst = re.search(r'(?:DST|dst|destination_ip|dest_ip)=([0-9a-fA-F\.:]+)', raw, re.IGNORECASE)
    dst_ip = m_dst.group(1) if m_dst else None

    # Search for DPT (destination port)
    m_port = re.search(r'(?:DPT|dpt|dport|destination_port)=([0-9]+)', raw, re.IGNORECASE)
    dst_port = int(m_port.group(1)) if m_port else None

    # Action detection
    action = "ALLOW"
    if any(k in raw.upper() for k in ("BLOCK", "DENY", "DROP", "REJECT")):
        action = "BLOCK"
    sev = "medium" if action == "BLOCK" else "low"

    # User if any
    m_u = re.search(r'(?:user|username|srcuser)=([^\s,;]+)', raw, re.IGNORECASE)
    user = m_u.group(1) if m_u else None

    doc = assemble_normalized_doc(
        timestamp=iso_ts,
        source="Network",
        source_type=source_type,
        event_type="network_connection",
        user=user,
        source_ip=src_ip,
        destination_ip=dst_ip,
        destination_port=dst_port,
        process_name=None,
        severity=sev,
        host=host,
        raw_log=raw,
        extra_fields={"action": action}
    )
    return doc, None


# ---------------------------------------------------------------------------
# High-Level Normalizers & Tolerant Formats (JSON, CSV, Lines)
# ---------------------------------------------------------------------------

def normalize_windows_security_line(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Backward compatibility wrapper for Windows text lines."""
    raw = line.strip()
    if not raw:
        return None, "Empty line"

    # JSON line
    if raw.startswith("{") and raw.endswith("}"):
        try:
            d = json.loads(raw)
            return parse_windows_sysmon(d, raw, source_type="windows_security")
        except json.JSONDecodeError as e:
            return None, f"Invalid JSON syntax: {e}"

    # Key-value line
    kv_pairs = dict(re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', raw))
    if kv_pairs:
        data = {k: (v[0] if v[0] else v[1]) for k, v in kv_pairs.items()}
        if any(k.lower() in [a.lower() for a in FIELD_ALIASES["event_id"]] for k in data.keys()):
            return parse_windows_sysmon(data, raw, source_type="windows_security")

    # Delimited: "2026-10-13 10:15:30, WIN-SRV01, 4624, alice, 192.168.1.50"
    parts = [p.strip() for p in re.split(r"[,|\t]", raw)]
    if len(parts) >= 4:
        found_eid = None
        for p in parts:
            if p in ("4624", "4625", "4688", "4672", "1", "3", "11"):
                found_eid = int(p)
                break
        if found_eid:
            data = {
                "timestamp": parts[0],
                "host": parts[1],
                "event_id": found_eid,
                "user": parts[3] if len(parts) > 3 else None,
                "source_ip": parts[4] if len(parts) > 4 else None,
                "process_name": parts[5] if len(parts) > 5 else None
            }
            return parse_windows_sysmon(data, raw, source_type="windows_security")

    return None, "Unrecognized Windows Security text format"


def normalize_linux_auth_line(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Backward compatibility wrapper for Linux auth lines."""
    return parse_linux_auditd(None, line, source_type="linux_auth")


def normalize_firewall_line(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Backward compatibility wrapper for Firewall lines."""
    raw = line.strip()
    if raw.startswith("{") and raw.endswith("}"):
        try:
            d = json.loads(raw)
            return parse_network_firewall(d, raw, source_type="firewall")
        except Exception as e:
            return None, f"Invalid firewall JSON: {e}"
    return parse_network_firewall(None, line, source_type="firewall")


def normalize_csv_content(csv_text: str, source_type: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parses and normalizes CSV data using header inspection and alias mapping."""
    events = []
    skipped = []

    f = io.StringIO(csv_text)
    reader = csv.DictReader(f)
    if not reader.fieldnames:
        return [], [{"line_number": 1, "raw": "", "reason": "Empty CSV or no header row found"}]

    canonical_source = SOURCE_CANONICAL_MAP.get(source_type, "Windows")

    line_num = 1
    for row in reader:
        line_num += 1
        raw_repr = json.dumps(row)
        if canonical_source == "Windows":
            doc, err = parse_windows_sysmon(row, raw_repr, source_type=source_type)
        elif canonical_source == "Linux":
            doc, err = parse_linux_auditd(row, raw_repr, source_type=source_type)
        elif canonical_source == "Network":
            doc, err = parse_network_firewall(row, raw_repr, source_type=source_type)
        else:
            doc, err = None, f"Unsupported source_type: {source_type}"

        if doc:
            doc_id = compute_deterministic_id(source_type, raw_repr)
            events.append({"_id": doc_id, "_source": doc})
        else:
            skipped.append({"line_number": line_num, "raw": raw_repr[:120], "reason": err})

    return events, skipped


def normalize_content(content_str: str, source_type: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Top-level normalizer: parses log text, JSON/JSONL, or CSV lines.
    Supports: windows_sysmon, windows_security, linux_auditd, linux_auth, network_firewall, firewall.
    Returns:
        events: List[{"_id": deterministic_id, "_source": doc}]
        skipped: List[{"line_number": int, "raw": str, "reason": str}]
    """
    if source_type not in SOURCE_CANONICAL_MAP:
        valid_sources = ", ".join(SOURCE_CANONICAL_MAP.keys())
        raise ValueError(f"Invalid source_type '{source_type}'. Allowed: {valid_sources}")

    canonical_source = SOURCE_CANONICAL_MAP[source_type]
    clean_content = content_str.strip()
    if not clean_content:
        return [], []

    # Check if whole file is a single JSON array
    if clean_content.startswith("[") and clean_content.endswith("]"):
        try:
            arr = json.loads(clean_content)
            events = []
            skipped = []
            for idx, item in enumerate(arr, start=1):
                raw_repr = json.dumps(item)
                if canonical_source == "Windows":
                    doc, err = parse_windows_sysmon(item, raw_repr, source_type=source_type)
                elif canonical_source == "Linux":
                    doc, err = parse_linux_auditd(item, raw_repr, source_type=source_type)
                elif canonical_source == "Network":
                    doc, err = parse_network_firewall(item, raw_repr, source_type=source_type)
                else:
                    doc, err = None, "Unknown source"

                if doc:
                    doc_id = compute_deterministic_id(source_type, raw_repr)
                    events.append({"_id": doc_id, "_source": doc})
                else:
                    skipped.append({"line_number": idx, "raw": raw_repr[:120], "reason": err})
            return events, skipped
        except json.JSONDecodeError:
            pass

    # Check if first line contains CSV header commas
    first_line = clean_content.splitlines()[0] if clean_content.splitlines() else ""
    if "," in first_line and not first_line.startswith("{") and any(
        col in first_line.lower() for col in ["eventid", "timecreated", "timestamp", "host", "user", "ipaddress", "event_id"]
    ):
        return normalize_csv_content(clean_content, source_type)

    # Process line-by-line (text logs or JSONL)
    events = []
    skipped = []
    lines = content_str.splitlines()

    for line_num, line in enumerate(lines, start=1):
        if not line.strip():
            continue

        raw = line.strip()
        doc = None
        err = None

        # Check JSONL
        if raw.startswith("{") and raw.endswith("}"):
            try:
                d = json.loads(raw)
                if canonical_source == "Windows":
                    doc, err = parse_windows_sysmon(d, raw, source_type=source_type)
                elif canonical_source == "Linux":
                    doc, err = parse_linux_auditd(d, raw, source_type=source_type)
                elif canonical_source == "Network":
                    doc, err = parse_network_firewall(d, raw, source_type=source_type)
            except Exception as e:
                doc, err = None, f"Invalid JSON line: {e}"
        else:
            if canonical_source == "Windows":
                if source_type == "windows_security":
                    doc, err = normalize_windows_security_line(line)
                else:
                    doc, err = parse_windows_sysmon({}, line, source_type=source_type)
            elif canonical_source == "Linux":
                doc, err = parse_linux_auditd(None, line, source_type=source_type)
            elif canonical_source == "Network":
                doc, err = parse_network_firewall(None, line, source_type=source_type)

        if doc:
            doc_id = compute_deterministic_id(source_type, line)
            events.append({"_id": doc_id, "_source": doc})
        else:
            skipped.append({"line_number": line_num, "raw": line.strip()[:120], "reason": err})

    return events, skipped
