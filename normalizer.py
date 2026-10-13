import re
import json
import csv
import io
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional
from dateutil import parser as date_parser

# Canonical common schema:
# {
#     "timestamp": "ISO8601 in UTC",
#     "host": "string",
#     "source_type": "windows_security | linux_auth | firewall",
#     "event_type": "logon_success | logon_failure | process_create | network_connection",
#     "user": "string | None",
#     "src_ip": "string | None",
#     "process_name": "string | None",
#     "raw": "string"
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
        "subjectusername", "account", "srcuser", "user.name", "destuser"
    ],
    "src_ip": [
        "src_ip", "srcip", "ipaddress", "ip", "clientaddress", "sourcenetworkaddress",
        "sourceip", "source_ip", "src", "client_ip", "remote_ip", "source_network_address"
    ],
    "process_name": [
        "process_name", "processname", "newprocessname", "image", "process",
        "commandline", "process.name", "process.executable", "new_process_name"
    ],
    "event_type": [
        "event_type", "eventtype", "action", "activity", "type"
    ]
}


def compute_deterministic_id(source_type: str, raw_line: str) -> str:
    """Computes SHA-256 hash of source_type + raw line to guarantee idempotent ingestion."""
    clean_line = raw_line.strip()
    return hashlib.sha256(f"{source_type}:{clean_line}".encode("utf-8")).hexdigest()


def parse_timestamp_to_utc_iso(ts_str: Any) -> Optional[str]:
    """Parses a timestamp string or epoch number into UTC ISO8601 string.
    Never uses datetime.now().
    Handles syslog lines lacking a year by applying the current calendar year.
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


def normalize_linux_auth_line(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Normalizes Linux auth / syslog text lines (sshd, sudo, pam)."""
    raw = line.strip()
    if not raw:
        return None, "Empty line"

    # 1. Syslog header: "Oct 13 10:15:30 hostname program[pid]: message"
    syslog_hdr = re.match(r"^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([^\s:]+)\s+([^:]+):\s*(.*)$", raw)
    if not syslog_hdr:
        # Try ISO timestamp: "2026-10-13T10:15:30+00:00 hostname sshd[123]: ..."
        iso_hdr = re.match(r"^(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+([^\s:]+)\s+([^:]+):\s*(.*)$", raw)
        if iso_hdr:
            ts_str, host, service, msg = iso_hdr.groups()
        else:
            return None, "Line does not match standard syslog or ISO auth format"
    else:
        ts_str, host, service, msg = syslog_hdr.groups()

    iso_ts = parse_timestamp_to_utc_iso(ts_str)
    if not iso_ts:
        return None, f"Failed to parse timestamp from '{ts_str}'"

    user = None
    src_ip = None
    event_type = None
    process_name = None

    # Check SSH Accepted password / publickey
    m_acc = re.search(r"Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+([0-9a-fA-F\.:]+)", msg)
    if m_acc:
        event_type = "logon_success"
        user = m_acc.group(1)
        src_ip = m_acc.group(2)
        return {
            "timestamp": iso_ts,
            "host": host,
            "source_type": "linux_auth",
            "event_type": event_type,
            "user": user,
            "src_ip": src_ip,
            "process_name": None,
            "raw": raw
        }, None

    # Check SSH Failed password / authentication failure
    m_fail = re.search(r"Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+([0-9a-fA-F\.:]+)", msg)
    if m_fail:
        event_type = "logon_failure"
        user = m_fail.group(1)
        src_ip = m_fail.group(2)
        return {
            "timestamp": iso_ts,
            "host": host,
            "source_type": "linux_auth",
            "event_type": event_type,
            "user": user,
            "src_ip": src_ip,
            "process_name": None,
            "raw": raw
        }, None

    # Sudo command execution -> process_create
    m_sudo_cmd = re.search(r"^\s*(\S+)\s*:\s*.*COMMAND=(.+)$", msg)
    if "sudo" in service.lower() and m_sudo_cmd:
        event_type = "process_create"
        user = m_sudo_cmd.group(1)
        cmd = m_sudo_cmd.group(2).strip()
        proc = cmd.split()[0] if cmd else cmd
        return {
            "timestamp": iso_ts,
            "host": host,
            "source_type": "linux_auth",
            "event_type": event_type,
            "user": user,
            "src_ip": None,
            "process_name": proc,
            "raw": raw
        }, None

    # Sudo / pam auth failure
    if "authentication failure" in msg.lower():
        event_type = "logon_failure"
        m_u = re.search(r"user=(\S+)", msg)
        m_ip = re.search(r"rhost=([0-9a-fA-F\.:]+)", msg)
        user = m_u.group(1) if m_u else None
        src_ip = m_ip.group(1) if m_ip else None
        return {
            "timestamp": iso_ts,
            "host": host,
            "source_type": "linux_auth",
            "event_type": event_type,
            "user": user,
            "src_ip": src_ip,
            "process_name": None,
            "raw": raw
        }, None

    return None, f"Unrecognized Linux auth activity in message: '{msg[:60]}...'"


def normalize_windows_dict(data: Dict[str, Any], raw_line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Normalizes structured Windows Security event dictionary (from JSON or CSV row)."""
    raw_event_id = extract_field_by_aliases(data, "event_id")
    if raw_event_id is None:
        return None, "Missing Windows Event ID"

    try:
        event_id = int(str(raw_event_id).strip())
    except ValueError:
        return None, f"Invalid non-integer Event ID: {raw_event_id}"

    # Map Event ID to SIEM event_type
    # 4624: Logon Success
    # 4625: Logon Failure
    # 4688: Process Creation
    if event_id == 4624:
        event_type = "logon_success"
    elif event_id == 4625:
        event_type = "logon_failure"
    elif event_id == 4688:
        event_type = "process_create"
    else:
        return None, f"Event ID {event_id} is not monitored (expects 4624, 4625, 4688)"

    # Extract timestamp
    raw_ts = extract_field_by_aliases(data, "timestamp")
    if not raw_ts:
        return None, "Missing timestamp field in Windows event"
    iso_ts = parse_timestamp_to_utc_iso(raw_ts)
    if not iso_ts:
        return None, f"Failed to parse timestamp '{raw_ts}'"

    # Extract host, user, src_ip, process_name
    host = extract_field_by_aliases(data, "host") or "WINDOWS-ENDPOINT"
    user = extract_field_by_aliases(data, "user")
    src_ip = extract_field_by_aliases(data, "src_ip")
    process_name = extract_field_by_aliases(data, "process_name")

    # Clean process name if full path is given (e.g. C:\Windows\System32\cmd.exe -> cmd.exe)
    if process_name:
        proc_str = str(process_name).replace("\\", "/").strip()
        process_name = proc_str.split("/")[-1].lower()

    # Clean IP address (exclude local dash or loopback if reported as -)
    if src_ip:
        src_ip = str(src_ip).strip()
        if src_ip in ("-", "::1", "127.0.0.1") and event_id == 4688:
            src_ip = None

    return {
        "timestamp": iso_ts,
        "host": str(host).strip(),
        "source_type": "windows_security",
        "event_type": event_type,
        "user": str(user).strip() if user else None,
        "src_ip": src_ip,
        "process_name": process_name,
        "raw": raw_line.strip()
    }, None


def normalize_windows_security_line(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Normalizes a single text line of Windows Security log (JSON, key-value, or formatted text)."""
    raw = line.strip()
    if not raw:
        return None, "Empty line"

    # Attempt JSON
    if raw.startswith("{") and raw.endswith("}"):
        try:
            d = json.loads(raw)
            return normalize_windows_dict(d, raw)
        except json.JSONDecodeError as e:
            return None, f"Invalid JSON syntax: {e}"

    # Attempt Key-Value format: "timestamp=... host=... event_id=4624 user=... ip=..."
    kv_pairs = dict(re.findall(r'(\w+)=(?:"([^"]*)"|(\S+))', raw))
    if kv_pairs:
        # flatten tuple values
        data = {k: (v[0] if v[0] else v[1]) for k, v in kv_pairs.items()}
        if any(k in [a.lower() for a in FIELD_ALIASES["event_id"]] for k in [k.lower() for k in data.keys()]):
            return normalize_windows_dict(data, raw)

    # Attempt comma or pipe delimited line without header:
    # "2026-10-13 10:15:30, WIN-SRV01, 4624, alice, 192.168.1.50"
    parts = [p.strip() for p in re.split(r"[,|\t]", raw)]
    if len(parts) >= 4:
        # Inspect for an event ID
        found_eid = None
        for p in parts:
            if p in ("4624", "4625", "4688"):
                found_eid = int(p)
                break
        if found_eid:
            iso_ts = parse_timestamp_to_utc_iso(parts[0])
            if iso_ts:
                event_type = "logon_success" if found_eid == 4624 else ("logon_failure" if found_eid == 4625 else "process_create")
                host = parts[1]
                user = parts[3] if len(parts) > 3 else None
                src_ip = parts[4] if len(parts) > 4 else None
                process_name = parts[5] if len(parts) > 5 and found_eid == 4688 else None
                return {
                    "timestamp": iso_ts,
                    "host": host,
                    "source_type": "windows_security",
                    "event_type": event_type,
                    "user": user,
                    "src_ip": src_ip,
                    "process_name": process_name,
                    "raw": raw
                }, None

    return None, "Unrecognized Windows Security text format"


def normalize_firewall_line(line: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Normalizes Firewall log entries (iptables, UFW, Cisco ASA, pfSense, generic key-value, JSON)."""
    raw = line.strip()
    if not raw:
        return None, "Empty line"

    # Attempt JSON
    if raw.startswith("{") and raw.endswith("}"):
        try:
            d = json.loads(raw)
            raw_ts = extract_field_by_aliases(d, "timestamp")
            iso_ts = parse_timestamp_to_utc_iso(raw_ts)
            if not iso_ts:
                return None, f"Missing or unparseable timestamp in firewall JSON"
            host = extract_field_by_aliases(d, "host") or "firewall"
            src_ip = extract_field_by_aliases(d, "src_ip")
            user = extract_field_by_aliases(d, "user")
            return {
                "timestamp": iso_ts,
                "host": str(host).strip(),
                "source_type": "firewall",
                "event_type": "network_connection",
                "user": str(user).strip() if user else None,
                "src_ip": str(src_ip).strip() if src_ip else None,
                "process_name": None,
                "raw": raw
            }, None
        except Exception as e:
            return None, f"Invalid firewall JSON: {e}"

    # Syslog or key-value pattern
    # e.g.: "Oct 13 10:15:30 fw01 kernel: [UFW BLOCK] IN=eth0 SRC=192.168.1.100 DST=10.0.0.1 PROTO=TCP SPT=4432 DPT=22"
    m_ts = re.match(r"^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+([^\s:]+)", raw)
    if m_ts:
        ts_str = m_ts.group(1)
        host = m_ts.group(2)
        iso_ts = parse_timestamp_to_utc_iso(ts_str)
    else:
        # Look for explicit timestamp=
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

    # Search for user if any
    m_u = re.search(r'(?:user|username|srcuser)=([^\s,;]+)', raw, re.IGNORECASE)
    user = m_u.group(1) if m_u else None

    return {
        "timestamp": iso_ts,
        "host": host,
        "source_type": "firewall",
        "event_type": "network_connection",
        "user": user,
        "src_ip": src_ip,
        "process_name": None,
        "raw": raw
    }, None


def normalize_csv_content(csv_text: str, source_type: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Parses and normalizes CSV data using header inspection and alias mapping."""
    events = []
    skipped = []

    f = io.StringIO(csv_text)
    reader = csv.DictReader(f)
    if not reader.fieldnames:
        return [], [{"line_number": 1, "raw": "", "reason": "Empty CSV or no header row found"}]

    line_num = 1  # Header is line 1
    for row in reader:
        line_num += 1
        raw_repr = json.dumps(row)
        if source_type == "windows_security":
            doc, err = normalize_windows_dict(row, raw_repr)
        elif source_type == "linux_auth":
            # Map common linux fields from CSV
            ts = extract_field_by_aliases(row, "timestamp")
            iso_ts = parse_timestamp_to_utc_iso(ts)
            ev_type = extract_field_by_aliases(row, "event_type")
            if not iso_ts or not ev_type:
                doc, err = None, "Missing timestamp or event_type in CSV row"
            else:
                doc = {
                    "timestamp": iso_ts,
                    "host": extract_field_by_aliases(row, "host") or "linux-host",
                    "source_type": "linux_auth",
                    "event_type": ev_type,
                    "user": extract_field_by_aliases(row, "user"),
                    "src_ip": extract_field_by_aliases(row, "src_ip"),
                    "process_name": extract_field_by_aliases(row, "process_name"),
                    "raw": raw_repr
                }
                err = None
        elif source_type == "firewall":
            ts = extract_field_by_aliases(row, "timestamp")
            iso_ts = parse_timestamp_to_utc_iso(ts)
            if not iso_ts:
                doc, err = None, "Missing timestamp in firewall CSV row"
            else:
                doc = {
                    "timestamp": iso_ts,
                    "host": extract_field_by_aliases(row, "host") or "firewall",
                    "source_type": "firewall",
                    "event_type": "network_connection",
                    "user": extract_field_by_aliases(row, "user"),
                    "src_ip": extract_field_by_aliases(row, "src_ip"),
                    "process_name": None,
                    "raw": raw_repr
                }
                err = None
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
    Returns:
        events: List[{"_id": deterministic_id, "_source": doc}]
        skipped: List[{"line_number": int, "raw": str, "reason": str}]
    """
    if source_type not in ("windows_security", "linux_auth", "firewall"):
        raise ValueError(f"Invalid source_type '{source_type}'. Allowed: windows_security, linux_auth, firewall")

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
                if source_type == "windows_security":
                    doc, err = normalize_windows_dict(item, raw_repr)
                elif source_type == "linux_auth":
                    ts = extract_field_by_aliases(item, "timestamp")
                    iso_ts = parse_timestamp_to_utc_iso(ts)
                    ev_type = extract_field_by_aliases(item, "event_type") or "logon_failure"
                    if not iso_ts:
                        doc, err = None, "Missing or invalid timestamp"
                    else:
                        doc = {
                            "timestamp": iso_ts,
                            "host": extract_field_by_aliases(item, "host") or "linux-host",
                            "source_type": "linux_auth",
                            "event_type": ev_type,
                            "user": extract_field_by_aliases(item, "user"),
                            "src_ip": extract_field_by_aliases(item, "src_ip"),
                            "process_name": extract_field_by_aliases(item, "process_name"),
                            "raw": raw_repr
                        }
                        err = None
                elif source_type == "firewall":
                    ts = extract_field_by_aliases(item, "timestamp")
                    iso_ts = parse_timestamp_to_utc_iso(ts)
                    if not iso_ts:
                        doc, err = None, "Missing or invalid timestamp"
                    else:
                        doc = {
                            "timestamp": iso_ts,
                            "host": extract_field_by_aliases(item, "host") or "firewall",
                            "source_type": "firewall",
                            "event_type": "network_connection",
                            "user": extract_field_by_aliases(item, "user"),
                            "src_ip": extract_field_by_aliases(item, "src_ip"),
                            "process_name": None,
                            "raw": raw_repr
                        }
                        err = None
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
        col in first_line.lower() for col in ["eventid", "timecreated", "timestamp", "host", "user", "ipaddress"]
    ):
        return normalize_csv_content(clean_content, source_type)

    # Process line-by-line (text logs or JSONL)
    events = []
    skipped = []
    lines = content_str.splitlines()

    for line_num, line in enumerate(lines, start=1):
        if not line.strip():
            continue  # Blank lines silently ignored without error

        if source_type == "linux_auth":
            # Test if JSON line
            if line.strip().startswith("{") and line.strip().endswith("}"):
                try:
                    d = json.loads(line)
                    ts = extract_field_by_aliases(d, "timestamp")
                    iso_ts = parse_timestamp_to_utc_iso(ts)
                    ev_type = extract_field_by_aliases(d, "event_type") or "logon_failure"
                    if not iso_ts:
                        doc, err = None, "Missing timestamp"
                    else:
                        doc = {
                            "timestamp": iso_ts,
                            "host": extract_field_by_aliases(d, "host") or "linux-host",
                            "source_type": "linux_auth",
                            "event_type": ev_type,
                            "user": extract_field_by_aliases(d, "user"),
                            "src_ip": extract_field_by_aliases(d, "src_ip"),
                            "process_name": extract_field_by_aliases(d, "process_name"),
                            "raw": line.strip()
                        }
                        err = None
                except Exception as e:
                    doc, err = None, f"Invalid JSON: {e}"
            else:
                doc, err = normalize_linux_auth_line(line)

        elif source_type == "windows_security":
            doc, err = normalize_windows_security_line(line)

        elif source_type == "firewall":
            doc, err = normalize_firewall_line(line)
        else:
            doc, err = None, f"Unsupported source type: {source_type}"

        if doc:
            doc_id = compute_deterministic_id(source_type, line)
            events.append({"_id": doc_id, "_source": doc})
        else:
            skipped.append({"line_number": line_num, "raw": line.strip()[:120], "reason": err})

    return events, skipped
