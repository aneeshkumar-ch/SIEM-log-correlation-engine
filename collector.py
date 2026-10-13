"""
Collector Service for SIEM Correlation Engine (BCSSL Lab 07).
Emulates Beats / Logstash agent ingestion safely without interacting with host OS logs.
Collects telemetry passively from web uploads and the ./incoming directory,
forwards to normalizer, and indexes into Elasticsearch with deterministic deduplication.
"""

import sys
import logging
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import config
import normalizer
from storage import get_es_client, initialize_indices, bulk_index_events

logger = logging.getLogger(__name__)


def detect_source_type_from_filename(filename: str) -> str:
    """Infers source type from filename patterns, or defaults to windows_sysmon."""
    f = filename.lower()
    if any(k in f for k in ("win", "sysmon", "security")):
        return "windows_sysmon"
    if any(k in f for k in ("linux", "audit", "auth", "sshd", "sudo")):
        return "linux_auditd"
    if any(k in f for k in ("firewall", "fw", "net", "ufw", "iptables")):
        return "network_firewall"
    return "windows_sysmon"


def collect_file(
    file_path: Path,
    source_type: Optional[str] = None,
    es: Any = None
) -> Dict[str, Any]:
    """Ingests a file passively as plain data, parses with normalizer, and indexes into Elasticsearch.
    Never evaluates or executes file contents.
    Reports line-number skips and deduplicates via deterministic SHA-256 IDs.
    """
    if es is None:
        es = get_es_client()
    initialize_indices(es)

    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")

    # Read strictly as passive bytes
    raw_bytes = file_path.read_bytes()
    try:
        content_str = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_str = raw_bytes.decode("latin-1", errors="replace")

    chosen_source = source_type or detect_source_type_from_filename(file_path.name)

    # Normalize content
    events, skipped = normalizer.normalize_content(content_str, chosen_source)

    # Bulk index into security-events with deterministic IDs
    indexed_count = bulk_index_events(es, events, config.INDEX_EVENTS)

    return {
        "file_name": file_path.name,
        "source_type": chosen_source,
        "events_parsed": len(events),
        "skipped_count": len(skipped),
        "skipped_lines": skipped,
        "indexed_count": indexed_count
    }


def collect_incoming(incoming_dir: Path = config.INCOMING_DIR, es: Any = None) -> List[Dict[str, Any]]:
    """Scans ./incoming directory for telemetry files, ingests them, and archives them.
    Never collects from the host system.
    """
    if es is None:
        es = get_es_client()
    initialize_indices(es)

    processed_dir = incoming_dir / "processed"
    processed_dir.mkdir(exist_ok=True)

    results = []
    for file_path in incoming_dir.iterdir():
        if not file_path.is_file() or file_path.name.startswith("."):
            continue
        if file_path.suffix.lower() not in config.ALLOWED_EXTENSIONS:
            continue

        try:
            res = collect_file(file_path, es=es)
            results.append(res)
            # Move to processed subdirectory to prevent reprocessing
            target_path = processed_dir / file_path.name
            shutil.move(str(file_path), str(target_path))
            logger.info("Collector processed and archived %s", file_path.name)
        except Exception as e:
            logger.error("Error processing %s: %s", file_path.name, e)
            results.append({
                "file_name": file_path.name,
                "error": str(e)
            })

    return results


if __name__ == "__main__":
    print("=" * 60)
    print("  COLLECTOR: SCANNING ./incoming DIRECTORY")
    print("=" * 60)
    res = collect_incoming()
    if not res:
        print("  No new files found in ./incoming")
    else:
        for r in res:
            if "error" in r:
                print(f"  [!] {r['file_name']}: Error - {r['error']}")
            else:
                print(f"  [+] {r['file_name']}: {r['events_parsed']} events parsed, {r['skipped_count']} skipped.")
    print("=" * 60)
