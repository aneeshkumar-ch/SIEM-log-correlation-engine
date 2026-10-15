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


def detect_source_type_from_filename(filename: str) -> Optional[str]:
    """Infers source type from filename patterns, or returns None if unclassifiable."""
    f = filename.lower()
    if any(k in f for k in ("win", "sysmon", "security")):
        return "windows_sysmon"
    if any(k in f for k in ("auth", "sshd")):
        return "linux_auth"
    if any(k in f for k in ("linux", "audit", "sudo")):
        return "linux_auditd"
    if any(k in f for k in ("firewall", "fw", "net", "ufw", "iptables")):
        return "network_firewall"
    return None


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

    chosen_source = source_type or detect_source_type_from_filename(file_path.name)
    if not chosen_source:
        raise ValueError(f"Unclassifiable log file: cannot determine source type for {file_path.name}")

    # Read strictly as passive bytes
    raw_bytes = file_path.read_bytes()
    try:
        content_str = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        content_str = raw_bytes.decode("latin-1", errors="replace")

    # Normalize content
    events, skipped = normalizer.normalize_content(content_str, chosen_source)

    # Bulk index into security-events with deterministic IDs
    indexed_count = bulk_index_events(es, events, config.INDEX_EVENTS)
    try:
        es.indices.refresh(index=config.INDEX_EVENTS)
    except Exception:
        pass

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
    Unclassifiable files or disallowed extensions are moved to ./incoming/rejected.
    Never collects from the host system.
    """
    if es is None:
        es = get_es_client()
    initialize_indices(es)

    archive_dir = incoming_dir / "archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    rejected_dir = incoming_dir / "rejected"
    rejected_dir.mkdir(parents=True, exist_ok=True)

    results = []
    rejected_count = 0
    for file_path in incoming_dir.iterdir():
        if not file_path.is_file() or file_path.name.startswith("."):
            continue

        # Check allowed extension and source type classification
        is_disallowed_ext = file_path.suffix.lower() not in config.ALLOWED_EXTENSIONS
        detected_source = detect_source_type_from_filename(file_path.name)

        if is_disallowed_ext or detected_source is None:
            target_path = rejected_dir / file_path.name
            shutil.move(str(file_path), str(target_path))
            rejected_count += 1
            continue

        try:
            res = collect_file(file_path, source_type=detected_source, es=es)
            results.append(res)
            # Move to archive subdirectory to prevent reprocessing
            target_path = archive_dir / file_path.name
            shutil.move(str(file_path), str(target_path))
            logger.info("Collector processed and archived %s into %s", file_path.name, archive_dir.name)
        except Exception as e:
            logger.error("Error processing %s: %s", file_path.name, e)
            target_path = rejected_dir / file_path.name
            shutil.move(str(file_path), str(target_path))
            rejected_count += 1
            results.append({
                "file_name": file_path.name,
                "error": str(e)
            })

    if rejected_count > 0:
        logger.warning("Collector rejected %d unclassifiable file(s)", rejected_count)

    if results:
        try:
            es.indices.refresh(index=config.INDEX_EVENTS)
        except Exception:
            pass

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
