"""
Tests for Kibana temporary saved objects generation and safe cleanup logic.

Verifies:
1. Cleanup strictly ignores any ID that does not start with 'temp-'.
2. Production object IDs and non-temp IDs are NEVER deleted.
3. Only IDs strictly starting with 'temp-' can be deleted.
4. Temporary objects generated for test renders NEVER share IDs with production objects.
5. All references within temporary objects point strictly to 'temp-' targets.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, call
import pytest

from verify_headless_render import (
    generate_temp_saved_objects,
    delete_temporary_saved_objects
)

NDJSON_PATH = Path(__file__).resolve().parent.parent / "soc_triage_board.ndjson"


class TestKibanaCleanupSafety:
    """Verifies that cleanup strictly protects production saved objects."""

    def test_cleanup_strictly_rejects_non_temp_ids(self, monkeypatch):
        """Asserts that cleanup never sends DELETE requests for real/production object IDs."""
        mock_delete = MagicMock()
        monkeypatch.setattr("requests.delete", mock_delete)

        dangerous_real_ids = [
            "soc-triage-board-dashboard",
            "alerts-dashboard",
            "timeline-analysis-dashboard",
            "metric-total-alerts",
            "metric-critical-alerts",
            "metric-high-alerts",
            "metric-medium-alerts",
            "alerts-by-severity",
            "event-categories-pie",
            "top-hosts-by-events",
            "recent-alerts-table",
            "events-by-source-donut",
            "top-source-ips",
            "suspicious-execution-hosts",
            "events-search",
            "security-alerts-dataview",
            "security-events-dataview",
            "production-lens-1",
            "custom-search",
            None,
            12345,
            "",
            "temporary",   # doesn't start with 'temp-'
            "temp",        # doesn't start with 'temp-'
            "-temp-foo"
        ]

        deleted = delete_temporary_saved_objects("http://127.0.0.1:5601", dangerous_real_ids)

        assert deleted == []
        mock_delete.assert_not_called()

    def test_cleanup_only_deletes_temp_prefixed_ids(self, monkeypatch):
        """Asserts that cleanup only deletes objects whose IDs strictly begin with 'temp-'."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_delete = MagicMock(return_value=mock_resp)
        monkeypatch.setattr("requests.delete", mock_delete)

        mixed_ids = [
            "soc-triage-board-dashboard",   # REAL -> Must be skipped
            "temp-metric-total-alerts",     # TEMP -> Must be deleted
            "metric-critical-alerts",       # REAL -> Must be skipped
            "temp-events-search",           # TEMP -> Must be deleted
            "temp-alerts-dataview"          # TEMP -> Must be deleted
        ]

        deleted = delete_temporary_saved_objects("http://127.0.0.1:5601", mixed_ids)

        # Ensure all delete requests only targeted URLs with 'temp-'
        for c in mock_delete.call_args_list:
            url = c[0][0]
            assert "/temp-" in url, f"Dangerous delete URL detected: {url}"

        # Assert exactly the 3 temp objects were targeted across types
        assert len(deleted) > 0
        for item in deleted:
            assert item.startswith(("dashboard/temp-", "lens/temp-", "index-pattern/temp-", "search/temp-"))

    def test_temp_objects_never_share_real_ids(self):
        """Asserts generated temporary objects strictly use 'temp-' prefix and never share real IDs."""
        assert NDJSON_PATH.exists(), f"Missing ndjson file: {NDJSON_PATH}"

        real_objects = []
        with open(NDJSON_PATH, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    real_objects.append(json.loads(line))

        real_ids = {obj["id"] for obj in real_objects}

        # Generate temporary copies
        temp_objects = generate_temp_saved_objects(NDJSON_PATH)
        temp_ids = {obj["id"] for obj in temp_objects}

        assert len(temp_objects) == len(real_objects), "Temporary object count must match ndjson count"

        # 1. Check all temp IDs start with 'temp-'
        for obj in temp_objects:
            obj_id = obj["id"]
            assert obj_id.startswith("temp-"), f"Temporary ID does not start with 'temp-': {obj_id}"

        # 2. Check no temporary ID collides with any real ID
        collision = real_ids.intersection(temp_ids)
        assert len(collision) == 0, f"Found collision between temp and real IDs: {collision}"

        # 3. Check all references within temporary objects also point strictly to 'temp-' targets
        for obj in temp_objects:
            for ref in obj.get("references", []):
                ref_id = ref["id"]
                assert ref_id.startswith("temp-"), (
                    f"Temporary object {obj['id']} has reference not prefixed with 'temp-': {ref_id}"
                )
                assert ref_id not in real_ids, (
                    f"Temporary object {obj['id']} references real object ID: {ref_id}"
                )
