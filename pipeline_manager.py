"""
Pipeline Manager for SIEM Log Correlation Engine.
Provides background ingestion watcher (./incoming) and background correlation scheduler.
Enforces concurrency locking, deduplication, state tracking for pipeline health,
and optional webhook dispatch for critical alerts.
Logs strictly counts and durations, never file names or raw log contents.
"""

import os
import sys
import time
import json
import logging
import asyncio
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import urllib.request
import urllib.error

import config
import collector
import correlate
from storage import get_es_client, initialize_indices, MockElasticsearch

logger = logging.getLogger(__name__)


class PipelineManager:
    """Manages the automatic collector watcher and correlation scheduler."""

    def __init__(self):
        self.collector_running: bool = False
        self.scheduler_running: bool = False
        self.last_event_ingested_at: Optional[str] = None
        self.last_correlation_at: Optional[str] = None
        self.last_alert_raised_at: Optional[str] = None
        self.new_events_since_last_run: bool = False
        self._lock: Optional[asyncio.Lock] = None
        self._stop_event: Optional[asyncio.Event] = None
        self._collector_task: Optional[asyncio.Task] = None
        self._scheduler_task: Optional[asyncio.Task] = None

    def initialize_timestamps_from_es(self, es: Any = None):
        """Initializes existing timestamps from ES documents if available."""
        if es is None:
            es = get_es_client()
        try:
            if es.indices.exists(index=config.INDEX_EVENTS):
                res = es.search(
                    index=config.INDEX_EVENTS,
                    query={"match_all": {}},
                    sort=[{"timestamp": {"order": "desc"}}],
                    size=1
                )
                hits = res.get("hits", {}).get("hits", [])
                if hits:
                    ts = hits[0].get("_source", {}).get("timestamp")
                    if ts:
                        self.last_event_ingested_at = ts
        except Exception as e:
            logger.debug("Could not initialize event timestamp from ES: %s", e)

        try:
            if es.indices.exists(index=config.INDEX_ALERTS):
                res = es.search(
                    index=config.INDEX_ALERTS,
                    query={"match_all": {}},
                    sort=[{"created_at": {"order": "desc"}}],
                    size=1
                )
                hits = res.get("hits", {}).get("hits", [])
                if hits:
                    ts = hits[0].get("_source", {}).get("created_at") or hits[0].get("_source", {}).get("first_seen")
                    if ts:
                        self.last_alert_raised_at = ts
        except Exception as e:
            logger.debug("Could not initialize alert timestamp from ES: %s", e)

    def record_event_ingest(self, count: int = 1):
        """Record an ingestion event timestamp and flag new data for correlation."""
        self.last_event_ingested_at = datetime.now(timezone.utc).isoformat()
        if count > 0:
            self.new_events_since_last_run = True

    def record_correlation_run(self, alerts: List[Dict[str, Any]]):
        """Record a correlation cycle timestamp and update alert raised timestamp if new alerts exist."""
        self.last_correlation_at = datetime.now(timezone.utc).isoformat()
        self.new_events_since_last_run = False
        if alerts:
            self.last_alert_raised_at = datetime.now(timezone.utc).isoformat()
            self._dispatch_webhooks_for_critical_alerts(alerts)

    def reset_state(self):
        """Reset state tracking when pipeline data is cleared."""
        self.last_event_ingested_at = None
        self.last_alert_raised_at = None
        self.new_events_since_last_run = False

    def _dispatch_webhooks_for_critical_alerts(self, alerts: List[Dict[str, Any]]):
        """Sends webhook notifications for Critical alerts if WEBHOOK_URL is configured."""
        webhook_url = (config.WEBHOOK_URL or "").strip()
        if not webhook_url:
            return

        critical_alerts = [a for a in alerts if str(a.get("severity", "")).lower() == "critical"]
        if not critical_alerts:
            return

        for alert in critical_alerts:
            try:
                payload = {
                    "event": "critical_alert",
                    "rule_name": alert.get("rule_name"),
                    "severity": alert.get("severity"),
                    "user": alert.get("user"),
                    "host": alert.get("host"),
                    "source_ip": alert.get("source_ip") or alert.get("src_ip"),
                    "created_at": alert.get("created_at"),
                    "description": alert.get("description")
                }
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(
                    webhook_url,
                    data=data,
                    headers={"Content-Type": "application/json", "User-Agent": "SIEM-Correlation-Engine/1.0"}
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    logger.info("Dispatched critical alert webhook to %s (status %d)", webhook_url, resp.status)
            except Exception as e:
                logger.warning("Failed to dispatch webhook for critical alert: %s", e)

    def get_health(self, es: Any = None) -> Dict[str, Any]:
        """Returns health metadata for GET /api/pipeline-health."""
        if es is None:
            es = get_es_client()

        is_mock = isinstance(es, MockElasticsearch)
        try:
            connected = es.ping()
            es_status = "connected" if connected else "disconnected"
        except Exception:
            connected = False
            es_status = "disconnected"

        try:
            events_cnt = es.count(index=config.INDEX_EVENTS)["count"]
        except Exception:
            events_cnt = 0

        try:
            alerts_cnt = es.count(index=config.INDEX_ALERTS)["count"]
        except Exception:
            alerts_cnt = 0

        return {
            "collector_running": self.collector_running,
            "scheduler_running": self.scheduler_running,
            "collector_poll_seconds": config.COLLECTOR_POLL_SECONDS,
            "correlation_interval_seconds": config.CORRELATION_INTERVAL_SECONDS,
            "last_event_ingested_at": self.last_event_ingested_at,
            "last_correlation_at": self.last_correlation_at,
            "last_alert_raised_at": self.last_alert_raised_at,
            "elasticsearch_status": es_status,
            "events_count": events_cnt,
            "alerts_count": alerts_cnt
        }

    async def _collector_watcher_loop(self):
        """Watches ./incoming folder, ingesting and archiving files passively."""
        logger.info("Collector watcher started: polling %s every %ds", config.INCOMING_DIR, config.COLLECTOR_POLL_SECONDS)
        self.collector_running = True
        try:
            while not self._stop_event.is_set():
                try:
                    # Run collect_incoming in background thread to avoid blocking event loop
                    es = get_es_client()
                    results = await asyncio.to_thread(collector.collect_incoming, config.INCOMING_DIR, es)
                    if results:
                        total_indexed = sum(r.get("indexed_count", r.get("events_parsed", 0)) for r in results if "error" not in r)
                        if total_indexed > 0:
                            self.record_event_ingest(count=total_indexed)
                            try:
                                es.indices.refresh(index=config.INDEX_EVENTS)
                            except Exception:
                                pass
                except Exception as e:
                    logger.error("Collector watcher cycle error: %s", e)

                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=config.COLLECTOR_POLL_SECONDS)
                except asyncio.TimeoutError:
                    pass
        except asyncio.CancelledError:
            pass
        finally:
            self.collector_running = False
            logger.info("Collector watcher stopped.")

    async def _correlation_scheduler_loop(self):
        """Periodically triggers correlation rules if new events have arrived."""
        logger.info("Correlation scheduler started: interval %ds", config.CORRELATION_INTERVAL_SECONDS)
        self.scheduler_running = True
        try:
            while not self._stop_event.is_set():
                try:
                    await asyncio.wait_for(self._stop_event.wait(), timeout=config.CORRELATION_INTERVAL_SECONDS)
                    break
                except asyncio.TimeoutError:
                    pass

                if not self.new_events_since_last_run:
                    # Skip cycle if nothing new was ingested since last run
                    continue

                if self._lock is None:
                    self._lock = asyncio.Lock()

                if self._lock.locked():
                    logger.debug("Skipping correlation cycle: previous run still active.")
                    continue

                async with self._lock:
                    if not self.new_events_since_last_run:
                        continue

                    start_time = time.perf_counter()
                    es = get_es_client()
                    try:
                        alerts = await asyncio.to_thread(
                            correlate.run_correlation,
                            es,
                            config.INDEX_EVENTS,
                            config.INDEX_ALERTS
                        )
                        try:
                            es.indices.refresh(index=config.INDEX_ALERTS)
                        except Exception:
                            pass

                        duration = time.perf_counter() - start_time
                        self.record_correlation_run(alerts)
                        # Log ONLY counts and durations, never file names or log contents
                        logger.info("Correlation cycle executed in %.3fs: %d alerts evaluated", duration, len(alerts))
                    except Exception as e:
                        logger.error("Background correlation run failed: %s", e)

        except asyncio.CancelledError:
            pass
        finally:
            self.scheduler_running = False
            logger.info("Correlation scheduler stopped.")

    async def start(self):
        """Starts background tasks."""
        self._stop_event = asyncio.Event()
        self._lock = asyncio.Lock()
        self.initialize_timestamps_from_es()

        if config.ENABLE_COLLECTOR:
            self._collector_task = asyncio.create_task(self._collector_watcher_loop())

        if config.ENABLE_SCHEDULER:
            self._scheduler_task = asyncio.create_task(self._correlation_scheduler_loop())

    async def stop(self):
        """Stops background tasks gracefully."""
        if self._stop_event:
            self._stop_event.set()

        for task in (self._collector_task, self._scheduler_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass

        self.collector_running = False
        self.scheduler_running = False


# Global singleton instance
pipeline_manager = PipelineManager()
