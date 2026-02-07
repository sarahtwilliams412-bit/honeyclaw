#!/usr/bin/env python3
"""
Honeyclaw Enhanced Logging Pipeline

Unifies correlation IDs, geolocation enrichment, immutable storage, and
backup streams into a single logging pipeline. Designed to be integrated
into existing honeypot templates with minimal code changes.

Usage in templates:

    from src.logging.pipeline import get_enhanced_logger, enrich_event

    # Option 1: Enrich individual events before logging
    event = {'ip': '1.2.3.4', 'event': 'login_attempt', ...}
    enriched = enrich_event(event, source_ip='1.2.3.4')
    # enriched now contains correlation_id, geo_* fields

    # Option 2: Use the enhanced logger (wraps file + stdout + alerts + immutable + backup)
    logger = get_enhanced_logger()
    logger.log_event('login_attempt', {'ip': '1.2.3.4', 'username': 'root'}, source_ip='1.2.3.4')
"""

import json
import logging
import os
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from src.utils.correlation import get_correlation_id, get_correlation_manager
from src.utils.geoip import get_geo_fields, get_geoip_resolver

logger = logging.getLogger("honeyclaw.pipeline")


def enrich_event(
    event: Dict[str, Any],
    source_ip: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Enrich a log event with correlation ID and geolocation data.

    This is the core enrichment function. It can be used standalone to
    add correlation and geo fields to any event dict before logging.

    Args:
        event: The event dict to enrich (modified in-place and returned).
        source_ip: Source IP address. If not provided, looks for 'ip' or
                   'source_ip' keys in the event dict.

    Returns:
        The enriched event dict (same reference as input).
    """
    # Determine source IP
    ip = source_ip or event.get("source_ip") or event.get("ip")

    if ip and ip not in ("unknown", "127.0.0.1", "::1"):
        # Add correlation ID
        if "correlation_id" not in event:
            event["correlation_id"] = get_correlation_id(ip)

        # Add geolocation
        geo_fields = get_geo_fields(ip)
        for key, value in geo_fields.items():
            if key not in event:
                event[key] = value

    return event


class EnhancedLogger:
    """
    Enhanced logging pipeline that wraps standard log output with correlation
    IDs, geolocation, immutable storage, and backup streams.

    Designed as a drop-in enhancement for existing template `log_event()`
    functions.
    """

    def __init__(
        self,
        log_path: Optional[str] = None,
        honeypot_id: Optional[str] = None,
        enable_immutable: bool = True,
        enable_backup: bool = True,
    ):
        self.log_path = Path(
            log_path or os.environ.get("LOG_PATH", "/var/log/honeypot/events.json")
        )
        self.honeypot_id = honeypot_id or os.environ.get("HONEYPOT_ID", "honeyclaw")

        # Immutable storage (lazy init)
        self._immutable_store = None
        self._enable_immutable = enable_immutable

        # Backup stream (lazy init)
        self._backup_stream = None
        self._enable_backup = enable_backup

        # Ensure log directory exists
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    @property
    def immutable_store(self):
        """Lazy-init immutable store."""
        if self._immutable_store is None and self._enable_immutable:
            try:
                from src.integrations.immutable_storage import ImmutableLogStore
                self._immutable_store = ImmutableLogStore()
            except Exception as e:
                logger.debug(f"Immutable storage not available: {e}")
                self._enable_immutable = False
        return self._immutable_store

    @property
    def backup_stream(self):
        """Lazy-init backup stream."""
        if self._backup_stream is None and self._enable_backup:
            try:
                from src.logging.backup import get_backup_stream
                self._backup_stream = get_backup_stream()
            except Exception as e:
                logger.debug(f"Backup stream not available: {e}")
                self._enable_backup = False
        return self._backup_stream

    def log_event(
        self,
        event_type: str,
        data: Dict[str, Any],
        source_ip: Optional[str] = None,
        alert_func=None,
    ) -> Dict[str, Any]:
        """
        Log an event through the full enhanced pipeline.

        1. Add timestamp and event type
        2. Enrich with correlation ID and geolocation
        3. Write to stdout (JSON lines)
        4. Append to log file
        5. Send to immutable storage
        6. Send to backup stream
        7. Forward to alert pipeline (if alert_func provided)

        Args:
            event_type: Event type string (e.g., 'login_attempt').
            data: Event data dict.
            source_ip: Source IP for enrichment.
            alert_func: Optional callable(event, event_type) for alert dispatch.

        Returns:
            The fully enriched event dict.
        """
        # Build event
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "honeypot_id": self.honeypot_id,
            **data,
        }

        # Enrich with correlation ID and geolocation
        enrich_event(event, source_ip=source_ip)

        # Serialize
        line = json.dumps(event, default=str)
        if len(line) > 16384:
            event["_truncated"] = True
            event["_original_length"] = len(line)
            line = json.dumps(event, default=str)[:16384]

        # Write to stdout
        print(line, flush=True)

        # Write to log file
        try:
            with open(self.log_path, "a") as f:
                f.write(line + "\n")
        except Exception as e:
            print(f"Log write error: {e}", file=sys.stderr)

        # Ship to immutable storage
        if self.immutable_store and self.immutable_store.enabled:
            try:
                self.immutable_store.store_event(event)
            except Exception as e:
                logger.debug(f"Immutable store error: {e}")

        # Ship to backup stream
        if self.backup_stream and self.backup_stream.enabled:
            try:
                self.backup_stream.send(event)
            except Exception as e:
                logger.debug(f"Backup stream error: {e}")

        # Forward to alert pipeline
        if alert_func:
            try:
                alert_func(event, event_type)
            except Exception as e:
                print(f"[ALERT] Error: {e}", file=sys.stderr)

        return event

    def get_stats(self) -> Dict[str, Any]:
        """Get pipeline statistics."""
        stats = {
            "correlation": get_correlation_manager().get_stats(),
            "geoip_enabled": get_geoip_resolver().enabled,
        }

        if self.immutable_store:
            stats["immutable_storage"] = self.immutable_store.get_stats()

        if self.backup_stream:
            stats["backup_stream"] = self.backup_stream.get_stats()

        return stats

    def shutdown(self):
        """Flush and shutdown all pipeline components."""
        if self._immutable_store:
            self._immutable_store.shutdown()
        if self._backup_stream:
            self._backup_stream.shutdown()
        get_correlation_manager().shutdown()


# Module-level singleton
_default_logger: Optional[EnhancedLogger] = None
_init_lock = threading.Lock()


def get_enhanced_logger(**kwargs) -> EnhancedLogger:
    """Get or create the default EnhancedLogger singleton."""
    global _default_logger
    if _default_logger is None:
        with _init_lock:
            if _default_logger is None:
                _default_logger = EnhancedLogger(**kwargs)
    return _default_logger
