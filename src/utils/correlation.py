#!/usr/bin/env python3
"""
Honeyclaw Correlation ID Manager

Generates and tracks session correlation IDs for linking multi-step attacks
across services and time windows. A single attacker connecting from the same IP
to multiple honeypot services (SSH, API, enterprise-sim) within a configurable
time window will receive the same correlation ID, enabling attack-chain analysis.

Environment variables:
    CORRELATION_WINDOW_SECONDS  - Time window for correlating events (default: 3600)
    CORRELATION_CLEANUP_SECONDS - Cleanup interval for expired entries (default: 300)
"""

import os
import time
import uuid
import hashlib
import threading
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple


# Default correlation window: 1 hour
DEFAULT_WINDOW_SECONDS = 3600
# Cleanup expired entries every 5 minutes
DEFAULT_CLEANUP_SECONDS = 300


class CorrelationManager:
    """
    Manages correlation IDs that link events from the same attacker across
    services and time windows.

    A correlation ID is generated on first contact from a source IP and reused
    for subsequent events within the configured time window. If the window
    expires, a new correlation ID is generated.

    Thread-safe for concurrent honeypot services.
    """

    def __init__(
        self,
        window_seconds: Optional[int] = None,
        cleanup_seconds: Optional[int] = None,
    ):
        self.window_seconds = window_seconds or int(
            os.environ.get("CORRELATION_WINDOW_SECONDS", DEFAULT_WINDOW_SECONDS)
        )
        self.cleanup_seconds = cleanup_seconds or int(
            os.environ.get("CORRELATION_CLEANUP_SECONDS", DEFAULT_CLEANUP_SECONDS)
        )

        # Map: source_ip -> (correlation_id, last_seen_timestamp, first_seen_timestamp)
        self._sessions: Dict[str, Tuple[str, float, float]] = {}
        self._lock = threading.Lock()

        # Statistics
        self._stats = {
            "correlations_created": 0,
            "correlations_reused": 0,
            "correlations_expired": 0,
        }

        # Background cleanup thread
        self._stop_event = threading.Event()
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, daemon=True
        )
        self._cleanup_thread.start()

    def get_correlation_id(self, source_ip: str) -> str:
        """
        Get or create a correlation ID for the given source IP.

        If an active correlation exists within the time window, it is reused
        and the last-seen timestamp is updated. Otherwise a new correlation
        ID is generated.

        Args:
            source_ip: The source IP address of the attacker.

        Returns:
            A correlation ID string (prefixed with 'corr_').
        """
        now = time.time()

        with self._lock:
            if source_ip in self._sessions:
                corr_id, last_seen, first_seen = self._sessions[source_ip]

                if (now - last_seen) <= self.window_seconds:
                    # Still within window — reuse
                    self._sessions[source_ip] = (corr_id, now, first_seen)
                    self._stats["correlations_reused"] += 1
                    return corr_id
                else:
                    # Window expired — create new
                    self._stats["correlations_expired"] += 1

            # Create new correlation ID
            corr_id = self._generate_id(source_ip, now)
            self._sessions[source_ip] = (corr_id, now, now)
            self._stats["correlations_created"] += 1
            return corr_id

    def get_session_info(self, source_ip: str) -> Optional[Dict[str, Any]]:
        """
        Get correlation session info for a source IP.

        Returns:
            Dict with correlation_id, first_seen, last_seen, duration_seconds,
            or None if no active session exists.
        """
        with self._lock:
            if source_ip not in self._sessions:
                return None

            corr_id, last_seen, first_seen = self._sessions[source_ip]
            now = time.time()

            if (now - last_seen) > self.window_seconds:
                return None

            return {
                "correlation_id": corr_id,
                "source_ip": source_ip,
                "first_seen": datetime.fromtimestamp(
                    first_seen, tz=timezone.utc
                ).isoformat(),
                "last_seen": datetime.fromtimestamp(
                    last_seen, tz=timezone.utc
                ).isoformat(),
                "duration_seconds": round(last_seen - first_seen, 2),
                "window_remaining_seconds": round(
                    self.window_seconds - (now - last_seen), 2
                ),
            }

    def get_active_sessions(self) -> Dict[str, Dict[str, Any]]:
        """Get all active correlation sessions."""
        now = time.time()
        result = {}

        with self._lock:
            for ip, (corr_id, last_seen, first_seen) in self._sessions.items():
                if (now - last_seen) <= self.window_seconds:
                    result[ip] = {
                        "correlation_id": corr_id,
                        "first_seen": datetime.fromtimestamp(
                            first_seen, tz=timezone.utc
                        ).isoformat(),
                        "last_seen": datetime.fromtimestamp(
                            last_seen, tz=timezone.utc
                        ).isoformat(),
                        "duration_seconds": round(last_seen - first_seen, 2),
                    }

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get correlation statistics."""
        with self._lock:
            active = sum(
                1
                for _, (_, last_seen, _) in self._sessions.items()
                if (time.time() - last_seen) <= self.window_seconds
            )

        return {
            **self._stats,
            "active_sessions": active,
            "total_tracked_ips": len(self._sessions),
            "window_seconds": self.window_seconds,
        }

    def shutdown(self):
        """Stop the background cleanup thread."""
        self._stop_event.set()

    def _generate_id(self, source_ip: str, timestamp: float) -> str:
        """Generate a deterministic-looking but unique correlation ID."""
        raw = f"{source_ip}:{timestamp}:{uuid.uuid4().hex}"
        digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return f"corr_{digest}"

    def _cleanup_loop(self):
        """Periodically remove expired sessions."""
        while not self._stop_event.wait(self.cleanup_seconds):
            self._cleanup()

    def _cleanup(self):
        """Remove sessions that have exceeded the time window."""
        now = time.time()
        expired = []

        with self._lock:
            for ip, (_, last_seen, _) in self._sessions.items():
                if (now - last_seen) > self.window_seconds:
                    expired.append(ip)

            for ip in expired:
                del self._sessions[ip]


# Module-level singleton for use across the application
_default_manager: Optional[CorrelationManager] = None
_init_lock = threading.Lock()


def get_correlation_manager() -> CorrelationManager:
    """Get or create the default CorrelationManager singleton."""
    global _default_manager
    if _default_manager is None:
        with _init_lock:
            if _default_manager is None:
                _default_manager = CorrelationManager()
    return _default_manager


def get_correlation_id(source_ip: str) -> str:
    """Convenience function: get/create a correlation ID for the source IP."""
    return get_correlation_manager().get_correlation_id(source_ip)
