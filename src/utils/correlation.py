#!/usr/bin/env python3
"""
Honeyclaw Log Correlation Module

Generates and tracks session correlation IDs for linking multi-step attacks
across services and time windows. A single attacker connecting from the same IP
to multiple honeypot services (SSH, API, enterprise-sim) within a configurable
time window will receive the same correlation ID, enabling attack-chain analysis.

Features:
- Session correlation ID generation on first connection
- Propagation across all events from same source IP within a time window
- Attack chain tracking across services (port scan -> SSH -> API exploit)
- Immutable log metadata

Environment variables:
    HONEYCLAW_CORRELATION_WINDOW  - Time window for correlating events (default: 3600)
    HONEYCLAW_LOG_IMMUTABLE       - Enable immutable log metadata (default: true)
    CORRELATION_CLEANUP_SECONDS   - Cleanup interval for expired entries (default: 300)
"""

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple


# Default correlation window: 1 hour
DEFAULT_WINDOW_SECONDS = 3600
# Cleanup expired entries every 5 minutes
DEFAULT_CLEANUP_SECONDS = 300


@dataclass
class CorrelationSession:
    """Tracks a correlated session across events."""
    correlation_id: str
    source_ip: str
    first_seen: float
    last_seen: float
    event_count: int = 0
    services: Set[str] = field(default_factory=set)
    event_types: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "source_ip": self.source_ip,
            "first_seen": datetime.fromtimestamp(self.first_seen, timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen, timezone.utc).isoformat(),
            "duration_seconds": round(self.last_seen - self.first_seen, 1),
            "event_count": self.event_count,
            "services": list(self.services),
            "event_types": self.event_types[-20:],  # Last 20 event types
        }


class CorrelationEngine:
    """
    Generates and manages correlation IDs for tracking multi-step attacks.

    When a new source IP is seen, a correlation ID is generated.
    All subsequent events from that IP within the correlation window
    receive the same correlation ID, enabling attack chain reconstruction.

    Thread-safe for concurrent honeypot services.
    """

    def __init__(
        self,
        correlation_window: Optional[int] = None,
        cleanup_seconds: Optional[int] = None,
        honeypot_id: Optional[str] = None,
    ):
        self.correlation_window = int(
            os.environ.get("HONEYCLAW_CORRELATION_WINDOW", str(correlation_window or DEFAULT_WINDOW_SECONDS))
        )
        self.cleanup_seconds = cleanup_seconds or int(
            os.environ.get("CORRELATION_CLEANUP_SECONDS", DEFAULT_CLEANUP_SECONDS)
        )
        self.honeypot_id = honeypot_id or os.environ.get("HONEYPOT_ID", "honeyclaw")

        # Map: source_ip -> CorrelationSession
        self._sessions: Dict[str, CorrelationSession] = {}
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

    def get_correlation_id(
        self,
        source_ip: str,
        event_type: str = "",
        service: str = "",
    ) -> str:
        """
        Get or create a correlation ID for the given source IP.

        If an active correlation exists within the time window, it is reused
        and the last-seen timestamp is updated. Otherwise a new correlation
        ID is generated.

        Args:
            source_ip: The source IP address of the attacker.
            event_type: The event type for tracking.
            service: The service name (ssh, api, etc.)

        Returns:
            A correlation ID string (prefixed with 'corr_').
        """
        now = time.time()

        with self._lock:
            session = self._sessions.get(source_ip)

            if session and (now - session.last_seen) <= self.correlation_window:
                # Still within window — reuse and update
                session.last_seen = now
                session.event_count += 1
                if service:
                    session.services.add(service)
                if event_type:
                    session.event_types.append(event_type)
                self._stats["correlations_reused"] += 1
                return session.correlation_id
            else:
                # Window expired or new IP — create new session
                if session:
                    self._stats["correlations_expired"] += 1

                corr_id = self._generate_id(source_ip, now)
                new_session = CorrelationSession(
                    correlation_id=corr_id,
                    source_ip=source_ip,
                    first_seen=now,
                    last_seen=now,
                    event_count=1,
                    services={service} if service else set(),
                    event_types=[event_type] if event_type else [],
                )
                self._sessions[source_ip] = new_session
                self._stats["correlations_created"] += 1
                return corr_id

    def enrich_event(
        self,
        event: Dict[str, Any],
        event_type: str = "",
        service: str = "",
    ) -> Dict[str, Any]:
        """
        Enrich an event with correlation metadata.

        Adds:
        - session_correlation_id
        - correlation_event_sequence (event number in session)
        - log_integrity (hash if immutability enabled)
        - log_timestamp

        Args:
            event: The event dict (modified in-place)
            event_type: The event type
            service: The service name

        Returns:
            The enriched event dict
        """
        source_ip = event.get("source_ip") or event.get("ip") or event.get("client_ip", "")

        if source_ip:
            corr_id = self.get_correlation_id(source_ip, event_type, service)
            event["session_correlation_id"] = corr_id

            with self._lock:
                session = self._sessions.get(source_ip)
                if session:
                    event["correlation_event_sequence"] = session.event_count

        # Add immutable log metadata
        if os.environ.get("HONEYCLAW_LOG_IMMUTABLE", "true").lower() == "true":
            event["log_integrity"] = self._compute_integrity_hash(event)
            event["log_timestamp"] = datetime.now(timezone.utc).isoformat()

        return event

    def get_session(self, source_ip: str) -> Optional[CorrelationSession]:
        """Get the current correlation session for an IP."""
        with self._lock:
            return self._sessions.get(source_ip)

    def get_session_info(self, source_ip: str) -> Optional[Dict[str, Any]]:
        """
        Get correlation session info for a source IP.

        Returns:
            Dict with session info, or None if no active session exists.
        """
        now = time.time()

        with self._lock:
            session = self._sessions.get(source_ip)
            if not session:
                return None

            if (now - session.last_seen) > self.correlation_window:
                return None

            info = session.to_dict()
            info["window_remaining_seconds"] = round(
                self.correlation_window - (now - session.last_seen), 2
            )
            return info

    def get_active_sessions(self) -> List[CorrelationSession]:
        """Get all active correlation sessions as a list."""
        now = time.time()
        with self._lock:
            return [
                s for s in self._sessions.values()
                if (now - s.last_seen) < self.correlation_window
            ]

    def get_stats(self) -> Dict[str, Any]:
        """Get correlation engine statistics."""
        now = time.time()
        with self._lock:
            active = sum(
                1 for s in self._sessions.values()
                if (now - s.last_seen) < self.correlation_window
            )
            total_events = sum(s.event_count for s in self._sessions.values())
            multi_service = sum(
                1 for s in self._sessions.values()
                if len(s.services) > 1
            )

        return {
            **self._stats,
            "active_sessions": active,
            "total_sessions": len(self._sessions),
            "total_events_correlated": total_events,
            "multi_service_sessions": multi_service,
            "correlation_window_seconds": self.correlation_window,
        }

    def shutdown(self):
        """Stop the background cleanup thread."""
        self._stop_event.set()

    def cleanup_expired(self):
        """Remove expired sessions (alias for _cleanup)."""
        self._cleanup()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _generate_id(self, source_ip: str, timestamp: float) -> str:
        """Generate a deterministic-looking but unique correlation ID."""
        raw = f"{self.honeypot_id}:{source_ip}:{timestamp}:{uuid.uuid4().hex[:8]}"
        digest = hashlib.sha256(raw.encode()).hexdigest()[:16]
        return f"corr_{digest}"

    def _cleanup_loop(self):
        """Periodically remove expired sessions."""
        while not self._stop_event.wait(self.cleanup_seconds):
            self._cleanup()

    def _cleanup(self):
        """Remove sessions that have exceeded the time window (with buffer)."""
        now = time.time()
        expired = []

        with self._lock:
            for ip, session in self._sessions.items():
                # Keep sessions for 2x the window before cleanup
                if (now - session.last_seen) > (self.correlation_window * 2):
                    expired.append(ip)

            for ip in expired:
                del self._sessions[ip]

    @staticmethod
    def _compute_integrity_hash(event: Dict[str, Any]) -> str:
        """
        Compute an integrity hash for the event.

        This hash can be used to verify the event hasn't been tampered with.
        Excludes the hash field itself and mutable metadata.
        """
        # Create a copy without integrity-specific fields
        hashable = {
            k: v for k, v in event.items()
            if k not in ("log_integrity", "log_timestamp")
        }
        try:
            raw = json.dumps(hashable, sort_keys=True, default=str)
            return hashlib.sha256(raw.encode()).hexdigest()[:32]
        except Exception:
            return ""


# --- Singleton ---

_default_engine: Optional[CorrelationEngine] = None
_init_lock = threading.Lock()


def get_correlation_engine() -> CorrelationEngine:
    """Get or create the default CorrelationEngine singleton."""
    global _default_engine
    if _default_engine is None:
        with _init_lock:
            if _default_engine is None:
                _default_engine = CorrelationEngine()
    return _default_engine


# Alias for compatibility
def get_correlation_manager() -> CorrelationEngine:
    """Alias for get_correlation_engine() for compatibility."""
    return get_correlation_engine()


def get_correlation_id(source_ip: str) -> str:
    """Convenience function: get/create a correlation ID for the source IP."""
    return get_correlation_engine().get_correlation_id(source_ip)


def correlate_event(
    event: Dict[str, Any],
    event_type: str = "",
    service: str = "",
) -> Dict[str, Any]:
    """Convenience function to enrich an event with correlation data."""
    return get_correlation_engine().enrich_event(event, event_type, service)
