#!/usr/bin/env python3
"""
Honeyclaw Log Correlation Module

Provides correlation IDs for tracking multi-step attacks across services.

Features:
- Session correlation ID generation on first connection
- Propagation across all events from same source IP within a time window
- Attack chain tracking across services (port scan -> SSH -> API exploit)
- Immutable log metadata

Environment variables:
  HONEYCLAW_CORRELATION_WINDOW  - Time window for IP correlation in seconds (default: 3600)
  HONEYCLAW_LOG_IMMUTABLE       - Enable immutable log metadata (default: true)
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
    """

    def __init__(
        self,
        correlation_window: int = 3600,
        honeypot_id: Optional[str] = None,
    ):
        self.correlation_window = int(
            os.environ.get("HONEYCLAW_CORRELATION_WINDOW", str(correlation_window))
        )
        self.honeypot_id = honeypot_id or os.environ.get("HONEYPOT_ID", "honeyclaw")

        self._sessions: Dict[str, CorrelationSession] = {}  # ip -> session
        self._lock = threading.Lock()

    def get_correlation_id(
        self,
        source_ip: str,
        event_type: str = "",
        service: str = "",
    ) -> str:
        """
        Get or create a correlation ID for the given source IP.

        Args:
            source_ip: The source IP address
            event_type: The event type for tracking
            service: The service name (ssh, api, etc.)

        Returns:
            The correlation ID string
        """
        now = time.time()

        with self._lock:
            session = self._sessions.get(source_ip)

            if session and (now - session.last_seen) < self.correlation_window:
                # Update existing session
                session.last_seen = now
                session.event_count += 1
                if service:
                    session.services.add(service)
                if event_type:
                    session.event_types.append(event_type)
                return session.correlation_id
            else:
                # Create new session
                corr_id = self._generate_correlation_id(source_ip, now)
                session = CorrelationSession(
                    correlation_id=corr_id,
                    source_ip=source_ip,
                    first_seen=now,
                    last_seen=now,
                    event_count=1,
                    services={service} if service else set(),
                    event_types=[event_type] if event_type else [],
                )
                self._sessions[source_ip] = session
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
        - immutable_hash (if immutability enabled)

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

    def get_active_sessions(self) -> List[CorrelationSession]:
        """Get all active correlation sessions."""
        now = time.time()
        with self._lock:
            return [
                s for s in self._sessions.values()
                if (now - s.last_seen) < self.correlation_window
            ]

    def cleanup_expired(self):
        """Remove expired sessions."""
        now = time.time()
        with self._lock:
            expired = [
                ip for ip, s in self._sessions.items()
                if (now - s.last_seen) >= self.correlation_window * 2
            ]
            for ip in expired:
                del self._sessions[ip]

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
            "active_sessions": active,
            "total_sessions": len(self._sessions),
            "total_events_correlated": total_events,
            "multi_service_sessions": multi_service,
            "correlation_window_seconds": self.correlation_window,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _generate_correlation_id(self, source_ip: str, timestamp: float) -> str:
        """Generate a deterministic but unique correlation ID."""
        raw = f"{self.honeypot_id}:{source_ip}:{timestamp}:{uuid.uuid4().hex[:8]}"
        return f"corr_{hashlib.sha256(raw.encode()).hexdigest()[:16]}"

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


def get_correlation_engine() -> CorrelationEngine:
    """Get or create the default correlation engine."""
    global _default_engine
    if _default_engine is None:
        _default_engine = CorrelationEngine()
    return _default_engine


def correlate_event(
    event: Dict[str, Any],
    event_type: str = "",
    service: str = "",
) -> Dict[str, Any]:
    """Convenience function to enrich an event with correlation data."""
    return get_correlation_engine().enrich_event(event, event_type, service)
