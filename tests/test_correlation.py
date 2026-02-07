#!/usr/bin/env python3
"""
Tests for correlation ID generation and management.
"""

import time
import threading
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.correlation import CorrelationManager, get_correlation_id


class TestCorrelationManager:
    """Tests for CorrelationManager."""

    def test_new_ip_gets_correlation_id(self):
        """First connection from an IP generates a new correlation ID."""
        mgr = CorrelationManager(window_seconds=60)
        corr_id = mgr.get_correlation_id("192.168.1.100")
        assert corr_id.startswith("corr_")
        assert len(corr_id) == 21  # "corr_" + 16 hex chars
        mgr.shutdown()

    def test_same_ip_within_window_reuses_id(self):
        """Same IP within the time window gets the same correlation ID."""
        mgr = CorrelationManager(window_seconds=60)
        id1 = mgr.get_correlation_id("10.0.0.1")
        id2 = mgr.get_correlation_id("10.0.0.1")
        assert id1 == id2
        mgr.shutdown()

    def test_different_ips_get_different_ids(self):
        """Different IPs get different correlation IDs."""
        mgr = CorrelationManager(window_seconds=60)
        id1 = mgr.get_correlation_id("10.0.0.1")
        id2 = mgr.get_correlation_id("10.0.0.2")
        assert id1 != id2
        mgr.shutdown()

    def test_expired_window_generates_new_id(self):
        """After the time window expires, a new correlation ID is generated."""
        mgr = CorrelationManager(window_seconds=1)
        id1 = mgr.get_correlation_id("10.0.0.1")
        time.sleep(1.5)
        id2 = mgr.get_correlation_id("10.0.0.1")
        assert id1 != id2
        mgr.shutdown()

    def test_session_info(self):
        """get_session_info returns correct session data."""
        mgr = CorrelationManager(window_seconds=60)
        corr_id = mgr.get_correlation_id("172.16.0.5")
        info = mgr.get_session_info("172.16.0.5")

        assert info is not None
        assert info["correlation_id"] == corr_id
        assert info["source_ip"] == "172.16.0.5"
        assert "first_seen" in info
        assert "last_seen" in info
        assert info["duration_seconds"] >= 0
        assert info["window_remaining_seconds"] > 0
        mgr.shutdown()

    def test_session_info_unknown_ip(self):
        """get_session_info returns None for unknown IP."""
        mgr = CorrelationManager(window_seconds=60)
        info = mgr.get_session_info("1.2.3.4")
        assert info is None
        mgr.shutdown()

    def test_active_sessions(self):
        """get_active_sessions returns all active sessions."""
        mgr = CorrelationManager(window_seconds=60)
        mgr.get_correlation_id("10.0.0.1")
        mgr.get_correlation_id("10.0.0.2")
        mgr.get_correlation_id("10.0.0.3")

        active = mgr.get_active_sessions()
        assert len(active) == 3
        assert "10.0.0.1" in active
        assert "10.0.0.2" in active
        assert "10.0.0.3" in active
        mgr.shutdown()

    def test_stats(self):
        """get_stats returns correct statistics."""
        mgr = CorrelationManager(window_seconds=60)
        mgr.get_correlation_id("10.0.0.1")  # create
        mgr.get_correlation_id("10.0.0.1")  # reuse
        mgr.get_correlation_id("10.0.0.2")  # create

        stats = mgr.get_stats()
        assert stats["correlations_created"] == 2
        assert stats["correlations_reused"] == 1
        assert stats["active_sessions"] == 2
        mgr.shutdown()

    def test_thread_safety(self):
        """Concurrent access from multiple threads works correctly."""
        mgr = CorrelationManager(window_seconds=60)
        results = {}
        errors = []

        def worker(ip):
            try:
                cid = mgr.get_correlation_id(ip)
                results[ip] = cid
            except Exception as e:
                errors.append(str(e))

        threads = []
        for i in range(50):
            ip = f"10.0.0.{i % 10}"
            t = threading.Thread(target=worker, args=(ip,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert not errors
        # Should have exactly 10 unique IPs
        assert len(results) == 10
        mgr.shutdown()

    def test_cleanup_removes_expired(self):
        """Cleanup removes expired sessions."""
        mgr = CorrelationManager(window_seconds=1, cleanup_seconds=100)
        mgr.get_correlation_id("10.0.0.1")
        assert len(mgr._sessions) == 1

        time.sleep(1.5)
        mgr._cleanup()
        assert len(mgr._sessions) == 0
        mgr.shutdown()


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_get_correlation_id(self):
        """Module-level get_correlation_id works."""
        corr_id = get_correlation_id("203.0.113.42")
        assert corr_id.startswith("corr_")
        assert len(corr_id) == 21
