#!/usr/bin/env python3
"""
Tests for immutable log storage and the enhanced logging pipeline.
Tests work without AWS credentials or S3 access.
"""

import json
import os
import tempfile
import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.integrations.immutable_storage import ImmutableStorageConfig, ImmutableLogStore
from src.logging.backup import BackupStream, _FileBackend
from src.logging.pipeline import enrich_event


class TestImmutableStorageConfig:
    """Tests for ImmutableStorageConfig."""

    def test_default_config(self):
        """Default config has sensible defaults."""
        config = ImmutableStorageConfig()
        assert config.bucket == ""
        assert config.region == "us-east-1"
        assert config.retention_days == 90
        assert config.retention_mode == "COMPLIANCE"
        assert config.versioning_enabled is True
        assert config.compress is True

    def test_from_env(self):
        """Config loads from environment variables."""
        env = {
            "IMMUTABLE_S3_BUCKET": "my-logs-bucket",
            "IMMUTABLE_S3_REGION": "eu-west-1",
            "IMMUTABLE_RETENTION_DAYS": "180",
            "IMMUTABLE_RETENTION_MODE": "GOVERNANCE",
        }
        with patch.dict(os.environ, env, clear=False):
            config = ImmutableStorageConfig.from_env()

        assert config.bucket == "my-logs-bucket"
        assert config.region == "eu-west-1"
        assert config.retention_days == 180
        assert config.retention_mode == "GOVERNANCE"


class TestImmutableLogStore:
    """Tests for ImmutableLogStore."""

    def test_disabled_without_bucket(self):
        """Store is disabled when no bucket is configured."""
        config = ImmutableStorageConfig(bucket="")
        store = ImmutableLogStore(config=config)
        assert not store.enabled

    def test_store_event_noop_when_disabled(self):
        """store_event is a no-op when disabled."""
        config = ImmutableStorageConfig(bucket="")
        store = ImmutableLogStore(config=config)
        # Should not raise
        store.store_event({"event": "test"})

    def test_stats_when_disabled(self):
        """Stats return correctly when store is disabled."""
        config = ImmutableStorageConfig(bucket="")
        store = ImmutableLogStore(config=config)
        stats = store.get_stats()
        assert stats["enabled"] is False
        assert stats["events_buffered"] == 0


class TestFileBackend:
    """Tests for the file backup backend."""

    def test_file_backend_ships_events(self):
        """File backend writes events to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "backup.jsonl")
            with patch.dict(os.environ, {"BACKUP_FILE_PATH": log_path}):
                backend = _FileBackend()
                assert backend.available

                events = [
                    {"event": "test1", "ip": "1.2.3.4"},
                    {"event": "test2", "ip": "5.6.7.8"},
                ]
                shipped = backend.ship(events)
                assert shipped == 2

                # Verify written content
                with open(log_path) as f:
                    lines = f.readlines()
                assert len(lines) == 2
                assert json.loads(lines[0])["event"] == "test1"
                assert json.loads(lines[1])["event"] == "test2"

    def test_file_backend_rotation(self):
        """File backend rotates when file exceeds max size."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "backup.jsonl")

            # Create a file that's "too large"
            with open(log_path, "w") as f:
                f.write("x" * 200)

            with patch.dict(os.environ, {
                "BACKUP_FILE_PATH": log_path,
                "BACKUP_FILE_MAX_MB": "0",  # 0 MB = always rotate
            }):
                backend = _FileBackend()
                backend.max_bytes = 100  # Override for test
                backend._maybe_rotate()

                # Original should be gone, rotated to .jsonl.1
                assert not os.path.exists(log_path)
                assert os.path.exists(log_path.replace(".jsonl", ".jsonl.1"))


class TestBackupStream:
    """Tests for BackupStream."""

    def test_disabled_by_default(self):
        """Backup stream is disabled by default."""
        stream = BackupStream()
        assert not stream.enabled

    def test_send_noop_when_disabled(self):
        """send() is a no-op when disabled."""
        stream = BackupStream()
        stream.send({"event": "test"})
        assert stream._stats["events_received"] == 0


class TestEnrichEvent:
    """Tests for the enrich_event function."""

    def test_adds_correlation_id(self):
        """enrich_event adds a correlation_id."""
        event = {"ip": "203.0.113.50", "event": "login_attempt"}
        enriched = enrich_event(event)

        assert "correlation_id" in enriched
        assert enriched["correlation_id"].startswith("corr_")

    def test_same_ip_same_correlation(self):
        """Same IP gets the same correlation ID."""
        event1 = {"ip": "203.0.113.51", "event": "connection"}
        event2 = {"ip": "203.0.113.51", "event": "login_attempt"}

        enriched1 = enrich_event(event1)
        enriched2 = enrich_event(event2)

        assert enriched1["correlation_id"] == enriched2["correlation_id"]

    def test_different_ips_different_correlation(self):
        """Different IPs get different correlation IDs."""
        event1 = {"ip": "198.51.100.1", "event": "connection"}
        event2 = {"ip": "198.51.100.2", "event": "connection"}

        enriched1 = enrich_event(event1)
        enriched2 = enrich_event(event2)

        assert enriched1["correlation_id"] != enriched2["correlation_id"]

    def test_source_ip_parameter_takes_precedence(self):
        """Explicit source_ip parameter overrides event dict IP."""
        event = {"ip": "10.0.0.1", "event": "test"}
        enriched = enrich_event(event, source_ip="10.0.0.2")

        # Should have used 10.0.0.2 for correlation
        corr_id = enriched["correlation_id"]

        # Verify by checking what 10.0.0.2 would get
        event2 = {"ip": "10.0.0.2", "event": "test2"}
        enriched2 = enrich_event(event2)
        assert enriched2["correlation_id"] == corr_id

    def test_localhost_not_enriched(self):
        """Localhost IPs don't get correlation IDs."""
        event = {"ip": "127.0.0.1", "event": "test"}
        enriched = enrich_event(event)
        assert "correlation_id" not in enriched

    def test_unknown_ip_not_enriched(self):
        """Unknown IPs don't get correlation IDs."""
        event = {"ip": "unknown", "event": "test"}
        enriched = enrich_event(event)
        assert "correlation_id" not in enriched

    def test_no_ip_no_enrichment(self):
        """Events without an IP are not enriched."""
        event = {"event": "startup"}
        enriched = enrich_event(event)
        assert "correlation_id" not in enriched

    def test_preserves_existing_correlation_id(self):
        """Existing correlation_id in event is preserved."""
        event = {
            "ip": "203.0.113.99",
            "event": "test",
            "correlation_id": "corr_existing123456",
        }
        enriched = enrich_event(event)
        assert enriched["correlation_id"] == "corr_existing123456"

    def test_enriches_in_place(self):
        """enrich_event modifies the event dict in place."""
        event = {"ip": "203.0.113.60", "event": "test"}
        enriched = enrich_event(event)
        assert event is enriched  # Same object


class TestRecordingMetadataCorrelation:
    """Tests for correlation ID in RecordingMetadata."""

    def test_metadata_includes_correlation_id(self):
        """RecordingMetadata includes correlation_id field."""
        from src.replay.recorder import RecordingMetadata

        meta = RecordingMetadata(
            session_id="test-123",
            protocol="ssh",
            source_ip="10.0.0.1",
            source_port=12345,
            dest_port=22,
            start_time="2026-02-07T00:00:00Z",
            correlation_id="corr_abc123def45678",
        )
        d = meta.to_dict()
        assert d["correlation_id"] == "corr_abc123def45678"

    def test_ssh_recorder_accepts_correlation_id(self):
        """SSHRecorder passes correlation_id to metadata."""
        from src.replay.recorder import SSHRecorder

        recorder = SSHRecorder(
            source_ip="10.0.0.1",
            correlation_id="corr_test123456789",
        )
        assert recorder.metadata.correlation_id == "corr_test123456789"
        recording = recorder.finalize()
        assert recording["metadata"]["correlation_id"] == "corr_test123456789"

    def test_http_recorder_accepts_correlation_id(self):
        """HTTPRecorder passes correlation_id to metadata."""
        from src.replay.recorder import HTTPRecorder

        recorder = HTTPRecorder(
            source_ip="10.0.0.1",
            correlation_id="corr_http123456789",
        )
        assert recorder.metadata.correlation_id == "corr_http123456789"
        recording = recorder.finalize()
        assert recording["metadata"]["correlation_id"] == "corr_http123456789"


class TestHoneypotEventCorrelation:
    """Tests for correlation fields in HoneypotEvent."""

    def test_honeypot_event_has_correlation_id(self):
        """HoneypotEvent includes correlation_id field."""
        from src.integrations.base import HoneypotEvent, EventType

        event = HoneypotEvent(
            timestamp="2026-02-07T00:00:00Z",
            honeypot_id="test",
            source_ip="10.0.0.1",
            event_type=EventType.CONNECTION,
            correlation_id="corr_siem12345678",
        )
        d = event.to_dict()
        assert d["correlation_id"] == "corr_siem12345678"

    def test_honeypot_event_has_extended_geo_fields(self):
        """HoneypotEvent includes extended geo fields."""
        from src.integrations.base import HoneypotEvent, EventType

        event = HoneypotEvent(
            timestamp="2026-02-07T00:00:00Z",
            honeypot_id="test",
            source_ip="10.0.0.1",
            event_type=EventType.CONNECTION,
            geo_country="Germany",
            geo_country_code="DE",
            geo_city="Berlin",
            geo_lat=52.52,
            geo_lon=13.405,
            geo_asn="AS13335",
            geo_asn_org="Cloudflare, Inc.",
        )
        d = event.to_dict()
        assert d["geo_country"] == "Germany"
        assert d["geo_country_code"] == "DE"
        assert d["geo_city"] == "Berlin"
        assert d["geo_lat"] == 52.52
        assert d["geo_lon"] == 13.405
        assert d["geo_asn"] == "AS13335"
        assert d["geo_asn_org"] == "Cloudflare, Inc."
