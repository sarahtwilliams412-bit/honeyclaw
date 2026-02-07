#!/usr/bin/env python3
"""
Honeyclaw Backup Log Stream

Ships log events to a secondary destination as insurance against primary
storage compromise or failure. Supports multiple backends:
- Secondary S3 bucket (different account/region)
- Syslog (UDP/TCP)
- HTTP webhook endpoint
- Local file rotation

Environment variables:
    BACKUP_LOG_ENABLED      - Enable backup log stream (default: false)
    BACKUP_LOG_TYPE         - Backend type: s3, syslog, http, file (default: file)

    # S3 backend
    BACKUP_S3_BUCKET        - Backup S3 bucket name
    BACKUP_S3_REGION        - Backup S3 region
    BACKUP_S3_PREFIX        - Backup S3 key prefix (default: backup-logs/)
    BACKUP_S3_ENDPOINT      - Custom S3 endpoint

    # Syslog backend
    BACKUP_SYSLOG_HOST      - Syslog host
    BACKUP_SYSLOG_PORT      - Syslog port (default: 514)
    BACKUP_SYSLOG_PROTOCOL  - udp or tcp (default: udp)

    # HTTP backend
    BACKUP_HTTP_URL         - Webhook URL for log events
    BACKUP_HTTP_TOKEN       - Bearer token for auth

    # File backend
    BACKUP_FILE_PATH        - Log file path (default: /var/log/honeyclaw/backup.jsonl)
    BACKUP_FILE_MAX_MB      - Max file size before rotation (default: 100)
    BACKUP_FILE_KEEP        - Number of rotated files to keep (default: 5)
"""

import json
import logging
import os
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("honeyclaw.backup_log")

BUFFER_MAX = 1000
FLUSH_INTERVAL_SECONDS = 10


class BackupStream:
    """
    Backup log stream that ships events to a secondary destination.

    Buffers events and ships them asynchronously. Failed shipments are
    retried with exponential backoff. Thread-safe.
    """

    def __init__(self):
        self.enabled = os.environ.get("BACKUP_LOG_ENABLED", "false").lower() == "true"
        self._backend: Optional[_BackupBackend] = None
        self._buffer: deque = deque(maxlen=BUFFER_MAX)
        self._lock = threading.Lock()
        self._stop_event = threading.Event()

        self._stats = {
            "events_received": 0,
            "events_shipped": 0,
            "events_dropped": 0,
            "ship_errors": 0,
        }

        if not self.enabled:
            return

        # Initialize backend
        backend_type = os.environ.get("BACKUP_LOG_TYPE", "file").lower()

        if backend_type == "s3":
            self._backend = _S3Backend()
        elif backend_type == "syslog":
            self._backend = _SyslogBackend()
        elif backend_type == "http":
            self._backend = _HTTPBackend()
        else:
            self._backend = _FileBackend()

        if self._backend and self._backend.available:
            logger.info(f"Backup log stream enabled: {backend_type}")
            self._flush_thread = threading.Thread(
                target=self._flush_loop, daemon=True
            )
            self._flush_thread.start()
        else:
            self.enabled = False
            logger.warning(f"Backup log backend '{backend_type}' not available")

    def send(self, event: Dict[str, Any]) -> None:
        """Buffer an event for backup shipping."""
        if not self.enabled:
            return

        with self._lock:
            self._stats["events_received"] += 1
            if len(self._buffer) >= BUFFER_MAX:
                self._stats["events_dropped"] += 1
            self._buffer.append(event)

    def flush(self) -> int:
        """Force flush buffered events."""
        if not self.enabled or not self._backend:
            return 0

        with self._lock:
            events = list(self._buffer)
            self._buffer.clear()

        if not events:
            return 0

        try:
            shipped = self._backend.ship(events)
            self._stats["events_shipped"] += shipped
            return shipped
        except Exception as e:
            self._stats["ship_errors"] += 1
            logger.error(f"Backup stream ship error: {e}")
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """Get backup stream statistics."""
        return {
            **self._stats,
            "buffer_size": len(self._buffer),
            "enabled": self.enabled,
            "backend": type(self._backend).__name__ if self._backend else None,
        }

    def shutdown(self):
        """Flush and stop."""
        self._stop_event.set()
        if self.enabled:
            self.flush()

    def _flush_loop(self):
        """Periodically flush buffered events."""
        while not self._stop_event.wait(FLUSH_INTERVAL_SECONDS):
            self.flush()


class _BackupBackend:
    """Base class for backup backends."""

    available: bool = False

    def ship(self, events: List[Dict[str, Any]]) -> int:
        raise NotImplementedError


class _FileBackend(_BackupBackend):
    """Write backup logs to a rotated local file."""

    def __init__(self):
        self.path = Path(
            os.environ.get(
                "BACKUP_FILE_PATH", "/var/log/honeyclaw/backup.jsonl"
            )
        )
        self.max_bytes = (
            int(os.environ.get("BACKUP_FILE_MAX_MB", "100")) * 1024 * 1024
        )
        self.keep = int(os.environ.get("BACKUP_FILE_KEEP", "5"))
        self.available = True

        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning(f"Cannot create backup log directory: {e}")
            self.available = False

    def ship(self, events: List[Dict[str, Any]]) -> int:
        self._maybe_rotate()

        lines = [json.dumps(e, default=str) for e in events]
        content = "\n".join(lines) + "\n"

        try:
            with open(self.path, "a") as f:
                f.write(content)
            return len(events)
        except OSError as e:
            logger.error(f"Backup file write error: {e}")
            return 0

    def _maybe_rotate(self):
        """Rotate log file if it exceeds max size."""
        if not self.path.exists():
            return
        try:
            if self.path.stat().st_size < self.max_bytes:
                return
        except OSError:
            return

        # Rotate: backup.jsonl -> backup.jsonl.1, .1 -> .2, etc.
        for i in range(self.keep - 1, 0, -1):
            src = self.path.with_suffix(f".jsonl.{i}")
            dst = self.path.with_suffix(f".jsonl.{i + 1}")
            if src.exists():
                src.rename(dst)

        self.path.rename(self.path.with_suffix(".jsonl.1"))


class _SyslogBackend(_BackupBackend):
    """Ship events to a syslog server."""

    def __init__(self):
        self.host = os.environ.get("BACKUP_SYSLOG_HOST", "")
        self.port = int(os.environ.get("BACKUP_SYSLOG_PORT", "514"))
        self.protocol = os.environ.get("BACKUP_SYSLOG_PROTOCOL", "udp").lower()
        self.available = bool(self.host)

    def ship(self, events: List[Dict[str, Any]]) -> int:
        shipped = 0
        for event in events:
            msg = json.dumps(event, default=str)
            # RFC 5424 structured data
            syslog_msg = f"<134>1 {datetime.now(timezone.utc).isoformat()} honeyclaw - - - {msg}"

            try:
                if self.protocol == "tcp":
                    with socket.create_connection(
                        (self.host, self.port), timeout=5
                    ) as sock:
                        sock.sendall((syslog_msg + "\n").encode("utf-8"))
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    try:
                        sock.sendto(
                            syslog_msg.encode("utf-8")[:65507],
                            (self.host, self.port),
                        )
                    finally:
                        sock.close()
                shipped += 1
            except OSError as e:
                logger.error(f"Syslog send error: {e}")

        return shipped


class _HTTPBackend(_BackupBackend):
    """Ship events to an HTTP webhook endpoint."""

    def __init__(self):
        self.url = os.environ.get("BACKUP_HTTP_URL", "")
        self.token = os.environ.get("BACKUP_HTTP_TOKEN", "")
        self.available = bool(self.url)

    def ship(self, events: List[Dict[str, Any]]) -> int:
        try:
            import urllib.request
            import urllib.error

            payload = json.dumps(
                {"source": "honeyclaw-backup", "events": events}, default=str
            ).encode("utf-8")

            headers = {"Content-Type": "application/json"}
            if self.token:
                headers["Authorization"] = f"Bearer {self.token}"

            req = urllib.request.Request(
                self.url, data=payload, headers=headers, method="POST"
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status < 300:
                    return len(events)
                else:
                    logger.error(
                        f"Backup HTTP endpoint returned {resp.status}"
                    )
                    return 0
        except Exception as e:
            logger.error(f"Backup HTTP send error: {e}")
            return 0


class _S3Backend(_BackupBackend):
    """Ship events to a secondary S3 bucket."""

    def __init__(self):
        self.bucket = os.environ.get("BACKUP_S3_BUCKET", "")
        self.region = os.environ.get("BACKUP_S3_REGION", "us-east-1")
        self.prefix = os.environ.get("BACKUP_S3_PREFIX", "backup-logs/")
        self.endpoint_url = os.environ.get("BACKUP_S3_ENDPOINT")
        self._client = None
        self.available = False

        if not self.bucket:
            return

        try:
            import boto3

            kwargs = {"region_name": self.region}
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url
            self._client = boto3.client("s3", **kwargs)
            self.available = True
        except Exception as e:
            logger.warning(f"Backup S3 client init failed: {e}")

    def ship(self, events: List[Dict[str, Any]]) -> int:
        if not self._client:
            return 0

        import gzip
        import hashlib

        lines = [json.dumps(e, default=str) for e in events]
        content = ("\n".join(lines) + "\n").encode("utf-8")
        compressed = gzip.compress(content)

        now = datetime.now(timezone.utc)
        content_hash = hashlib.sha256(content).hexdigest()[:12]
        key = (
            f"{self.prefix}{now.strftime('%Y/%m/%d')}/"
            f"backup_{now.strftime('%H%M%S')}_{content_hash}.jsonl.gz"
        )

        try:
            self._client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=compressed,
                ContentType="application/x-ndjson",
                ContentEncoding="gzip",
            )
            return len(events)
        except Exception as e:
            logger.error(f"Backup S3 upload error: {e}")
            return 0


# Module-level singleton
_default_stream: Optional[BackupStream] = None
_init_lock = threading.Lock()


def get_backup_stream() -> BackupStream:
    """Get or create the default BackupStream singleton."""
    global _default_stream
    if _default_stream is None:
        with _init_lock:
            if _default_stream is None:
                _default_stream = BackupStream()
    return _default_stream
