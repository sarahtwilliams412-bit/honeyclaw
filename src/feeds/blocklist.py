#!/usr/bin/env python3
"""
Honeyclaw Blocklist Feed

Publishes confirmed attacker IPs as a blocklist feed in multiple formats.
Can be consumed by firewalls, IDS/IPS, and SOAR platforms.

Supported formats:
- Plain text (one IP per line)
- CSV (IP, first_seen, last_seen, confidence, tags)
- JSON (structured with metadata)
- STIX 2.1 indicators

Features:
- Configurable confidence threshold for inclusion
- TTL per entry (auto-expire after configurable period)
- Allowlist support (exclude known researchers/scanners)
- Thread-safe for concurrent access
- HTTP server for feed distribution

Usage:
    from honeyclaw.feeds.blocklist import BlocklistFeed

    feed = BlocklistFeed(min_confidence=0.7, ttl_hours=72)
    feed.add('45.33.32.156', confidence=0.95, tags=['brute-force', 'ssh'])
    feed.add('185.220.101.1', confidence=0.8, tags=['scanner'])

    # Get feed in various formats
    text = feed.to_text()
    csv_data = feed.to_csv()
    json_data = feed.to_json()

    # Serve via HTTP
    feed.serve(host='0.0.0.0', port=8080)
"""

import csv
import io
import json
import time
import logging
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List, Set, Any

logger = logging.getLogger('honeyclaw.feeds.blocklist')


@dataclass
class BlocklistEntry:
    """A single entry in the blocklist feed."""
    ip: str
    confidence: float  # 0.0 - 1.0
    first_seen: str  # ISO 8601
    last_seen: str  # ISO 8601
    times_seen: int = 1
    tags: List[str] = field(default_factory=list)
    services: List[str] = field(default_factory=list)
    honeypot_ids: List[str] = field(default_factory=list)
    severity: str = "medium"
    ttl_hours: int = 72
    source: str = "honeyclaw"

    @property
    def is_expired(self) -> bool:
        """Check if this entry has exceeded its TTL."""
        last = datetime.fromisoformat(self.last_seen.replace('Z', '+00:00'))
        expiry = last + timedelta(hours=self.ttl_hours)
        return datetime.now(timezone.utc) > expiry

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'ip': self.ip,
            'confidence': self.confidence,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'times_seen': self.times_seen,
            'tags': self.tags,
            'services': self.services,
            'honeypot_ids': self.honeypot_ids,
            'severity': self.severity,
            'source': self.source,
        }


class BlocklistFeed:
    """
    Manages a blocklist of confirmed attacker IPs.

    Thread-safe for concurrent reads and writes. Supports
    multiple output formats and optional HTTP serving.
    """

    def __init__(
        self,
        min_confidence: float = 0.5,
        ttl_hours: int = 72,
        max_entries: int = 100000,
        allowlist: Optional[Set[str]] = None,
    ):
        """
        Initialize the blocklist feed.

        Args:
            min_confidence: Minimum confidence score for inclusion (0.0-1.0)
            ttl_hours: Default time-to-live for entries in hours
            max_entries: Maximum number of entries to retain
            allowlist: Set of IPs to never include (researchers, scanners)
        """
        self.min_confidence = min_confidence
        self.ttl_hours = ttl_hours
        self.max_entries = max_entries
        self.allowlist = allowlist or set()

        self._entries: Dict[str, BlocklistEntry] = {}
        self._lock = threading.RLock()
        self._server: Optional[HTTPServer] = None

        # Reserved/private IPs that should never be blocklisted
        self._reserved_prefixes = (
            '10.', '172.16.', '172.17.', '172.18.', '172.19.',
            '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
            '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
            '172.30.', '172.31.', '192.168.', '127.', '0.',
        )

    def add(
        self,
        ip: str,
        confidence: float = 0.5,
        tags: Optional[List[str]] = None,
        service: Optional[str] = None,
        honeypot_id: Optional[str] = None,
        severity: str = "medium",
    ):
        """
        Add or update an IP in the blocklist.

        Args:
            ip: IP address to blocklist
            confidence: Confidence score (0.0-1.0)
            tags: Tags describing the threat (e.g., ['brute-force', 'ssh'])
            service: Service that was attacked
            honeypot_id: ID of the honeypot that observed this
            severity: Severity level (low, medium, high, critical)
        """
        if not ip or ip in self.allowlist:
            return

        # Skip private/reserved IPs
        if any(ip.startswith(prefix) for prefix in self._reserved_prefixes):
            return

        if confidence < self.min_confidence:
            return

        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            if ip in self._entries:
                entry = self._entries[ip]
                entry.last_seen = now
                entry.times_seen += 1
                entry.confidence = max(entry.confidence, confidence)
                if tags:
                    entry.tags = list(set(entry.tags + tags))
                if service and service not in entry.services:
                    entry.services.append(service)
                if honeypot_id and honeypot_id not in entry.honeypot_ids:
                    entry.honeypot_ids.append(honeypot_id)
                if severity in ('high', 'critical'):
                    entry.severity = severity
            else:
                self._entries[ip] = BlocklistEntry(
                    ip=ip,
                    confidence=confidence,
                    first_seen=now,
                    last_seen=now,
                    tags=tags or [],
                    services=[service] if service else [],
                    honeypot_ids=[honeypot_id] if honeypot_id else [],
                    severity=severity,
                    ttl_hours=self.ttl_hours,
                )

            # Enforce max entries by removing oldest
            if len(self._entries) > self.max_entries:
                self._evict_oldest()

    def remove(self, ip: str):
        """Remove an IP from the blocklist."""
        with self._lock:
            self._entries.pop(ip, None)

    def contains(self, ip: str) -> bool:
        """Check if an IP is in the blocklist."""
        with self._lock:
            entry = self._entries.get(ip)
            if entry and not entry.is_expired:
                return True
            return False

    def get_entries(self, min_confidence: Optional[float] = None) -> List[BlocklistEntry]:
        """
        Get active (non-expired) blocklist entries.

        Args:
            min_confidence: Override minimum confidence threshold
        """
        threshold = min_confidence if min_confidence is not None else self.min_confidence
        with self._lock:
            self._purge_expired()
            return [
                entry for entry in self._entries.values()
                if entry.confidence >= threshold
            ]

    def to_text(self, min_confidence: Optional[float] = None) -> str:
        """
        Export as plain text (one IP per line).

        Suitable for firewall blocklist import.
        """
        entries = self.get_entries(min_confidence)
        lines = [
            f'# Honeyclaw Blocklist Feed',
            f'# Generated: {datetime.now(timezone.utc).isoformat()}',
            f'# Entries: {len(entries)}',
            f'# Min confidence: {min_confidence or self.min_confidence}',
            f'#',
        ]
        for entry in sorted(entries, key=lambda e: e.confidence, reverse=True):
            lines.append(entry.ip)
        return '\n'.join(lines) + '\n'

    def to_csv(self, min_confidence: Optional[float] = None) -> str:
        """
        Export as CSV.

        Fields: ip, confidence, first_seen, last_seen, times_seen, severity, tags
        """
        entries = self.get_entries(min_confidence)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'ip', 'confidence', 'first_seen', 'last_seen',
            'times_seen', 'severity', 'tags', 'services',
        ])

        for entry in sorted(entries, key=lambda e: e.confidence, reverse=True):
            writer.writerow([
                entry.ip,
                f'{entry.confidence:.2f}',
                entry.first_seen,
                entry.last_seen,
                entry.times_seen,
                entry.severity,
                ';'.join(entry.tags),
                ';'.join(entry.services),
            ])

        return output.getvalue()

    def to_json(self, min_confidence: Optional[float] = None) -> str:
        """
        Export as JSON with metadata.
        """
        entries = self.get_entries(min_confidence)

        feed = {
            'feed': {
                'name': 'Honeyclaw Blocklist',
                'description': 'Confirmed attacker IPs observed by Honeyclaw honeypots',
                'generated': datetime.now(timezone.utc).isoformat(),
                'version': '1.0',
                'count': len(entries),
                'min_confidence': min_confidence or self.min_confidence,
                'ttl_hours': self.ttl_hours,
            },
            'entries': [entry.to_dict() for entry in sorted(
                entries, key=lambda e: e.confidence, reverse=True
            )],
        }

        return json.dumps(feed, indent=2)

    def to_stix(self, min_confidence: Optional[float] = None) -> str:
        """
        Export as STIX 2.1 bundle of indicators.
        """
        entries = self.get_entries(min_confidence)

        indicators = []
        for entry in entries:
            indicator = {
                'type': 'indicator',
                'spec_version': '2.1',
                'id': f'indicator--honeyclaw-{entry.ip.replace(".", "-")}',
                'created': entry.first_seen,
                'modified': entry.last_seen,
                'name': f'Malicious IP: {entry.ip}',
                'description': (
                    f'IP observed attacking honeypot. '
                    f'Seen {entry.times_seen} times. '
                    f'Services: {", ".join(entry.services) or "unknown"}. '
                    f'Tags: {", ".join(entry.tags) or "none"}.'
                ),
                'indicator_types': ['malicious-activity'],
                'pattern': f"[ipv4-addr:value = '{entry.ip}']",
                'pattern_type': 'stix',
                'valid_from': entry.first_seen,
                'confidence': int(entry.confidence * 100),
                'labels': ['honeypot', 'honeyclaw'] + entry.tags,
            }
            indicators.append(indicator)

        bundle = {
            'type': 'bundle',
            'id': f'bundle--honeyclaw-blocklist-{int(time.time())}',
            'objects': indicators,
        }

        return json.dumps(bundle, indent=2)

    @property
    def count(self) -> int:
        """Number of active entries."""
        with self._lock:
            return len(self._entries)

    def get_stats(self) -> Dict[str, Any]:
        """Get feed statistics."""
        with self._lock:
            entries = list(self._entries.values())
        return {
            'total_entries': len(entries),
            'active_entries': sum(1 for e in entries if not e.is_expired),
            'high_confidence': sum(1 for e in entries if e.confidence >= 0.8),
            'avg_confidence': (
                sum(e.confidence for e in entries) / len(entries)
                if entries else 0
            ),
            'allowlist_size': len(self.allowlist),
        }

    def serve(self, host: str = '0.0.0.0', port: int = 8080, background: bool = True):
        """
        Start HTTP server to serve the blocklist feed.

        Endpoints:
        - GET /blocklist.txt - Plain text format
        - GET /blocklist.csv - CSV format
        - GET /blocklist.json - JSON format
        - GET /blocklist.stix - STIX 2.1 format
        - GET /stats - Feed statistics
        - GET /health - Health check

        Args:
            host: Bind address
            port: Port number
            background: Run in background thread
        """
        feed = self

        class FeedHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                path = self.path.split('?')[0]

                if path == '/blocklist.txt' or path == '/blocklist':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/plain')
                    self.end_headers()
                    self.wfile.write(feed.to_text().encode())

                elif path == '/blocklist.csv':
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/csv')
                    self.end_headers()
                    self.wfile.write(feed.to_csv().encode())

                elif path == '/blocklist.json':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(feed.to_json().encode())

                elif path == '/blocklist.stix':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(feed.to_stix().encode())

                elif path == '/stats':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps(feed.get_stats(), indent=2).encode())

                elif path == '/health':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({'status': 'healthy'}).encode())

                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b'Not found')

            def log_message(self, format, *args):
                logger.debug(f"BlocklistFeed HTTP: {format % args}")

        self._server = HTTPServer((host, port), FeedHandler)
        logger.info(f"Blocklist feed server starting on {host}:{port}")

        if background:
            thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            thread.start()
        else:
            self._server.serve_forever()

    def stop(self):
        """Stop the HTTP server."""
        if self._server:
            self._server.shutdown()
            self._server = None

    def _purge_expired(self):
        """Remove expired entries (must hold lock)."""
        expired = [ip for ip, entry in self._entries.items() if entry.is_expired]
        for ip in expired:
            del self._entries[ip]
        if expired:
            logger.debug(f"Purged {len(expired)} expired blocklist entries")

    def _evict_oldest(self):
        """Evict oldest entries when at capacity (must hold lock)."""
        to_remove = len(self._entries) - self.max_entries
        if to_remove <= 0:
            return

        sorted_entries = sorted(
            self._entries.items(),
            key=lambda kv: kv[1].last_seen,
        )
        for ip, _ in sorted_entries[:to_remove]:
            del self._entries[ip]
