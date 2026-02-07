#!/usr/bin/env python3
"""
Honeyclaw SIEM Integration - Base Connector Interface

Provides common interface and utilities for all SIEM connectors.
All connectors inherit from SIEMConnector and implement the send() method.
"""

import os
import json
import time
import logging
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Union
from enum import Enum

# Configure logging
logger = logging.getLogger('honeyclaw.siem')


class Severity(Enum):
    """CEF-compatible severity levels (0-10 scale)"""
    UNKNOWN = 0
    LOW = 3
    MEDIUM = 5
    HIGH = 7
    CRITICAL = 10


class EventType(Enum):
    """Honeypot event types for categorization"""
    CONNECTION = "connection"
    AUTH_ATTEMPT = "auth_attempt"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    COMMAND = "command"
    FILE_ACCESS = "file_access"
    DATA_EXFIL = "data_exfil"
    SCAN = "scan"
    EXPLOIT_ATTEMPT = "exploit_attempt"
    MALWARE = "malware"
    LATERAL_MOVEMENT = "lateral_movement"
    UNKNOWN = "unknown"


@dataclass
class HoneypotEvent:
    """
    Normalized honeypot event structure.
    All SIEM connectors convert this to their native format.
    """
    # Required fields
    timestamp: str  # ISO 8601 format
    honeypot_id: str
    source_ip: str
    event_type: EventType
    
    # Optional identification
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str = "tcp"
    service: str = "unknown"
    
    # Authentication fields
    username: Optional[str] = None
    password_length: Optional[int] = None
    auth_method: Optional[str] = None
    
    # Command/payload fields
    command: Optional[str] = None
    payload_hash: Optional[str] = None
    payload_size: Optional[int] = None
    
    # Threat intelligence
    severity: Severity = Severity.MEDIUM
    tags: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    mitre_technique_names: List[str] = field(default_factory=list)
    
    # Session tracking
    session_id: Optional[str] = None
    session_duration_ms: Optional[int] = None

    # Correlation (for linking multi-step attacks across services)
    correlation_id: Optional[str] = None

    # Geolocation (if available)
    geo_country: Optional[str] = None
    geo_country_code: Optional[str] = None
    geo_city: Optional[str] = None
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    geo_asn: Optional[str] = None
    geo_asn_org: Optional[str] = None

    # Raw data (for forensics)
    raw_data: Optional[Dict[str, Any]] = None
    
    # Metadata
    honeypot_template: str = "unknown"
    collector_version: str = "1.0.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, handling enums"""
        result = {}
        for key, value in asdict(self).items():
            if isinstance(value, Enum):
                result[key] = value.value
            elif value is not None:
                result[key] = value
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HoneypotEvent':
        """Create from dictionary"""
        # Convert string enums back to Enum types
        if 'event_type' in data and isinstance(data['event_type'], str):
            data['event_type'] = EventType(data['event_type'])
        if 'severity' in data and isinstance(data['severity'], (str, int)):
            if isinstance(data['severity'], str):
                data['severity'] = Severity[data['severity'].upper()]
            else:
                data['severity'] = Severity(data['severity'])
        
        # Filter to only known fields
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known_fields}
        
        return cls(**filtered)
    
    def generate_event_id(self) -> str:
        """Generate unique event ID based on content"""
        content = f"{self.timestamp}:{self.honeypot_id}:{self.source_ip}:{self.event_type.value}"
        if self.command:
            content += f":{self.command[:100]}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class SIEMConfig:
    """Base configuration for SIEM connectors"""
    provider: str
    endpoint: str
    
    # Authentication (varies by provider)
    token: Optional[str] = None
    api_key: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    
    # Connection settings
    timeout_seconds: int = 30
    verify_ssl: bool = True
    ca_cert_path: Optional[str] = None
    
    # Batching settings
    batch_size: int = 100
    flush_interval_seconds: int = 10
    
    # Retry settings
    max_retries: int = 3
    retry_delay_seconds: int = 5
    
    # Provider-specific settings
    index: Optional[str] = None
    source: Optional[str] = None
    sourcetype: Optional[str] = None
    workspace_id: Optional[str] = None
    shared_key: Optional[str] = None
    
    # Syslog-specific
    syslog_host: Optional[str] = None
    syslog_port: int = 514
    syslog_protocol: str = "udp"
    syslog_format: str = "cef"  # cef or leef
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SIEMConfig':
        """Create config from dictionary, expanding env vars"""
        expanded = {}
        for key, value in data.items():
            if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
                env_var = value[2:-1]
                expanded[key] = os.environ.get(env_var, '')
            else:
                expanded[key] = value
        
        # Filter to known fields
        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in expanded.items() if k in known_fields}
        
        return cls(**filtered)
    
    @classmethod
    def from_yaml(cls, yaml_path: str) -> 'SIEMConfig':
        """Load config from YAML file"""
        import yaml
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data.get('siem', data))


class SIEMConnector(ABC):
    """
    Abstract base class for SIEM connectors.
    
    All connectors must implement:
    - send(): Send a single event
    - send_batch(): Send multiple events efficiently
    - test_connection(): Verify connectivity
    """
    
    def __init__(self, config: Union[Dict[str, Any], SIEMConfig]):
        if isinstance(config, dict):
            self.config = SIEMConfig.from_dict(config)
        else:
            self.config = config
        
        self._batch_buffer: List[HoneypotEvent] = []
        self._last_flush = time.time()
        self._stats = {
            'events_sent': 0,
            'events_failed': 0,
            'batches_sent': 0,
            'last_error': None,
        }
    
    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name (e.g., 'splunk', 'elastic')"""
        pass
    
    @abstractmethod
    def send(self, event: HoneypotEvent) -> bool:
        """
        Send a single event to the SIEM.
        
        Args:
            event: HoneypotEvent to send
            
        Returns:
            True if successful, False otherwise
        """
        pass
    
    @abstractmethod
    def send_batch(self, events: List[HoneypotEvent]) -> int:
        """
        Send multiple events to the SIEM.
        
        Args:
            events: List of HoneypotEvent objects
            
        Returns:
            Number of events successfully sent
        """
        pass
    
    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connectivity to the SIEM.
        
        Returns:
            True if connection successful
        """
        pass
    
    def buffer_event(self, event: HoneypotEvent) -> Optional[int]:
        """
        Add event to buffer. Auto-flushes when batch_size reached.
        
        Returns:
            Number of events flushed, or None if just buffered
        """
        self._batch_buffer.append(event)
        
        # Check if we should flush
        should_flush = (
            len(self._batch_buffer) >= self.config.batch_size or
            (time.time() - self._last_flush) >= self.config.flush_interval_seconds
        )
        
        if should_flush:
            return self.flush()
        return None
    
    def flush(self) -> int:
        """Flush buffered events to SIEM"""
        if not self._batch_buffer:
            return 0
        
        events = self._batch_buffer
        self._batch_buffer = []
        self._last_flush = time.time()
        
        sent = self.send_batch(events)
        self._stats['batches_sent'] += 1
        
        return sent
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connector statistics"""
        return {
            **self._stats,
            'buffered_events': len(self._batch_buffer),
            'provider': self.provider_name,
        }
    
    def _log_success(self, count: int):
        """Log successful send"""
        self._stats['events_sent'] += count
        logger.debug(f"[{self.provider_name}] Sent {count} events")
    
    def _log_failure(self, error: str, count: int = 1):
        """Log failed send"""
        self._stats['events_failed'] += count
        self._stats['last_error'] = error
        logger.error(f"[{self.provider_name}] Failed to send: {error}")
    
    def close(self):
        """Cleanup - flush remaining events"""
        if self._batch_buffer:
            logger.info(f"[{self.provider_name}] Flushing {len(self._batch_buffer)} remaining events")
            self.flush()


def normalize_timestamp(timestamp: Any) -> str:
    """Convert various timestamp formats to ISO 8601"""
    if isinstance(timestamp, str):
        return timestamp
    elif isinstance(timestamp, (int, float)):
        # Unix timestamp
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
    elif isinstance(timestamp, datetime):
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.isoformat()
    else:
        return datetime.now(timezone.utc).isoformat()


def severity_to_cef(severity: Severity) -> int:
    """Convert Severity enum to CEF numeric severity (0-10)"""
    return severity.value


def event_type_to_category(event_type: EventType) -> str:
    """Map event type to SIEM category"""
    categories = {
        EventType.CONNECTION: "Network",
        EventType.AUTH_ATTEMPT: "Authentication",
        EventType.AUTH_SUCCESS: "Authentication",
        EventType.AUTH_FAILURE: "Authentication",
        EventType.COMMAND: "Execution",
        EventType.FILE_ACCESS: "File",
        EventType.DATA_EXFIL: "Exfiltration",
        EventType.SCAN: "Reconnaissance",
        EventType.EXPLOIT_ATTEMPT: "Exploit",
        EventType.MALWARE: "Malware",
        EventType.LATERAL_MOVEMENT: "LateralMovement",
        EventType.UNKNOWN: "Unknown",
    }
    return categories.get(event_type, "Unknown")
