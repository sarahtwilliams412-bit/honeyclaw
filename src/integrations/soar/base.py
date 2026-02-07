#!/usr/bin/env python3
"""
Honeyclaw SOAR Integration - Base Connector Interface

Provides common interface and utilities for all SOAR connectors.
All connectors inherit from SOARConnector and implement the required methods.
"""

import os
import json
import time
import logging
import hashlib
import urllib.request
import urllib.error
import ssl
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Union
from enum import Enum

logger = logging.getLogger('honeyclaw.soar')


class IncidentSeverity(Enum):
    """SOAR-compatible severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IncidentStatus(Enum):
    """Incident lifecycle states"""
    NEW = "new"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"


class TLP(Enum):
    """Traffic Light Protocol for information sharing"""
    WHITE = "TLP:WHITE"
    GREEN = "TLP:GREEN"
    AMBER = "TLP:AMBER"
    RED = "TLP:RED"


@dataclass
class PlaybookTrigger:
    """
    Defines when and how to trigger a SOAR playbook.

    Attributes:
        playbook_id: Identifier of the playbook to trigger
        name: Human-readable name
        trigger_on_severity: Minimum severity to trigger
        trigger_on_event_types: Event types that activate this playbook
        trigger_on_tags: Tags that activate this playbook
        parameters: Additional parameters to pass to the playbook
        enabled: Whether this trigger is active
    """
    playbook_id: str
    name: str
    trigger_on_severity: IncidentSeverity = IncidentSeverity.HIGH
    trigger_on_event_types: List[str] = field(default_factory=list)
    trigger_on_tags: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def matches(self, alert: 'SOARAlert') -> bool:
        """Check if this trigger matches the given alert."""
        if not self.enabled:
            return False

        if alert.severity.value < self.trigger_on_severity.value:
            return False

        if self.trigger_on_event_types:
            if alert.event_type not in self.trigger_on_event_types:
                return False

        if self.trigger_on_tags:
            if not any(tag in alert.tags for tag in self.trigger_on_tags):
                return False

        return True


@dataclass
class SOARAlert:
    """
    Normalized alert structure for SOAR platforms.
    All SOAR connectors convert this to their native format.
    """
    # Required fields
    title: str
    description: str
    source_ip: str
    severity: IncidentSeverity
    event_type: str

    # Identification
    alert_id: Optional[str] = None
    honeypot_id: str = "honeyclaw"
    timestamp: Optional[str] = None

    # Context
    username: Optional[str] = None
    command: Optional[str] = None
    service: str = "unknown"
    destination_port: Optional[int] = None

    # Threat intelligence
    tags: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    ioc_type: Optional[str] = None  # ip, domain, hash, url
    ioc_value: Optional[str] = None

    # Geolocation
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None
    geo_asn: Optional[str] = None

    # Session
    session_id: Optional[str] = None

    # Sharing
    tlp: TLP = TLP.AMBER

    # Raw event data
    raw_event: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if self.alert_id is None:
            self.alert_id = self._generate_id()
        if self.ioc_type is None and self.source_ip:
            self.ioc_type = "ip"
            self.ioc_value = self.source_ip

    def _generate_id(self) -> str:
        """Generate unique alert ID"""
        content = f"{self.timestamp}:{self.honeypot_id}:{self.source_ip}:{self.event_type}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]

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
    def from_alert_dict(cls, alert: Dict[str, Any], event: Dict[str, Any] = None) -> 'SOARAlert':
        """
        Create SOARAlert from alert engine output.

        Args:
            alert: Alert dict from AlertEngine.evaluate()
            event: Original event data
        """
        event = event or alert.get('event', {})

        severity_map = {
            'CRITICAL': IncidentSeverity.CRITICAL,
            'HIGH': IncidentSeverity.HIGH,
            'MEDIUM': IncidentSeverity.MEDIUM,
            'LOW': IncidentSeverity.LOW,
            'INFO': IncidentSeverity.LOW,
            'DEBUG': IncidentSeverity.LOW,
        }

        return cls(
            title=alert.get('description', 'Honeyclaw Security Alert'),
            description=cls._build_description(alert, event),
            source_ip=event.get('ip', event.get('source_ip', 'unknown')),
            severity=severity_map.get(alert.get('severity', 'MEDIUM'), IncidentSeverity.MEDIUM),
            event_type=alert.get('event_type', 'unknown'),
            honeypot_id=alert.get('honeypot_id', 'honeyclaw'),
            username=event.get('username'),
            command=event.get('command'),
            service=event.get('service', 'unknown'),
            destination_port=event.get('port') or event.get('destination_port'),
            tags=alert.get('tags', []),
            mitre_tactics=event.get('mitre_tactics', []),
            mitre_techniques=event.get('mitre_techniques', []),
            session_id=event.get('session_id'),
            geo_country=event.get('geo_country'),
            geo_city=event.get('geo_city'),
            geo_asn=event.get('geo_asn'),
            raw_event=event,
        )

    @staticmethod
    def _build_description(alert: Dict[str, Any], event: Dict[str, Any]) -> str:
        """Build detailed description from alert and event data."""
        parts = [
            f"Rule: {alert.get('rule', 'unknown')}",
            f"Source IP: {event.get('ip', event.get('source_ip', 'unknown'))}",
        ]
        if event.get('username'):
            parts.append(f"Username: {event['username']}")
        if event.get('command'):
            parts.append(f"Command: {event['command']}")
        if alert.get('tags'):
            parts.append(f"Tags: {', '.join(alert['tags'])}")
        return '\n'.join(parts)


@dataclass
class SOARConfig:
    """Configuration for SOAR connectors"""
    endpoint: str
    provider: str = ""

    # Authentication
    api_key: Optional[str] = None
    token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

    # Connection settings
    timeout_seconds: int = 30
    verify_ssl: bool = True
    ca_cert_path: Optional[str] = None

    # Retry settings
    max_retries: int = 3
    retry_delay_seconds: int = 2

    # Playbook configuration
    default_playbook_id: Optional[str] = None
    auto_trigger_playbooks: bool = True

    # Organization / tenant
    org_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SOARConfig':
        """Create config from dictionary, expanding env vars"""
        expanded = {}
        for key, value in data.items():
            if isinstance(value, str) and value.startswith('${') and value.endswith('}'):
                env_var = value[2:-1]
                expanded[key] = os.environ.get(env_var, '')
            else:
                expanded[key] = value

        known_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in expanded.items() if k in known_fields}

        return cls(**filtered)


class SOARConnector(ABC):
    """
    Abstract base class for SOAR connectors.

    All connectors must implement:
    - create_alert(): Create an alert/case in the SOAR platform
    - trigger_playbook(): Trigger an automated response playbook
    - test_connection(): Verify connectivity
    """

    def __init__(self, config: Union[Dict[str, Any], SOARConfig]):
        if isinstance(config, dict):
            self.config = SOARConfig.from_dict(config)
        else:
            self.config = config

        self._playbook_triggers: List[PlaybookTrigger] = []
        self._ssl_context = self._build_ssl_context()
        self._stats = {
            'alerts_created': 0,
            'alerts_failed': 0,
            'playbooks_triggered': 0,
            'playbooks_failed': 0,
            'last_error': None,
        }

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Return the provider name"""
        pass

    @abstractmethod
    def create_alert(self, alert: SOARAlert) -> Optional[str]:
        """
        Create an alert/case in the SOAR platform.

        Args:
            alert: SOARAlert to create

        Returns:
            Alert/case ID from the SOAR platform, or None on failure
        """
        pass

    @abstractmethod
    def trigger_playbook(self, playbook_id: str, alert: SOARAlert,
                         parameters: Optional[Dict[str, Any]] = None) -> bool:
        """
        Trigger an automated response playbook.

        Args:
            playbook_id: ID of the playbook to trigger
            alert: Alert context for the playbook
            parameters: Additional parameters for the playbook

        Returns:
            True if playbook triggered successfully
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connectivity to the SOAR platform.

        Returns:
            True if connection successful
        """
        pass

    def process_alert(self, alert: SOARAlert) -> Optional[str]:
        """
        Process an alert: create it in SOAR and trigger matching playbooks.

        Args:
            alert: The alert to process

        Returns:
            Alert/case ID if created successfully
        """
        # Create the alert
        alert_id = self.create_alert(alert)

        if alert_id and self.config.auto_trigger_playbooks:
            self._check_playbook_triggers(alert)

        return alert_id

    def register_playbook_trigger(self, trigger: PlaybookTrigger):
        """Register a playbook trigger rule."""
        self._playbook_triggers.append(trigger)
        logger.info(f"[{self.provider_name}] Registered playbook trigger: {trigger.name}")

    def _check_playbook_triggers(self, alert: SOARAlert):
        """Check and execute matching playbook triggers."""
        for trigger in self._playbook_triggers:
            if trigger.matches(alert):
                logger.info(
                    f"[{self.provider_name}] Triggering playbook '{trigger.name}' "
                    f"for alert {alert.alert_id}"
                )
                success = self.trigger_playbook(
                    trigger.playbook_id, alert, trigger.parameters
                )
                if success:
                    self._stats['playbooks_triggered'] += 1
                else:
                    self._stats['playbooks_failed'] += 1

    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build SSL context for HTTPS connections"""
        context = ssl.create_default_context()
        if not self.config.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif self.config.ca_cert_path:
            context.load_verify_locations(self.config.ca_cert_path)
        return context

    def _http_request(self, method: str, url: str, data: Optional[Dict] = None,
                      headers: Optional[Dict] = None) -> Optional[Dict]:
        """
        Send HTTP request with retry logic.

        Returns:
            Response body as dict, or None on failure
        """
        req_headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Honeyclaw-SOAR/1.0',
        }
        if headers:
            req_headers.update(headers)

        body = json.dumps(data).encode('utf-8') if data else None

        request = urllib.request.Request(
            url, data=body, headers=req_headers, method=method
        )

        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                with urllib.request.urlopen(
                    request,
                    timeout=self.config.timeout_seconds,
                    context=self._ssl_context,
                ) as response:
                    response_body = response.read().decode('utf-8')
                    if response_body:
                        return json.loads(response_body)
                    return {}

            except urllib.error.HTTPError as e:
                last_error = f"HTTP {e.code}: {e.reason}"
                if e.code in (400, 401, 403, 404, 409):
                    break  # Don't retry client errors

            except urllib.error.URLError as e:
                last_error = f"URL Error: {e.reason}"

            except Exception as e:
                last_error = str(e)

            if attempt < self.config.max_retries - 1:
                delay = self.config.retry_delay_seconds * (2 ** attempt)
                logger.warning(f"[{self.provider_name}] Retry in {delay}s: {last_error}")
                time.sleep(delay)

        self._stats['last_error'] = last_error
        logger.error(f"[{self.provider_name}] Request failed: {last_error}")
        return None

    def get_stats(self) -> Dict[str, Any]:
        """Get connector statistics"""
        return {
            **self._stats,
            'provider': self.provider_name,
            'playbook_triggers_registered': len(self._playbook_triggers),
        }

    def close(self):
        """Cleanup resources"""
        pass
