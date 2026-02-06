#!/usr/bin/env python3
"""
Honeyclaw SIEM Integration - Generic Syslog Connector (CEF/LEEF)

Pushes honeypot events via syslog in CEF (Common Event Format) or 
LEEF (Log Event Extended Format) for compatibility with:
- IBM QRadar
- HP ArcSight
- LogRhythm
- Any syslog-compatible SIEM

Configuration:
    siem:
      provider: syslog
      syslog_host: siem.example.com
      syslog_port: 514
      syslog_protocol: udp  # udp, tcp, or tls
      syslog_format: cef    # cef or leef

Usage:
    from honeyclaw.integrations import SyslogConnector
    
    connector = SyslogConnector({
        'syslog_host': 'qradar.example.com',
        'syslog_port': 514,
        'syslog_protocol': 'tcp',
        'syslog_format': 'leef',
    })
    
    event = HoneypotEvent(...)
    connector.send(event)
"""

import json
import time
import socket
import ssl
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from .base import (
    SIEMConnector,
    SIEMConfig,
    HoneypotEvent,
    Severity,
    EventType,
    severity_to_cef,
    event_type_to_category,
)

logger = logging.getLogger('honeyclaw.siem.syslog')


class SyslogConnector(SIEMConnector):
    """
    Generic syslog connector supporting CEF and LEEF formats.
    
    CEF (ArcSight Common Event Format):
    CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    
    LEEF (IBM Log Event Extended Format):
    LEEF:Version|Vendor|Product|Version|EventID|Key=Value<tab>Key=Value...
    
    Features:
    - UDP, TCP, and TLS transport
    - CEF and LEEF format support
    - Automatic syslog priority calculation
    - Extension field mapping for threat data
    - Batch support via multiple messages
    """
    
    # Syslog facilities
    FACILITY_LOCAL0 = 16
    FACILITY_LOCAL7 = 23
    
    # Syslog severities
    SYSLOG_EMERGENCY = 0
    SYSLOG_ALERT = 1
    SYSLOG_CRITICAL = 2
    SYSLOG_ERROR = 3
    SYSLOG_WARNING = 4
    SYSLOG_NOTICE = 5
    SYSLOG_INFO = 6
    SYSLOG_DEBUG = 7
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Syslog configuration
        self._host = self.config.syslog_host or config.get('endpoint', 'localhost')
        self._port = self.config.syslog_port or 514
        self._protocol = self.config.syslog_protocol or 'udp'
        self._format = (self.config.syslog_format or 'cef').lower()
        
        # Validate format
        if self._format not in ('cef', 'leef'):
            raise ValueError(f"Invalid syslog format: {self._format}. Use 'cef' or 'leef'")
        
        # Socket (lazily created)
        self._socket: Optional[socket.socket] = None
        
        # CEF/LEEF config
        self._vendor = "Honeyclaw"
        self._product = "Honeypot"
        self._version = "1.0.0"
        
        logger.info(
            f"Syslog connector initialized: {self._protocol}://{self._host}:{self._port} "
            f"(format: {self._format.upper()})"
        )
    
    @property
    def provider_name(self) -> str:
        return f"syslog-{self._format}"
    
    def _get_socket(self) -> socket.socket:
        """Get or create socket connection"""
        if self._socket is None:
            if self._protocol == 'udp':
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            elif self._protocol in ('tcp', 'tls'):
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(self.config.timeout_seconds)
                
                if self._protocol == 'tls':
                    context = ssl.create_default_context()
                    if not self.config.verify_ssl:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    self._socket = context.wrap_socket(
                        self._socket, 
                        server_hostname=self._host
                    )
                
                self._socket.connect((self._host, self._port))
            else:
                raise ValueError(f"Unknown protocol: {self._protocol}")
        
        return self._socket
    
    def _close_socket(self):
        """Close socket if open"""
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None
    
    def _calculate_priority(self, severity: Severity) -> int:
        """
        Calculate syslog priority value.
        Priority = Facility * 8 + Severity
        """
        # Map honeypot severity to syslog severity
        syslog_severity_map = {
            Severity.UNKNOWN: self.SYSLOG_INFO,
            Severity.LOW: self.SYSLOG_NOTICE,
            Severity.MEDIUM: self.SYSLOG_WARNING,
            Severity.HIGH: self.SYSLOG_ERROR,
            Severity.CRITICAL: self.SYSLOG_CRITICAL,
        }
        
        syslog_severity = syslog_severity_map.get(severity, self.SYSLOG_INFO)
        return self.FACILITY_LOCAL0 * 8 + syslog_severity
    
    def _escape_cef(self, value: str) -> str:
        """Escape CEF special characters"""
        if not value:
            return ""
        return str(value).replace('\\', '\\\\').replace('|', '\\|').replace('=', '\\=')
    
    def _escape_leef(self, value: str) -> str:
        """Escape LEEF special characters"""
        if not value:
            return ""
        # LEEF uses tab as delimiter
        return str(value).replace('\t', ' ').replace('\n', ' ').replace('\r', '')
    
    def _format_cef(self, event: HoneypotEvent) -> str:
        """
        Format event as CEF (Common Event Format).
        
        CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
        """
        # Build signature ID from event type
        sig_id = f"honeyclaw:{event.event_type.value}"
        
        # Build event name
        name = f"Honeypot {event.event_type.value} from {event.source_ip}"
        
        # CEF severity (0-10)
        cef_severity = severity_to_cef(event.severity)
        
        # Build extension fields
        extensions = []
        
        # Source/destination
        extensions.append(f"src={event.source_ip}")
        if event.source_port:
            extensions.append(f"spt={event.source_port}")
        if event.destination_port:
            extensions.append(f"dpt={event.destination_port}")
        
        # Protocol
        extensions.append(f"proto={event.protocol}")
        extensions.append(f"app={self._escape_cef(event.service)}")
        
        # User
        if event.username:
            extensions.append(f"duser={self._escape_cef(event.username)}")
        
        # Command
        if event.command:
            cmd = self._escape_cef(event.command[:1024])
            extensions.append(f"cs1={cmd}")
            extensions.append("cs1Label=Command")
        
        # Payload
        if event.payload_hash:
            extensions.append(f"fileHash={event.payload_hash}")
        if event.payload_size:
            extensions.append(f"fsize={event.payload_size}")
        
        # Device/honeypot info
        extensions.append(f"dvchost={self._escape_cef(event.honeypot_id)}")
        
        # Session
        if event.session_id:
            extensions.append(f"cs2={self._escape_cef(event.session_id)}")
            extensions.append("cs2Label=SessionID")
        
        # Geo
        if event.geo_country:
            extensions.append(f"cs3={event.geo_country}")
            extensions.append("cs3Label=SrcCountry")
        if event.geo_asn:
            extensions.append(f"cs4={self._escape_cef(event.geo_asn)}")
            extensions.append("cs4Label=SrcASN")
        
        # MITRE ATT&CK
        if event.mitre_tactics:
            tactics = ",".join(event.mitre_tactics)
            extensions.append(f"cs5={self._escape_cef(tactics)}")
            extensions.append("cs5Label=MitreTactics")
        if event.mitre_techniques:
            techniques = ",".join(event.mitre_techniques)
            extensions.append(f"cs6={self._escape_cef(techniques)}")
            extensions.append("cs6Label=MitreTechniques")
        
        # Category
        extensions.append(f"cat={event_type_to_category(event.event_type)}")
        
        # Timestamp
        extensions.append(f"rt={event.timestamp}")
        
        # Event ID
        extensions.append(f"externalId={event.generate_event_id()}")
        
        # Build CEF string
        extension_str = " ".join(extensions)
        cef = f"CEF:0|{self._vendor}|{self._product}|{self._version}|{sig_id}|{name}|{cef_severity}|{extension_str}"
        
        return cef
    
    def _format_leef(self, event: HoneypotEvent) -> str:
        """
        Format event as LEEF (Log Event Extended Format).
        
        LEEF:Version|Vendor|Product|Version|EventID|Key=Value<tab>Key=Value...
        """
        # Event ID
        event_id = f"{event.event_type.value}"
        
        # Build key-value pairs (tab-separated)
        fields = []
        
        # Source
        fields.append(f"src={event.source_ip}")
        if event.source_port:
            fields.append(f"srcPort={event.source_port}")
        if event.destination_port:
            fields.append(f"dstPort={event.destination_port}")
        
        # Protocol
        fields.append(f"proto={event.protocol}")
        fields.append(f"sev={event.severity.value}")
        
        # Category (LEEF uses cat)
        fields.append(f"cat={event_type_to_category(event.event_type)}")
        
        # User
        if event.username:
            fields.append(f"usrName={self._escape_leef(event.username)}")
        
        # Command
        if event.command:
            fields.append(f"command={self._escape_leef(event.command[:512])}")
        
        # Device
        fields.append(f"devName={self._escape_leef(event.honeypot_id)}")
        fields.append(f"resource={self._escape_leef(event.service)}")
        
        # Geo
        if event.geo_country:
            fields.append(f"srcGeoCountry={event.geo_country}")
        
        # Timestamp (LEEF 2.0 uses devTime)
        fields.append(f"devTime={event.timestamp}")
        
        # Session
        if event.session_id:
            fields.append(f"sessionId={self._escape_leef(event.session_id)}")
        
        # Build LEEF string (tab-separated fields)
        fields_str = '\t'.join(fields)
        leef = f"LEEF:2.0|{self._vendor}|{self._product}|{self._version}|{event_id}|{fields_str}"
        
        return leef
    
    def _format_event(self, event: HoneypotEvent) -> str:
        """Format event based on configured format"""
        if self._format == 'leef':
            return self._format_leef(event)
        else:
            return self._format_cef(event)
    
    def _build_syslog_message(self, event: HoneypotEvent) -> bytes:
        """
        Build complete syslog message with header.
        
        RFC 5424 format: <priority>version timestamp hostname app-name procid msgid msg
        We use simplified RFC 3164 compatible format for wider compatibility.
        """
        priority = self._calculate_priority(event.severity)
        
        # Timestamp in syslog format
        timestamp = datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')
        
        # Hostname (use honeypot ID)
        hostname = event.honeypot_id.replace(' ', '_')[:48]
        
        # Format the event payload
        payload = self._format_event(event)
        
        # Build syslog message (RFC 3164 compatible)
        message = f"<{priority}>{timestamp} {hostname} honeyclaw: {payload}"
        
        # Ensure message ends with newline for TCP
        if self._protocol in ('tcp', 'tls') and not message.endswith('\n'):
            message += '\n'
        
        return message.encode('utf-8')
    
    def _send_message(self, message: bytes) -> bool:
        """Send syslog message over configured transport"""
        try:
            sock = self._get_socket()
            
            if self._protocol == 'udp':
                sock.sendto(message, (self._host, self._port))
            else:
                sock.sendall(message)
            
            return True
            
        except socket.error as e:
            self._log_failure(f"Socket error: {e}")
            self._close_socket()
            return False
            
        except Exception as e:
            self._log_failure(str(e))
            self._close_socket()
            return False
    
    def send(self, event: HoneypotEvent) -> bool:
        """Send a single event via syslog"""
        message = self._build_syslog_message(event)
        
        # Retry logic
        for attempt in range(self.config.max_retries):
            if self._send_message(message):
                self._log_success(1)
                return True
            
            if attempt < self.config.max_retries - 1:
                time.sleep(self.config.retry_delay_seconds)
        
        return False
    
    def send_batch(self, events: List[HoneypotEvent]) -> int:
        """
        Send multiple events via syslog.
        
        Each event is sent as a separate syslog message.
        """
        if not events:
            return 0
        
        success_count = 0
        messages = [self._build_syslog_message(e) for e in events]
        
        # For UDP, send all at once
        if self._protocol == 'udp':
            for message in messages:
                if self._send_message(message):
                    success_count += 1
        else:
            # For TCP/TLS, concatenate and send
            try:
                sock = self._get_socket()
                combined = b''.join(messages)
                sock.sendall(combined)
                success_count = len(events)
            except Exception as e:
                self._log_failure(str(e))
                self._close_socket()
                # Fall back to individual sends
                for message in messages:
                    if self._send_message(message):
                        success_count += 1
        
        if success_count > 0:
            self._log_success(success_count)
        
        return success_count
    
    def test_connection(self) -> bool:
        """Test syslog connection"""
        test_event = HoneypotEvent(
            timestamp=datetime.now(timezone.utc).isoformat(),
            honeypot_id="honeyclaw-test",
            source_ip="0.0.0.0",
            event_type=EventType.UNKNOWN,
            service="test",
            tags=["connection_test"],
        )
        
        try:
            return self.send(test_event)
        except Exception as e:
            logger.error(f"Syslog connection test failed: {e}")
            return False
    
    def close(self):
        """Cleanup resources"""
        super().close()
        self._close_socket()


# Convenience functions
def create_cef_connector(
    host: str,
    port: int = 514,
    protocol: str = 'udp'
) -> SyslogConnector:
    """Create a CEF syslog connector"""
    return SyslogConnector({
        'provider': 'syslog',
        'syslog_host': host,
        'syslog_port': port,
        'syslog_protocol': protocol,
        'syslog_format': 'cef',
    })


def create_leef_connector(
    host: str,
    port: int = 514,
    protocol: str = 'tcp'
) -> SyslogConnector:
    """Create a LEEF syslog connector (for QRadar)"""
    return SyslogConnector({
        'provider': 'syslog',
        'syslog_host': host,
        'syslog_port': port,
        'syslog_protocol': protocol,
        'syslog_format': 'leef',
    })
