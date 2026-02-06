#!/usr/bin/env python3
"""
Honeyclaw SIEM Integration - Azure Sentinel Connector

Pushes honeypot events to Azure Sentinel via Log Analytics Data Collector API.

Configuration:
    siem:
      provider: sentinel
      workspace_id: ${AZURE_WORKSPACE_ID}
      shared_key: ${AZURE_SHARED_KEY}
      log_type: HoneyclawEvents

Usage:
    from honeyclaw.integrations import AzureSentinelConnector
    
    connector = AzureSentinelConnector({
        'workspace_id': 'your-workspace-id',
        'shared_key': 'your-shared-key',
        'log_type': 'HoneyclawEvents',
    })
    
    event = HoneypotEvent(...)
    connector.send(event)
"""

import json
import time
import logging
import urllib.request
import urllib.error
import ssl
import base64
import hashlib
import hmac
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from .base import (
    SIEMConnector,
    SIEMConfig,
    HoneypotEvent,
    Severity,
    EventType,
    normalize_timestamp,
    event_type_to_category,
)

logger = logging.getLogger('honeyclaw.siem.sentinel')


class AzureSentinelConnector(SIEMConnector):
    """
    Azure Sentinel connector via Log Analytics Data Collector API.
    
    Features:
    - Shared key authentication with HMAC-SHA256 signing
    - Custom log type support
    - ASIM (Azure Sentinel Information Model) field mapping
    - Batch submission support
    - Time-generated field for proper timestamp handling
    
    Documentation:
    https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Validate required config
        if not self.config.workspace_id:
            raise ValueError("Azure Log Analytics workspace_id is required")
        if not self.config.shared_key:
            raise ValueError("Azure Log Analytics shared_key is required")
        
        # Log type (table name in Sentinel)
        self._log_type = config.get('log_type', 'HoneyclawEvents')
        
        # Build endpoint URL
        self._endpoint = (
            f"https://{self.config.workspace_id}"
            f".ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
        )
        
        # SSL context
        self._ssl_context = self._build_ssl_context()
        
        logger.info(f"Azure Sentinel connector initialized for workspace: {self.config.workspace_id[:8]}...")
    
    @property
    def provider_name(self) -> str:
        return "sentinel"
    
    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build SSL context for HTTPS connections"""
        context = ssl.create_default_context()
        
        if not self.config.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif self.config.ca_cert_path:
            context.load_verify_locations(self.config.ca_cert_path)
        
        return context
    
    def _build_signature(
        self, 
        date: str, 
        content_length: int, 
        method: str, 
        content_type: str, 
        resource: str
    ) -> str:
        """
        Build Azure Log Analytics authorization signature.
        
        The signature is HMAC-SHA256 of the string-to-sign, base64 encoded.
        """
        x_headers = f"x-ms-date:{date}"
        string_to_sign = (
            f"{method}\n"
            f"{content_length}\n"
            f"{content_type}\n"
            f"{x_headers}\n"
            f"{resource}"
        )
        
        # Decode the shared key from base64
        decoded_key = base64.b64decode(self.config.shared_key)
        
        # Create HMAC-SHA256 signature
        signature = hmac.new(
            decoded_key,
            string_to_sign.encode('utf-8'),
            hashlib.sha256
        ).digest()
        
        # Base64 encode the signature
        encoded_signature = base64.b64encode(signature).decode('utf-8')
        
        return f"SharedKey {self.config.workspace_id}:{encoded_signature}"
    
    def _format_event(self, event: HoneypotEvent) -> Dict[str, Any]:
        """
        Format HoneypotEvent for Azure Sentinel.
        
        Uses ASIM (Azure Sentinel Information Model) where applicable.
        https://docs.microsoft.com/en-us/azure/sentinel/normalization
        """
        # ASIM-compatible document
        doc = {
            # ASIM Common fields
            "TimeGenerated": event.timestamp,
            "EventVendor": "Honeyclaw",
            "EventProduct": "Honeypot",
            "EventProductVersion": event.collector_version,
            "EventType": event.event_type.value,
            "EventSeverity": self._map_severity(event.severity),
            "EventOriginalSeverity": str(event.severity.value),
            "EventResult": self._map_result(event.event_type),
            "EventMessage": self._build_message(event),
            
            # ASIM Network Session fields
            "SrcIpAddr": event.source_ip,
            "SrcPortNumber": event.source_port,
            "DstPortNumber": event.destination_port,
            "NetworkProtocol": event.protocol.upper(),
            "NetworkApplicationProtocol": event.service,
            
            # ASIM Authentication fields
            "TargetUsername": event.username,
            "LogonMethod": event.auth_method,
            
            # ASIM Process/Command fields
            "CommandLine": event.command,
            
            # ASIM File fields
            "FileHashSha256": event.payload_hash,
            "FileSize": event.payload_size,
            
            # Geo fields
            "SrcGeoCountry": event.geo_country,
            "SrcGeoCity": event.geo_city,
            "SrcGeoAsn": event.geo_asn,
            
            # Threat Intelligence
            "ThreatCategory": event_type_to_category(event.event_type),
            "ThreatTactics": ",".join(event.mitre_tactics) if event.mitre_tactics else None,
            "ThreatTechniques": ",".join(event.mitre_techniques) if event.mitre_techniques else None,
            
            # Honeyclaw-specific fields
            "HoneypotId": event.honeypot_id,
            "HoneypotTemplate": event.honeypot_template,
            "HoneypotService": event.service,
            "SessionId": event.session_id,
            "SessionDurationMs": event.session_duration_ms,
            "PasswordLength": event.password_length,
            "EventId": event.generate_event_id(),
            "Tags": ",".join(event.tags) if event.tags else None,
        }
        
        # Remove None values (Azure doesn't like nulls)
        doc = {k: v for k, v in doc.items() if v is not None}
        
        return doc
    
    def _map_severity(self, severity: Severity) -> str:
        """Map severity to Azure Sentinel severity string"""
        mapping = {
            Severity.UNKNOWN: "Informational",
            Severity.LOW: "Low",
            Severity.MEDIUM: "Medium",
            Severity.HIGH: "High",
            Severity.CRITICAL: "High",  # Sentinel max is High
        }
        return mapping.get(severity, "Informational")
    
    def _map_result(self, event_type: EventType) -> str:
        """Map event type to ASIM EventResult"""
        if event_type == EventType.AUTH_SUCCESS:
            return "Success"
        elif event_type in (EventType.AUTH_FAILURE, EventType.EXPLOIT_ATTEMPT):
            return "Failure"
        return "NA"
    
    def _build_message(self, event: HoneypotEvent) -> str:
        """Build human-readable message"""
        parts = [
            f"Honeypot alert: {event.event_type.value}",
            f"from {event.source_ip}",
            f"targeting {event.honeypot_id}",
            f"({event.service})",
        ]
        
        if event.username:
            parts.append(f"user={event.username}")
        
        return " ".join(parts)
    
    def _send_request(self, body: str) -> bool:
        """
        Send data to Azure Log Analytics Data Collector API.
        
        Args:
            body: JSON body string
            
        Returns:
            True if successful
        """
        # Generate RFC 1123 date
        rfc1123_date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        # Content type and length
        content_type = "application/json"
        content_length = len(body)
        
        # Build authorization signature
        resource = "/api/logs"
        signature = self._build_signature(
            rfc1123_date,
            content_length,
            "POST",
            content_type,
            resource
        )
        
        headers = {
            "Content-Type": content_type,
            "Authorization": signature,
            "Log-Type": self._log_type,
            "x-ms-date": rfc1123_date,
            "time-generated-field": "TimeGenerated",
        }
        
        request = urllib.request.Request(
            self._endpoint,
            data=body.encode('utf-8'),
            headers=headers,
            method='POST'
        )
        
        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                with urllib.request.urlopen(
                    request,
                    timeout=self.config.timeout_seconds,
                    context=self._ssl_context
                ) as response:
                    if response.status in (200, 202):
                        return True
                    else:
                        last_error = f"HTTP {response.status}"
                        
            except urllib.error.HTTPError as e:
                last_error = f"HTTP {e.code}: {e.reason}"
                
                # Read error body for details
                try:
                    error_body = e.read().decode()
                    last_error = f"{last_error} - {error_body[:200]}"
                except:
                    pass
                
                if e.code in (400, 401, 403):
                    break
                    
            except urllib.error.URLError as e:
                last_error = f"URL Error: {e.reason}"
                
            except Exception as e:
                last_error = str(e)
            
            if attempt < self.config.max_retries - 1:
                delay = self.config.retry_delay_seconds * (2 ** attempt)
                logger.warning(f"Azure Sentinel retry in {delay}s: {last_error}")
                time.sleep(delay)
        
        self._log_failure(last_error)
        return False
    
    def send(self, event: HoneypotEvent) -> bool:
        """Send a single event to Azure Sentinel"""
        doc = self._format_event(event)
        
        # Azure expects an array of records
        body = json.dumps([doc])
        
        if self._send_request(body):
            self._log_success(1)
            return True
        
        return False
    
    def send_batch(self, events: List[HoneypotEvent]) -> int:
        """
        Send multiple events to Azure Sentinel.
        
        The Data Collector API accepts an array of records.
        Max payload size is 30MB.
        """
        if not events:
            return 0
        
        # Format all events
        docs = [self._format_event(e) for e in events]
        
        # Build JSON array
        body = json.dumps(docs)
        
        # Check size limit (30MB)
        if len(body) > 30 * 1024 * 1024:
            logger.warning("Batch too large, splitting")
            # Split and send in chunks
            mid = len(events) // 2
            return (
                self.send_batch(events[:mid]) + 
                self.send_batch(events[mid:])
            )
        
        if self._send_request(body):
            self._log_success(len(events))
            return len(events)
        
        return 0
    
    def test_connection(self) -> bool:
        """
        Test connection to Azure Sentinel.
        
        Sends a test event to verify credentials and connectivity.
        """
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
            logger.error(f"Azure Sentinel connection test failed: {e}")
            return False


# Convenience function
def create_sentinel_connector(
    workspace_id: str,
    shared_key: str,
    log_type: str = "HoneyclawEvents"
) -> AzureSentinelConnector:
    """
    Create an Azure Sentinel connector with minimal config.
    
    Args:
        workspace_id: Log Analytics workspace ID
        shared_key: Log Analytics shared key
        log_type: Custom log type name (table name in Sentinel)
        
    Returns:
        Configured AzureSentinelConnector
    """
    return AzureSentinelConnector({
        'provider': 'sentinel',
        'workspace_id': workspace_id,
        'shared_key': shared_key,
        'log_type': log_type,
    })
