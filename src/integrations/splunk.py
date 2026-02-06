#!/usr/bin/env python3
"""
Honeyclaw SIEM Integration - Splunk HEC Connector

Pushes honeypot events to Splunk via HTTP Event Collector (HEC).

Configuration:
    siem:
      provider: splunk
      endpoint: https://hec.splunk.example.com:8088
      token: ${SPLUNK_HEC_TOKEN}
      index: honeypot
      source: honeyclaw
      sourcetype: honeyclaw:events

Usage:
    from honeyclaw.integrations import SplunkHECConnector
    
    connector = SplunkHECConnector({
        'endpoint': 'https://localhost:8088',
        'token': 'your-token-here',
        'index': 'honeypot',
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
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from .base import (
    SIEMConnector, 
    SIEMConfig, 
    HoneypotEvent, 
    Severity,
    EventType,
    normalize_timestamp,
    event_type_to_category,
)

logger = logging.getLogger('honeyclaw.siem.splunk')


class SplunkHECConnector(SIEMConnector):
    """
    Splunk HTTP Event Collector (HEC) connector.
    
    Features:
    - Batch event submission
    - Automatic retry with backoff
    - Token-based authentication
    - Index/source/sourcetype configuration
    - SSL verification (configurable)
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Validate required config
        if not self.config.endpoint:
            raise ValueError("Splunk HEC endpoint is required")
        if not self.config.token:
            raise ValueError("Splunk HEC token is required")
        
        # Build HEC URL
        self._hec_url = self._build_hec_url()
        
        # SSL context
        self._ssl_context = self._build_ssl_context()
        
        logger.info(f"Splunk HEC connector initialized: {self.config.endpoint}")
    
    @property
    def provider_name(self) -> str:
        return "splunk"
    
    def _build_hec_url(self) -> str:
        """Build the HEC endpoint URL"""
        endpoint = self.config.endpoint.rstrip('/')
        
        # Ensure we're hitting the event endpoint
        if not endpoint.endswith('/services/collector/event'):
            endpoint = f"{endpoint}/services/collector/event"
        
        return endpoint
    
    def _build_ssl_context(self) -> ssl.SSLContext:
        """Build SSL context for HTTPS connections"""
        context = ssl.create_default_context()
        
        if not self.config.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        elif self.config.ca_cert_path:
            context.load_verify_locations(self.config.ca_cert_path)
        
        return context
    
    def _format_event(self, event: HoneypotEvent) -> Dict[str, Any]:
        """
        Format HoneypotEvent for Splunk HEC.
        
        Splunk HEC expects:
        {
            "time": <epoch>,
            "host": <honeypot_id>,
            "source": <source>,
            "sourcetype": <sourcetype>,
            "index": <index>,
            "event": <event_data>
        }
        """
        # Parse timestamp to epoch
        try:
            if isinstance(event.timestamp, str):
                dt = datetime.fromisoformat(event.timestamp.replace('Z', '+00:00'))
                epoch_time = dt.timestamp()
            else:
                epoch_time = time.time()
        except (ValueError, TypeError):
            epoch_time = time.time()
        
        # Build event data with Splunk CIM field mappings
        event_data = {
            # CIM Network Traffic fields
            "src_ip": event.source_ip,
            "src_port": event.source_port,
            "dest_port": event.destination_port,
            "transport": event.protocol,
            
            # CIM Authentication fields
            "user": event.username,
            "action": self._map_event_action(event.event_type),
            
            # Honeyclaw-specific fields
            "honeypot_id": event.honeypot_id,
            "honeypot_template": event.honeypot_template,
            "event_type": event.event_type.value,
            "service": event.service,
            "severity": event.severity.name.lower(),
            "severity_id": event.severity.value,
            
            # Session info
            "session_id": event.session_id,
            "session_duration_ms": event.session_duration_ms,
            
            # Threat intel
            "tags": event.tags,
            "mitre_attack_tactics": event.mitre_tactics,
            "mitre_attack_techniques": event.mitre_techniques,
            
            # Geo
            "src_country": event.geo_country,
            "src_city": event.geo_city,
            "src_asn": event.geo_asn,
            
            # Command/payload
            "command": event.command,
            "payload_hash": event.payload_hash,
            "payload_size": event.payload_size,
            
            # Event ID for dedup
            "event_id": event.generate_event_id(),
        }
        
        # Remove None values
        event_data = {k: v for k, v in event_data.items() if v is not None}
        
        # Build HEC payload
        hec_event = {
            "time": epoch_time,
            "host": event.honeypot_id,
            "event": event_data,
        }
        
        # Add optional HEC fields
        if self.config.index:
            hec_event["index"] = self.config.index
        if self.config.source:
            hec_event["source"] = self.config.source
        else:
            hec_event["source"] = f"honeyclaw:{event.service}"
        if self.config.sourcetype:
            hec_event["sourcetype"] = self.config.sourcetype
        else:
            hec_event["sourcetype"] = "honeyclaw:events"
        
        return hec_event
    
    def _map_event_action(self, event_type: EventType) -> str:
        """Map event type to Splunk CIM action field"""
        action_map = {
            EventType.CONNECTION: "allowed",
            EventType.AUTH_ATTEMPT: "unknown",
            EventType.AUTH_SUCCESS: "success",
            EventType.AUTH_FAILURE: "failure",
            EventType.COMMAND: "executed",
            EventType.FILE_ACCESS: "allowed",
            EventType.DATA_EXFIL: "blocked",
            EventType.SCAN: "blocked",
            EventType.EXPLOIT_ATTEMPT: "blocked",
            EventType.MALWARE: "blocked",
            EventType.LATERAL_MOVEMENT: "blocked",
            EventType.UNKNOWN: "unknown",
        }
        return action_map.get(event_type, "unknown")
    
    def _send_request(self, payload: str) -> bool:
        """
        Send HTTP request to HEC endpoint.
        
        Args:
            payload: JSON payload string
            
        Returns:
            True if successful
        """
        headers = {
            "Authorization": f"Splunk {self.config.token}",
            "Content-Type": "application/json",
        }
        
        request = urllib.request.Request(
            self._hec_url,
            data=payload.encode('utf-8'),
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
                    if response.status == 200:
                        return True
                    else:
                        last_error = f"HTTP {response.status}"
                        
            except urllib.error.HTTPError as e:
                last_error = f"HTTP {e.code}: {e.reason}"
                if e.code in (400, 401, 403):
                    # Don't retry client errors
                    break
                    
            except urllib.error.URLError as e:
                last_error = f"URL Error: {e.reason}"
                
            except Exception as e:
                last_error = str(e)
            
            # Wait before retry
            if attempt < self.config.max_retries - 1:
                delay = self.config.retry_delay_seconds * (2 ** attempt)
                logger.warning(f"Splunk HEC retry in {delay}s: {last_error}")
                time.sleep(delay)
        
        self._log_failure(last_error)
        return False
    
    def send(self, event: HoneypotEvent) -> bool:
        """Send a single event to Splunk HEC"""
        hec_event = self._format_event(event)
        payload = json.dumps(hec_event)
        
        if self._send_request(payload):
            self._log_success(1)
            return True
        return False
    
    def send_batch(self, events: List[HoneypotEvent]) -> int:
        """
        Send multiple events to Splunk HEC.
        
        HEC supports newline-delimited JSON for batch events.
        """
        if not events:
            return 0
        
        # Format all events
        hec_events = [self._format_event(e) for e in events]
        
        # HEC batch format: newline-delimited JSON
        payload = '\n'.join(json.dumps(e) for e in hec_events)
        
        if self._send_request(payload):
            self._log_success(len(events))
            return len(events)
        
        # On failure, try sending individually
        logger.warning("Batch failed, falling back to individual sends")
        success_count = 0
        for event in events:
            if self.send(event):
                success_count += 1
        
        return success_count
    
    def test_connection(self) -> bool:
        """
        Test connection to Splunk HEC.
        
        Sends a test event to verify connectivity and authentication.
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
            logger.error(f"Splunk HEC connection test failed: {e}")
            return False
    
    def get_health_endpoint(self) -> str:
        """Return the HEC health check endpoint"""
        base = self.config.endpoint.rstrip('/')
        return f"{base}/services/collector/health"
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check HEC health status.
        
        Returns health info dict or error info.
        """
        health_url = self.get_health_endpoint()
        
        request = urllib.request.Request(
            health_url,
            headers={"Authorization": f"Splunk {self.config.token}"},
            method='GET'
        )
        
        try:
            with urllib.request.urlopen(
                request,
                timeout=10,
                context=self._ssl_context
            ) as response:
                data = json.loads(response.read().decode())
                return {
                    "healthy": True,
                    "status": data,
                }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e),
            }


# Convenience function for quick setup
def create_splunk_connector(
    endpoint: str,
    token: str,
    index: str = "main",
    verify_ssl: bool = True
) -> SplunkHECConnector:
    """
    Create a Splunk HEC connector with minimal config.
    
    Args:
        endpoint: HEC endpoint URL (e.g., https://splunk:8088)
        token: HEC authentication token
        index: Target Splunk index
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Configured SplunkHECConnector
    """
    return SplunkHECConnector({
        'provider': 'splunk',
        'endpoint': endpoint,
        'token': token,
        'index': index,
        'verify_ssl': verify_ssl,
    })
