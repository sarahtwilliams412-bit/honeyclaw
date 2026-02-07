#!/usr/bin/env python3
"""
Honeyclaw SIEM Integration - Elasticsearch Connector

Pushes honeypot events directly to Elasticsearch for use with
Elastic SIEM, Kibana, or custom detection pipelines.

Configuration:
    siem:
      provider: elastic
      endpoint: https://elasticsearch.example.com:9200
      api_key: ${ELASTIC_API_KEY}
      index: honeyclaw-events

Usage:
    from honeyclaw.integrations import ElasticsearchConnector
    
    connector = ElasticsearchConnector({
        'endpoint': 'https://localhost:9200',
        'api_key': 'your-api-key',
        'index': 'honeyclaw-events',
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

logger = logging.getLogger('honeyclaw.siem.elastic')


class ElasticsearchConnector(SIEMConnector):
    """
    Elasticsearch connector for Elastic SIEM integration.
    
    Features:
    - Direct indexing via Elasticsearch REST API
    - ECS (Elastic Common Schema) field mapping
    - Bulk API support for efficient batch indexing
    - API key or basic authentication
    - Data stream support for time-series data
    """
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        
        # Validate required config
        if not self.config.endpoint:
            raise ValueError("Elasticsearch endpoint is required")
        
        # Determine auth method
        self._auth_header = self._build_auth_header()
        
        # Build base URL
        self._base_url = self.config.endpoint.rstrip('/')
        
        # Index name (supports date patterns)
        self._index = self.config.index or 'honeyclaw-events'
        
        # SSL context
        self._ssl_context = self._build_ssl_context()
        
        # Track if index template exists
        self._template_created = False
        
        logger.info(f"Elasticsearch connector initialized: {self._base_url}")
    
    @property
    def provider_name(self) -> str:
        return "elasticsearch"
    
    def _build_auth_header(self) -> Optional[str]:
        """Build authentication header"""
        if self.config.api_key:
            # API key auth: base64 encode id:key format or use as-is
            if ':' in self.config.api_key:
                encoded = base64.b64encode(self.config.api_key.encode()).decode()
                return f"ApiKey {encoded}"
            else:
                return f"ApiKey {self.config.api_key}"
        
        elif self.config.username and self.config.password:
            # Basic auth
            credentials = f"{self.config.username}:{self.config.password}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return f"Basic {encoded}"
        
        return None
    
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
        Format HoneypotEvent for Elasticsearch using ECS.
        
        Maps to Elastic Common Schema (ECS) fields where applicable.
        https://www.elastic.co/guide/en/ecs/current/index.html
        """
        # ECS-compliant document
        doc = {
            # ECS Base fields
            "@timestamp": event.timestamp,
            "message": self._build_message(event),
            "tags": event.tags or [],
            
            # ECS Event fields
            "event": {
                "kind": "event",
                "category": [self._map_category(event.event_type)],
                "type": [self._map_event_type(event.event_type)],
                "action": event.event_type.value,
                "outcome": self._map_outcome(event.event_type),
                "severity": event.severity.value,
                "duration": event.session_duration_ms * 1000000 if event.session_duration_ms else None,
                "id": event.generate_event_id(),
                "dataset": "honeyclaw.events",
                "module": "honeyclaw",
            },
            
            # ECS Source fields
            "source": {
                "ip": event.source_ip,
                "port": event.source_port,
                "geo": {
                    "country_iso_code": event.geo_country,
                    "city_name": event.geo_city,
                } if event.geo_country else None,
                "as": {
                    "organization": {"name": event.geo_asn}
                } if event.geo_asn else None,
            },
            
            # ECS Destination fields  
            "destination": {
                "port": event.destination_port,
            } if event.destination_port else None,
            
            # ECS Network fields
            "network": {
                "transport": event.protocol,
                "protocol": event.service,
            },
            
            # ECS User fields (for auth events)
            "user": {
                "name": event.username,
            } if event.username else None,
            
            # ECS Process fields (for command events)
            "process": {
                "command_line": event.command,
            } if event.command else None,
            
            # ECS File fields (for file/payload events)
            "file": {
                "hash": {"sha256": event.payload_hash},
                "size": event.payload_size,
            } if event.payload_hash else None,
            
            # ECS Threat fields
            "threat": {
                "framework": "MITRE ATT&CK",
                "tactic": {
                    "name": event.mitre_tactics,
                } if event.mitre_tactics else None,
                "technique": {
                    "id": event.mitre_techniques,
                    "name": event.mitre_technique_names,
                } if event.mitre_techniques else None,
            } if event.mitre_tactics or event.mitre_techniques else None,
            
            # ECS Observer fields (honeypot as observer)
            "observer": {
                "type": "honeypot",
                "name": event.honeypot_id,
                "product": "honeyclaw",
                "version": event.collector_version,
                "vendor": "honeyclaw",
            },
            
            # Honeyclaw-specific fields (in custom namespace)
            "honeyclaw": {
                "honeypot_id": event.honeypot_id,
                "honeypot_template": event.honeypot_template,
                "service": event.service,
                "session_id": event.session_id,
                "password_length": event.password_length,
                "auth_method": event.auth_method,
            },
        }
        
        # Clean up None values recursively
        doc = self._clean_nones(doc)
        
        return doc
    
    def _clean_nones(self, d: Dict) -> Dict:
        """Recursively remove None values from dict"""
        if not isinstance(d, dict):
            return d
        return {
            k: self._clean_nones(v) if isinstance(v, dict) else v
            for k, v in d.items()
            if v is not None and v != {} and v != []
        }
    
    def _build_message(self, event: HoneypotEvent) -> str:
        """Build human-readable message for the event"""
        msg_parts = [
            f"Honeypot {event.honeypot_id}:",
            f"{event.event_type.value} from {event.source_ip}",
            f"on {event.service}",
        ]
        
        if event.username:
            msg_parts.append(f"(user: {event.username})")
        if event.command:
            msg_parts.append(f"cmd: {event.command[:50]}...")
        
        return " ".join(msg_parts)
    
    def _map_category(self, event_type: EventType) -> str:
        """Map to ECS event.category"""
        categories = {
            EventType.CONNECTION: "network",
            EventType.AUTH_ATTEMPT: "authentication",
            EventType.AUTH_SUCCESS: "authentication",
            EventType.AUTH_FAILURE: "authentication",
            EventType.COMMAND: "process",
            EventType.FILE_ACCESS: "file",
            EventType.DATA_EXFIL: "network",
            EventType.SCAN: "network",
            EventType.EXPLOIT_ATTEMPT: "intrusion_detection",
            EventType.MALWARE: "malware",
            EventType.LATERAL_MOVEMENT: "network",
            EventType.UNKNOWN: "host",
        }
        return categories.get(event_type, "host")
    
    def _map_event_type(self, event_type: EventType) -> str:
        """Map to ECS event.type"""
        types = {
            EventType.CONNECTION: "connection",
            EventType.AUTH_ATTEMPT: "start",
            EventType.AUTH_SUCCESS: "allowed",
            EventType.AUTH_FAILURE: "denied",
            EventType.COMMAND: "start",
            EventType.FILE_ACCESS: "access",
            EventType.DATA_EXFIL: "denied",
            EventType.SCAN: "denied",
            EventType.EXPLOIT_ATTEMPT: "denied",
            EventType.MALWARE: "denied",
            EventType.LATERAL_MOVEMENT: "denied",
            EventType.UNKNOWN: "info",
        }
        return types.get(event_type, "info")
    
    def _map_outcome(self, event_type: EventType) -> str:
        """Map to ECS event.outcome"""
        if event_type == EventType.AUTH_SUCCESS:
            return "success"
        elif event_type in (EventType.AUTH_FAILURE, EventType.EXPLOIT_ATTEMPT):
            return "failure"
        return "unknown"
    
    def _get_index_name(self) -> str:
        """Get index name, expanding date patterns"""
        index = self._index
        
        # Support date pattern like honeyclaw-events-YYYY.MM.DD
        if '%' in index or '{' in index:
            now = datetime.now(timezone.utc)
            index = index.replace('%Y', str(now.year))
            index = index.replace('%m', f"{now.month:02d}")
            index = index.replace('%d', f"{now.day:02d}")
            index = index.replace('{now/d}', now.strftime('%Y.%m.%d'))
        
        return index
    
    def _send_request(
        self, 
        method: str, 
        path: str, 
        body: Optional[str] = None
    ) -> Optional[Dict]:
        """
        Send HTTP request to Elasticsearch.
        
        Args:
            method: HTTP method
            path: URL path (will be appended to base URL)
            body: JSON body string
            
        Returns:
            Response dict or None on failure
        """
        url = f"{self._base_url}{path}"
        
        headers = {
            "Content-Type": "application/json",
        }
        if self._auth_header:
            headers["Authorization"] = self._auth_header
        
        request = urllib.request.Request(
            url,
            data=body.encode('utf-8') if body else None,
            headers=headers,
            method=method
        )
        
        last_error = None
        for attempt in range(self.config.max_retries):
            try:
                with urllib.request.urlopen(
                    request,
                    timeout=self.config.timeout_seconds,
                    context=self._ssl_context
                ) as response:
                    return json.loads(response.read().decode())
                    
            except urllib.error.HTTPError as e:
                last_error = f"HTTP {e.code}: {e.reason}"
                if e.code in (400, 401, 403, 404):
                    break
                    
            except urllib.error.URLError as e:
                last_error = f"URL Error: {e.reason}"
                
            except Exception as e:
                last_error = str(e)
            
            if attempt < self.config.max_retries - 1:
                delay = self.config.retry_delay_seconds * (2 ** attempt)
                logger.warning(f"Elasticsearch retry in {delay}s: {last_error}")
                time.sleep(delay)
        
        self._log_failure(last_error)
        return None
    
    def send(self, event: HoneypotEvent) -> bool:
        """Send a single event to Elasticsearch"""
        doc = self._format_event(event)
        index = self._get_index_name()
        
        result = self._send_request(
            'POST',
            f"/{index}/_doc",
            json.dumps(doc)
        )
        
        if result and result.get('result') in ('created', 'updated'):
            self._log_success(1)
            return True
        
        return False
    
    def send_batch(self, events: List[HoneypotEvent]) -> int:
        """
        Send multiple events using Elasticsearch Bulk API.
        
        Format:
        {"index": {"_index": "..."}}
        {"doc": "..."}
        ...
        """
        if not events:
            return 0
        
        index = self._get_index_name()
        
        # Build bulk request body
        lines = []
        for event in events:
            action = {"index": {"_index": index}}
            doc = self._format_event(event)
            lines.append(json.dumps(action))
            lines.append(json.dumps(doc))
        
        # Bulk API requires trailing newline
        body = '\n'.join(lines) + '\n'
        
        result = self._send_request('POST', '/_bulk', body)
        
        if result:
            # Count successes
            if result.get('errors', True):
                # Some failed - count successes
                success_count = sum(
                    1 for item in result.get('items', [])
                    if item.get('index', {}).get('status') in (200, 201)
                )
            else:
                success_count = len(events)
            
            self._log_success(success_count)
            return success_count
        
        return 0
    
    def test_connection(self) -> bool:
        """Test connection to Elasticsearch"""
        result = self._send_request('GET', '/', None)
        
        if result and result.get('cluster_name'):
            logger.info(f"Connected to Elasticsearch cluster: {result['cluster_name']}")
            return True
        
        return False
    
    def create_index_template(self) -> bool:
        """
        Create index template for honeyclaw events.
        
        This sets up proper field mappings for ECS compliance.
        """
        template = {
            "index_patterns": [f"{self._index}*", "honeyclaw-*"],
            "priority": 100,
            "template": {
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 1,
                },
                "mappings": {
                    "properties": {
                        "@timestamp": {"type": "date"},
                        "message": {"type": "text"},
                        "tags": {"type": "keyword"},
                        "event": {
                            "properties": {
                                "kind": {"type": "keyword"},
                                "category": {"type": "keyword"},
                                "type": {"type": "keyword"},
                                "action": {"type": "keyword"},
                                "outcome": {"type": "keyword"},
                                "severity": {"type": "integer"},
                                "id": {"type": "keyword"},
                            }
                        },
                        "source": {
                            "properties": {
                                "ip": {"type": "ip"},
                                "port": {"type": "integer"},
                                "geo": {
                                    "properties": {
                                        "country_iso_code": {"type": "keyword"},
                                        "city_name": {"type": "keyword"},
                                    }
                                },
                            }
                        },
                        "destination": {
                            "properties": {
                                "port": {"type": "integer"},
                            }
                        },
                        "user": {
                            "properties": {
                                "name": {"type": "keyword"},
                            }
                        },
                        "observer": {
                            "properties": {
                                "name": {"type": "keyword"},
                                "type": {"type": "keyword"},
                            }
                        },
                        "honeyclaw": {
                            "properties": {
                                "honeypot_id": {"type": "keyword"},
                                "honeypot_template": {"type": "keyword"},
                                "service": {"type": "keyword"},
                                "session_id": {"type": "keyword"},
                            }
                        },
                    }
                }
            }
        }
        
        result = self._send_request(
            'PUT',
            '/_index_template/honeyclaw',
            json.dumps(template)
        )
        
        if result and result.get('acknowledged'):
            logger.info("Created Elasticsearch index template: honeyclaw")
            self._template_created = True
            return True
        
        return False
    
    def get_cluster_health(self) -> Dict[str, Any]:
        """Get Elasticsearch cluster health"""
        result = self._send_request('GET', '/_cluster/health', None)
        return result or {"status": "unknown"}


# Convenience function
def create_elastic_connector(
    endpoint: str,
    api_key: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    index: str = 'honeyclaw-events',
    verify_ssl: bool = True
) -> ElasticsearchConnector:
    """
    Create an Elasticsearch connector with minimal config.
    
    Args:
        endpoint: Elasticsearch URL (e.g., https://localhost:9200)
        api_key: API key for authentication
        username: Username for basic auth (if not using api_key)
        password: Password for basic auth
        index: Target index name
        verify_ssl: Whether to verify SSL certificates
        
    Returns:
        Configured ElasticsearchConnector
    """
    return ElasticsearchConnector({
        'provider': 'elastic',
        'endpoint': endpoint,
        'api_key': api_key,
        'username': username,
        'password': password,
        'index': index,
        'verify_ssl': verify_ssl,
    })
