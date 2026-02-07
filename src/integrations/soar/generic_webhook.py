#!/usr/bin/env python3
"""
Honeyclaw SOAR Integration - Generic SOAR Webhook Connector

Supports any SOAR platform via configurable webhook payloads.
Uses Jinja2-style template substitution for payload customization.

Configuration:
    soar:
      provider: generic
      endpoint: https://soar.example.com/api/webhook
      api_key: ${SOAR_API_KEY}

Usage:
    from honeyclaw.integrations.soar import GenericSOARWebhook

    connector = GenericSOARWebhook({
        'endpoint': 'https://soar.example.com/api/webhook',
        'api_key': 'your-api-key',
    })

    alert = SOARAlert(...)
    connector.create_alert(alert)
"""

import json
import logging
import string
from typing import Optional, Dict, List, Any

from .base import (
    SOARConnector,
    SOARAlert,
    IncidentSeverity,
    TLP,
)

logger = logging.getLogger('honeyclaw.soar.generic')

# Default payload template for generic SOAR webhooks
DEFAULT_ALERT_TEMPLATE = {
    'source': 'honeyclaw',
    'type': 'honeypot_alert',
    'alert_id': '${alert_id}',
    'title': '${title}',
    'description': '${description}',
    'severity': '${severity}',
    'timestamp': '${timestamp}',
    'honeypot_id': '${honeypot_id}',
    'event_type': '${event_type}',
    'source_ip': '${source_ip}',
    'service': '${service}',
    'indicators': [],
    'mitre': {
        'tactics': [],
        'techniques': [],
    },
    'tags': [],
}

DEFAULT_PLAYBOOK_TEMPLATE = {
    'source': 'honeyclaw',
    'type': 'playbook_trigger',
    'playbook_id': '${playbook_id}',
    'alert_id': '${alert_id}',
    'parameters': {},
}


class GenericSOARWebhook(SOARConnector):
    """
    Generic SOAR webhook connector.

    Sends alerts and playbook triggers via configurable webhook payloads.
    Supports template-based payload customization for any SOAR platform.

    Features:
    - Configurable payload templates
    - Variable substitution from alert fields
    - Custom header support
    - Bearer token and API key authentication
    - Payload signing (HMAC) support
    """

    def __init__(self, config: Dict[str, Any]):
        # Extract template configs before parent init
        self._alert_template = config.pop('alert_template', None)
        self._playbook_template = config.pop('playbook_template', None)
        self._custom_headers = config.pop('custom_headers', {})
        self._auth_scheme = config.pop('auth_scheme', 'bearer')  # bearer, apikey, header

        super().__init__(config)

        if not self.config.endpoint:
            raise ValueError("Webhook endpoint is required")

        self._base_url = self.config.endpoint.rstrip('/')

        # Build auth headers
        self._auth_headers = self._build_auth_headers()

        logger.info(f"Generic SOAR webhook initialized: {self._base_url}")

    @property
    def provider_name(self) -> str:
        return "generic"

    def create_alert(self, alert: SOARAlert) -> Optional[str]:
        """
        Send alert to generic SOAR webhook.

        Uses the configured alert template or builds a default payload.
        """
        payload = self._build_alert_payload(alert)

        headers = {**self._auth_headers, **self._custom_headers}

        response = self._http_request(
            'POST',
            self._base_url,
            data=payload,
            headers=headers,
        )

        if response is not None:
            self._stats['alerts_created'] += 1
            # Try to extract an ID from the response
            alert_id = (
                response.get('id')
                or response.get('alert_id')
                or response.get('incident_id')
                or alert.alert_id
            )
            logger.info(f"Generic SOAR alert sent: {alert_id}")
            return str(alert_id)

        self._stats['alerts_failed'] += 1
        return None

    def trigger_playbook(self, playbook_id: str, alert: SOARAlert,
                         parameters: Optional[Dict[str, Any]] = None) -> bool:
        """
        Send playbook trigger to generic SOAR webhook.

        Posts to {endpoint}/playbook (or custom URL if configured).
        """
        payload = self._build_playbook_payload(playbook_id, alert, parameters)

        headers = {**self._auth_headers, **self._custom_headers}

        # Use a /playbook sub-path for playbook triggers
        playbook_url = f'{self._base_url}/playbook'

        response = self._http_request(
            'POST',
            playbook_url,
            data=payload,
            headers=headers,
        )

        if response is not None:
            logger.info(f"Generic SOAR playbook triggered: {playbook_id}")
            return True

        logger.error(f"Failed to trigger generic SOAR playbook: {playbook_id}")
        return False

    def test_connection(self) -> bool:
        """Test connectivity to the webhook endpoint"""
        headers = {**self._auth_headers, **self._custom_headers}

        test_payload = {
            'source': 'honeyclaw',
            'type': 'connection_test',
            'message': 'Honeyclaw SOAR integration test',
        }

        response = self._http_request(
            'POST',
            self._base_url,
            data=test_payload,
            headers=headers,
        )

        if response is not None:
            logger.info("Generic SOAR webhook connection verified")
            return True

        logger.error("Generic SOAR webhook connection test failed")
        return False

    def _build_alert_payload(self, alert: SOARAlert) -> Dict[str, Any]:
        """Build alert payload using template or defaults"""
        if self._alert_template:
            return self._apply_template(self._alert_template, alert)

        # Build default payload
        payload = {
            'source': 'honeyclaw',
            'type': 'honeypot_alert',
            'alert_id': alert.alert_id,
            'title': alert.title,
            'description': alert.description,
            'severity': alert.severity.name.lower(),
            'severity_level': alert.severity.value,
            'timestamp': alert.timestamp,
            'honeypot_id': alert.honeypot_id,
            'event_type': alert.event_type,
            'service': alert.service,
            'tlp': alert.tlp.value,
            'indicators': [],
            'mitre': {
                'tactics': alert.mitre_tactics,
                'techniques': alert.mitre_techniques,
            },
            'tags': alert.tags,
        }

        # Add indicators
        if alert.source_ip and alert.source_ip != 'unknown':
            indicator = {
                'type': 'ip',
                'value': alert.source_ip,
                'role': 'attacker',
            }
            if alert.geo_country:
                indicator['geo'] = {
                    'country': alert.geo_country,
                    'city': alert.geo_city,
                    'asn': alert.geo_asn,
                }
            payload['indicators'].append(indicator)

        if alert.username:
            payload['indicators'].append({
                'type': 'username',
                'value': alert.username,
                'role': 'credential',
            })

        if alert.command:
            payload['command'] = alert.command

        if alert.session_id:
            payload['session_id'] = alert.session_id

        if alert.destination_port:
            payload['destination_port'] = alert.destination_port

        return payload

    def _build_playbook_payload(self, playbook_id: str, alert: SOARAlert,
                                parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build playbook trigger payload"""
        if self._playbook_template:
            context = {
                'playbook_id': playbook_id,
                'alert_id': alert.alert_id,
                'source_ip': alert.source_ip,
                'severity': alert.severity.name.lower(),
            }
            if parameters:
                context.update(parameters)
            return self._apply_template(self._playbook_template, alert, context)

        payload = {
            'source': 'honeyclaw',
            'type': 'playbook_trigger',
            'playbook_id': playbook_id,
            'alert_id': alert.alert_id,
            'alert': {
                'title': alert.title,
                'source_ip': alert.source_ip,
                'severity': alert.severity.name.lower(),
                'event_type': alert.event_type,
                'honeypot_id': alert.honeypot_id,
            },
            'parameters': parameters or {},
        }

        return payload

    def _apply_template(self, template: Dict[str, Any], alert: SOARAlert,
                        extra_context: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """Apply variable substitution to a template"""
        context = {
            'alert_id': alert.alert_id or '',
            'title': alert.title,
            'description': alert.description,
            'severity': alert.severity.name.lower(),
            'timestamp': alert.timestamp or '',
            'honeypot_id': alert.honeypot_id,
            'event_type': alert.event_type,
            'source_ip': alert.source_ip,
            'service': alert.service,
            'username': alert.username or '',
            'command': alert.command or '',
            'session_id': alert.session_id or '',
        }
        if extra_context:
            context.update(extra_context)

        return self._substitute_dict(template, context)

    def _substitute_dict(self, obj: Any, context: Dict[str, str]) -> Any:
        """Recursively substitute ${var} patterns in a dict/list/string"""
        if isinstance(obj, str):
            # Simple ${var} substitution
            for key, value in context.items():
                obj = obj.replace(f'${{{key}}}', str(value))
            return obj
        elif isinstance(obj, dict):
            return {k: self._substitute_dict(v, context) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._substitute_dict(item, context) for item in obj]
        return obj

    def _build_auth_headers(self) -> Dict[str, str]:
        """Build authentication headers based on config"""
        headers = {}

        if self._auth_scheme == 'bearer' and self.config.token:
            headers['Authorization'] = f'Bearer {self.config.token}'
        elif self._auth_scheme == 'bearer' and self.config.api_key:
            headers['Authorization'] = f'Bearer {self.config.api_key}'
        elif self._auth_scheme == 'apikey' and self.config.api_key:
            headers['X-API-Key'] = self.config.api_key
        elif self._auth_scheme == 'header' and self.config.api_key:
            # Custom header name can be specified in custom_headers
            headers['Authorization'] = self.config.api_key

        return headers
