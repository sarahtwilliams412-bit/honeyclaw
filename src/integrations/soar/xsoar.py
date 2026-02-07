#!/usr/bin/env python3
"""
Honeyclaw SOAR Integration - Palo Alto XSOAR (Demisto) Connector

Creates incidents and triggers playbooks in Palo Alto Cortex XSOAR.

XSOAR API:
    - POST /incident - Create incident
    - POST /incident/investigate - Create and investigate
    - POST /inv-playbook/run - Trigger playbook

Configuration:
    soar:
      provider: xsoar
      endpoint: https://xsoar.example.com
      api_key: ${XSOAR_API_KEY}

Usage:
    from honeyclaw.integrations.soar import XSOARConnector

    connector = XSOARConnector({
        'endpoint': 'https://xsoar.example.com',
        'api_key': 'your-api-key',
    })

    alert = SOARAlert(...)
    connector.create_alert(alert)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any

from .base import (
    SOARConnector,
    SOARAlert,
    IncidentSeverity,
    TLP,
)

logger = logging.getLogger('honeyclaw.soar.xsoar')


class XSOARConnector(SOARConnector):
    """
    Palo Alto Cortex XSOAR (Demisto) connector.

    Creates incidents with indicator extraction and triggers
    automated investigation playbooks.

    Features:
    - Incident creation with XSOAR field mapping
    - Indicator extraction (IP, domain, hash)
    - Playbook triggering with parameter passing
    - Investigation context population
    - Severity and type mapping
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        if not self.config.endpoint:
            raise ValueError("XSOAR endpoint is required")
        if not self.config.api_key:
            raise ValueError("XSOAR API key is required")

        self._base_url = self.config.endpoint.rstrip('/')
        self._headers = {
            'Authorization': self.config.api_key,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

        logger.info(f"XSOAR connector initialized: {self._base_url}")

    @property
    def provider_name(self) -> str:
        return "xsoar"

    def create_alert(self, alert: SOARAlert) -> Optional[str]:
        """
        Create an incident in XSOAR.

        Maps SOARAlert to XSOAR incident format with custom fields
        and indicator extraction.
        """
        incident = self._format_incident(alert)

        response = self._http_request(
            'POST',
            f'{self._base_url}/incident',
            data=incident,
            headers=self._headers,
        )

        if response and 'id' in response:
            incident_id = response['id']
            self._stats['alerts_created'] += 1
            logger.info(f"XSOAR incident created: {incident_id}")
            return incident_id

        self._stats['alerts_failed'] += 1
        return None

    def create_and_investigate(self, alert: SOARAlert) -> Optional[str]:
        """
        Create an incident and immediately start investigation.

        This triggers the default playbook for the incident type.
        """
        incident = self._format_incident(alert)

        response = self._http_request(
            'POST',
            f'{self._base_url}/incident/investigate',
            data=incident,
            headers=self._headers,
        )

        if response and 'id' in response:
            incident_id = response['id']
            self._stats['alerts_created'] += 1
            logger.info(f"XSOAR incident created and investigating: {incident_id}")
            return incident_id

        self._stats['alerts_failed'] += 1
        return None

    def trigger_playbook(self, playbook_id: str, alert: SOARAlert,
                         parameters: Optional[Dict[str, Any]] = None) -> bool:
        """
        Trigger a playbook in XSOAR.

        Args:
            playbook_id: Playbook ID or name
            alert: Alert context for the playbook
            parameters: Input parameters for the playbook
        """
        run_data = {
            'investigationId': alert.alert_id,
            'playbookId': playbook_id,
        }
        if parameters:
            run_data['inputs'] = parameters

        response = self._http_request(
            'POST',
            f'{self._base_url}/inv-playbook/run',
            data=run_data,
            headers=self._headers,
        )

        if response:
            logger.info(f"XSOAR playbook triggered: {playbook_id}")
            return True

        logger.error(f"Failed to trigger XSOAR playbook: {playbook_id}")
        return False

    def create_indicator(self, indicator_type: str, value: str,
                         score: int = 2, source: str = "honeyclaw") -> Optional[str]:
        """
        Create an indicator (IOC) in XSOAR.

        Args:
            indicator_type: Type (IP, Domain, File, URL, etc.)
            value: Indicator value
            score: XSOAR reputation score (0=Unknown, 1=Good, 2=Suspicious, 3=Bad)
            source: Source of the indicator

        Returns:
            Indicator ID if created
        """
        indicator = {
            'indicator': {
                'indicator_type': indicator_type,
                'value': value,
                'score': score,
                'source': source,
                'sourceBrands': ['Honeyclaw'],
                'comment': f'Observed in honeypot attack',
            },
        }

        response = self._http_request(
            'POST',
            f'{self._base_url}/indicator/create',
            data=indicator,
            headers=self._headers,
        )

        if response and 'id' in response:
            return response['id']
        return None

    def test_connection(self) -> bool:
        """Test connectivity to XSOAR"""
        response = self._http_request(
            'GET',
            f'{self._base_url}/user',
            headers=self._headers,
        )
        if response and 'id' in response:
            logger.info(f"XSOAR connection verified: user={response.get('username', 'unknown')}")
            return True

        logger.error("XSOAR connection test failed")
        return False

    def _format_incident(self, alert: SOARAlert) -> Dict[str, Any]:
        """Format SOARAlert as XSOAR incident"""
        incident = {
            'name': f'[Honeyclaw] {alert.title}',
            'type': self._map_incident_type(alert.event_type),
            'severity': self._map_severity(alert.severity),
            'details': alert.description,
            'labels': self._build_labels(alert),
            'createInvestigation': True,
            'CustomFields': {
                'honeypotid': alert.honeypot_id,
                'attackerip': alert.source_ip,
                'attackservice': alert.service,
                'sessionid': alert.session_id or '',
                'honeyclawsource': True,
            },
        }

        if self.config.default_playbook_id:
            incident['playbookId'] = self.config.default_playbook_id

        return incident

    def _build_labels(self, alert: SOARAlert) -> List[Dict[str, str]]:
        """Build XSOAR labels from alert data"""
        labels = [
            {'type': 'source', 'value': 'honeyclaw'},
            {'type': 'honeypot_id', 'value': alert.honeypot_id},
            {'type': 'source_ip', 'value': alert.source_ip},
            {'type': 'event_type', 'value': alert.event_type},
            {'type': 'service', 'value': alert.service},
        ]

        if alert.username:
            labels.append({'type': 'username', 'value': alert.username})

        if alert.geo_country:
            labels.append({'type': 'geo_country', 'value': alert.geo_country})

        for tag in alert.tags:
            labels.append({'type': 'tag', 'value': tag})

        for tactic in alert.mitre_tactics:
            labels.append({'type': 'mitre_tactic', 'value': tactic})

        for technique in alert.mitre_techniques:
            labels.append({'type': 'mitre_technique', 'value': technique})

        return labels

    @staticmethod
    def _map_severity(severity: IncidentSeverity) -> int:
        """Map to XSOAR severity (0-4)"""
        mapping = {
            IncidentSeverity.LOW: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.HIGH: 3,
            IncidentSeverity.CRITICAL: 4,
        }
        return mapping.get(severity, 2)

    @staticmethod
    def _map_incident_type(event_type: str) -> str:
        """Map honeypot event type to XSOAR incident type"""
        type_mapping = {
            'auth_success': 'Access',
            'auth_failure': 'Brute Force',
            'auth_attempt': 'Brute Force',
            'command': 'Malware',
            'exploit_attempt': 'Exploit',
            'data_exfil': 'Data Exfiltration',
            'malware': 'Malware',
            'lateral_movement': 'Lateral Movement',
            'scan': 'Reconnaissance',
        }
        return type_mapping.get(event_type, 'Unclassified')
