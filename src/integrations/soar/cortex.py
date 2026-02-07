#!/usr/bin/env python3
"""
Honeyclaw SOAR Integration - TheHive/Cortex Connector

Creates alerts and triggers analyzers/responders in TheHive + Cortex.

TheHive API v1 (TheHive 5.x):
    - POST /api/v1/alert - Create alert
    - POST /api/v1/case - Create case
    - POST /api/connector/cortex/job - Run analyzer/responder

Configuration:
    soar:
      provider: cortex
      endpoint: https://thehive.example.com
      api_key: ${THEHIVE_API_KEY}
      org_id: honeyclaw

Usage:
    from honeyclaw.integrations.soar import CortexConnector

    connector = CortexConnector({
        'endpoint': 'https://thehive.example.com',
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

logger = logging.getLogger('honeyclaw.soar.cortex')


class CortexConnector(SOARConnector):
    """
    TheHive/Cortex SOAR connector.

    Creates alerts in TheHive and triggers Cortex analyzers/responders
    for automated incident response.

    Features:
    - Alert creation with full observable mapping
    - Case promotion from alerts
    - Cortex analyzer triggering (IP reputation, domain analysis, etc.)
    - Cortex responder triggering (block IP, update firewall, etc.)
    - TLP and PAP tagging
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        if not self.config.endpoint:
            raise ValueError("TheHive endpoint is required")
        if not self.config.api_key:
            raise ValueError("TheHive API key is required")

        self._base_url = self.config.endpoint.rstrip('/')
        self._headers = {
            'Authorization': f'Bearer {self.config.api_key}',
            'Content-Type': 'application/json',
        }
        if self.config.org_id:
            self._headers['X-Organisation'] = self.config.org_id

        logger.info(f"TheHive/Cortex connector initialized: {self._base_url}")

    @property
    def provider_name(self) -> str:
        return "cortex"

    def create_alert(self, alert: SOARAlert) -> Optional[str]:
        """
        Create an alert in TheHive.

        Maps SOARAlert to TheHive alert format with observables.
        """
        thehive_alert = self._format_alert(alert)

        response = self._http_request(
            'POST',
            f'{self._base_url}/api/v1/alert',
            data=thehive_alert,
            headers=self._headers,
        )

        if response and '_id' in response:
            alert_id = response['_id']
            self._stats['alerts_created'] += 1
            logger.info(f"TheHive alert created: {alert_id}")
            return alert_id

        self._stats['alerts_failed'] += 1
        return None

    def trigger_playbook(self, playbook_id: str, alert: SOARAlert,
                         parameters: Optional[Dict[str, Any]] = None) -> bool:
        """
        Trigger a Cortex responder as a playbook action.

        In TheHive/Cortex, 'playbooks' are Cortex responders.
        """
        job_data = {
            'cortexId': playbook_id.split(':')[0] if ':' in playbook_id else 'cortex-1',
            'responderId': playbook_id.split(':')[-1] if ':' in playbook_id else playbook_id,
            'objectType': 'Alert',
            'objectId': alert.alert_id,
            'parameters': parameters or {},
        }

        response = self._http_request(
            'POST',
            f'{self._base_url}/api/connector/cortex/job',
            data=job_data,
            headers=self._headers,
        )

        if response:
            logger.info(f"Cortex responder triggered: {playbook_id}")
            return True

        logger.error(f"Failed to trigger Cortex responder: {playbook_id}")
        return False

    def run_analyzer(self, analyzer_id: str, observable_type: str,
                     observable_value: str, cortex_id: str = "cortex-1") -> Optional[str]:
        """
        Run a Cortex analyzer on an observable.

        Args:
            analyzer_id: Cortex analyzer ID (e.g., 'Abuse_Finder_3_0')
            observable_type: Type of observable (ip, domain, hash, etc.)
            observable_value: The value to analyze
            cortex_id: Cortex instance ID

        Returns:
            Job ID if submitted successfully
        """
        job_data = {
            'cortexId': cortex_id,
            'analyzerId': analyzer_id,
            'artifactId': None,
            'parameters': {
                'dataType': observable_type,
                'data': observable_value,
                'tlp': 2,  # AMBER
            },
        }

        response = self._http_request(
            'POST',
            f'{self._base_url}/api/connector/cortex/job',
            data=job_data,
            headers=self._headers,
        )

        if response and '_id' in response:
            return response['_id']
        return None

    def create_case(self, alert: SOARAlert) -> Optional[str]:
        """
        Create a case directly in TheHive (bypassing alert stage).

        Useful for high-severity incidents that need immediate case management.
        """
        case_data = {
            'title': f'[Honeyclaw] {alert.title}',
            'description': alert.description,
            'severity': self._map_severity(alert.severity),
            'tlp': self._map_tlp(alert.tlp),
            'pap': 2,  # AMBER
            'tags': ['honeyclaw', 'honeypot'] + alert.tags,
            'flag': alert.severity == IncidentSeverity.CRITICAL,
            'tasks': self._generate_tasks(alert),
        }

        if alert.mitre_tactics:
            for tactic in alert.mitre_tactics:
                case_data['tags'].append(f'mitre:{tactic}')
        if alert.mitre_techniques:
            for technique in alert.mitre_techniques:
                case_data['tags'].append(f'mitre:{technique}')

        response = self._http_request(
            'POST',
            f'{self._base_url}/api/v1/case',
            data=case_data,
            headers=self._headers,
        )

        if response and '_id' in response:
            case_id = response['_id']
            logger.info(f"TheHive case created: {case_id}")
            return case_id
        return None

    def test_connection(self) -> bool:
        """Test connectivity to TheHive"""
        response = self._http_request(
            'GET',
            f'{self._base_url}/api/v1/user/current',
            headers=self._headers,
        )
        if response and '_id' in response:
            logger.info(f"TheHive connection verified: user={response.get('login', 'unknown')}")
            return True

        logger.error("TheHive connection test failed")
        return False

    def _format_alert(self, alert: SOARAlert) -> Dict[str, Any]:
        """Format SOARAlert for TheHive API v1"""
        observables = self._build_observables(alert)

        thehive_alert = {
            'type': 'honeyclaw',
            'source': 'honeyclaw',
            'sourceRef': alert.alert_id,
            'title': f'[Honeyclaw] {alert.title}',
            'description': self._build_thehive_description(alert),
            'severity': self._map_severity(alert.severity),
            'tlp': self._map_tlp(alert.tlp),
            'pap': 2,  # AMBER
            'tags': ['honeyclaw', 'honeypot', alert.event_type] + alert.tags,
            'date': int(datetime.now(timezone.utc).timestamp() * 1000),
            'observables': observables,
        }

        # Add MITRE tags
        if alert.mitre_tactics:
            for tactic in alert.mitre_tactics:
                thehive_alert['tags'].append(f'mitre:{tactic}')
        if alert.mitre_techniques:
            for technique in alert.mitre_techniques:
                thehive_alert['tags'].append(f'mitre:{technique}')

        return thehive_alert

    def _build_observables(self, alert: SOARAlert) -> List[Dict[str, Any]]:
        """Build TheHive observables from alert data"""
        observables = []

        # Source IP
        if alert.source_ip and alert.source_ip != 'unknown':
            observable = {
                'dataType': 'ip',
                'data': alert.source_ip,
                'message': f'Attacker IP from honeypot {alert.honeypot_id}',
                'tlp': self._map_tlp(alert.tlp),
                'ioc': True,
                'tags': ['honeyclaw', 'attacker-ip'],
            }
            if alert.geo_country:
                observable['tags'].append(f'country:{alert.geo_country}')
            observables.append(observable)

        # Username
        if alert.username:
            observables.append({
                'dataType': 'other',
                'data': alert.username,
                'message': f'Username used in attack against {alert.service}',
                'tlp': self._map_tlp(alert.tlp),
                'ioc': False,
                'tags': ['honeyclaw', 'username'],
            })

        # Command
        if alert.command:
            observables.append({
                'dataType': 'other',
                'data': alert.command[:1024],
                'message': 'Command executed on honeypot',
                'tlp': self._map_tlp(alert.tlp),
                'ioc': False,
                'tags': ['honeyclaw', 'command'],
            })

        return observables

    def _build_thehive_description(self, alert: SOARAlert) -> str:
        """Build markdown description for TheHive"""
        lines = [
            f'# Honeyclaw Alert: {alert.title}',
            '',
            f'**Honeypot:** {alert.honeypot_id}',
            f'**Service:** {alert.service}',
            f'**Source IP:** `{alert.source_ip}`',
            f'**Event Type:** {alert.event_type}',
            f'**Timestamp:** {alert.timestamp}',
        ]

        if alert.username:
            lines.append(f'**Username:** `{alert.username}`')
        if alert.command:
            lines.append(f'**Command:** `{alert.command}`')
        if alert.destination_port:
            lines.append(f'**Destination Port:** {alert.destination_port}')

        if alert.geo_country:
            lines.append(f'\n## Geolocation')
            lines.append(f'- Country: {alert.geo_country}')
            if alert.geo_city:
                lines.append(f'- City: {alert.geo_city}')
            if alert.geo_asn:
                lines.append(f'- ASN: {alert.geo_asn}')

        if alert.mitre_tactics or alert.mitre_techniques:
            lines.append(f'\n## MITRE ATT&CK')
            if alert.mitre_tactics:
                lines.append(f'- Tactics: {", ".join(alert.mitre_tactics)}')
            if alert.mitre_techniques:
                lines.append(f'- Techniques: {", ".join(alert.mitre_techniques)}')

        lines.append(f'\n---\n*Generated by Honeyclaw SOAR Integration*')

        return '\n'.join(lines)

    def _generate_tasks(self, alert: SOARAlert) -> List[Dict[str, Any]]:
        """Generate investigation tasks for a case"""
        tasks = [
            {
                'title': 'Verify attacker IP reputation',
                'description': f'Check {alert.source_ip} against threat intelligence feeds',
                'order': 0,
                'group': 'Investigation',
            },
            {
                'title': 'Review session recording',
                'description': f'Review session {alert.session_id or "N/A"} in replay dashboard',
                'order': 1,
                'group': 'Investigation',
            },
            {
                'title': 'Check for lateral movement',
                'description': 'Determine if the attacker has been seen on other honeypots',
                'order': 2,
                'group': 'Investigation',
            },
        ]

        if alert.severity == IncidentSeverity.CRITICAL:
            tasks.append({
                'title': 'Update firewall blocklist',
                'description': f'Block {alert.source_ip} on perimeter firewalls',
                'order': 3,
                'group': 'Containment',
            })

        return tasks

    @staticmethod
    def _map_severity(severity: IncidentSeverity) -> int:
        """Map to TheHive severity (1-4)"""
        return severity.value

    @staticmethod
    def _map_tlp(tlp: TLP) -> int:
        """Map TLP to TheHive numeric (0-3)"""
        mapping = {
            TLP.WHITE: 0,
            TLP.GREEN: 1,
            TLP.AMBER: 2,
            TLP.RED: 3,
        }
        return mapping.get(tlp, 2)
