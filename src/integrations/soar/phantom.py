#!/usr/bin/env python3
"""
Honeyclaw SOAR Integration - Splunk SOAR (Phantom) Connector

Creates containers/events and triggers playbooks in Splunk SOAR.

Splunk SOAR REST API:
    - POST /rest/container - Create container (incident)
    - POST /rest/artifact - Add artifact (observable)
    - POST /rest/playbook_run - Trigger playbook

Configuration:
    soar:
      provider: phantom
      endpoint: https://phantom.example.com
      token: ${PHANTOM_AUTH_TOKEN}

Usage:
    from honeyclaw.integrations.soar import PhantomConnector

    connector = PhantomConnector({
        'endpoint': 'https://phantom.example.com',
        'token': 'your-auth-token',
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

logger = logging.getLogger('honeyclaw.soar.phantom')


class PhantomConnector(SOARConnector):
    """
    Splunk SOAR (Phantom) connector.

    Creates containers (incidents) with artifacts (observables) and
    triggers automated playbooks for incident response.

    Features:
    - Container creation with CEF-mapped artifacts
    - Automatic playbook triggering by container label
    - Artifact IOC extraction and tagging
    - Severity and sensitivity mapping
    """

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)

        if not self.config.endpoint:
            raise ValueError("Splunk SOAR endpoint is required")
        if not self.config.token:
            raise ValueError("Splunk SOAR auth token is required")

        self._base_url = self.config.endpoint.rstrip('/')
        self._headers = {
            'ph-auth-token': self.config.token,
            'Content-Type': 'application/json',
        }

        logger.info(f"Splunk SOAR connector initialized: {self._base_url}")

    @property
    def provider_name(self) -> str:
        return "phantom"

    def create_alert(self, alert: SOARAlert) -> Optional[str]:
        """
        Create a container (incident) in Splunk SOAR.

        Splunk SOAR uses 'containers' as the top-level incident object,
        with 'artifacts' as the associated observables/IOCs.
        """
        container = self._format_container(alert)

        response = self._http_request(
            'POST',
            f'{self._base_url}/rest/container',
            data=container,
            headers=self._headers,
        )

        if response and 'id' in response:
            container_id = str(response['id'])
            self._stats['alerts_created'] += 1
            logger.info(f"Splunk SOAR container created: {container_id}")

            # Add artifacts to the container
            self._add_artifacts(container_id, alert)

            return container_id

        self._stats['alerts_failed'] += 1
        return None

    def trigger_playbook(self, playbook_id: str, alert: SOARAlert,
                         parameters: Optional[Dict[str, Any]] = None) -> bool:
        """
        Trigger a playbook in Splunk SOAR.

        Args:
            playbook_id: Playbook ID or name (e.g., 'local/honeyclaw_block_ip')
            alert: Alert context
            parameters: Additional playbook parameters
        """
        run_data = {
            'container_id': alert.alert_id,
            'playbook_id': playbook_id,
            'scope': 'new',
            'run': True,
        }

        response = self._http_request(
            'POST',
            f'{self._base_url}/rest/playbook_run',
            data=run_data,
            headers=self._headers,
        )

        if response and response.get('playbook_run_id'):
            logger.info(
                f"Splunk SOAR playbook triggered: {playbook_id} "
                f"(run_id={response['playbook_run_id']})"
            )
            return True

        logger.error(f"Failed to trigger Splunk SOAR playbook: {playbook_id}")
        return False

    def test_connection(self) -> bool:
        """Test connectivity to Splunk SOAR"""
        response = self._http_request(
            'GET',
            f'{self._base_url}/rest/version',
            headers=self._headers,
        )
        if response and 'version' in response:
            logger.info(f"Splunk SOAR connection verified: v{response['version']}")
            return True

        logger.error("Splunk SOAR connection test failed")
        return False

    def _format_container(self, alert: SOARAlert) -> Dict[str, Any]:
        """Format SOARAlert as Splunk SOAR container"""
        return {
            'name': f'[Honeyclaw] {alert.title}',
            'description': alert.description,
            'label': 'honeypot',
            'severity': self._map_severity(alert.severity),
            'sensitivity': self._map_tlp_to_sensitivity(alert.tlp),
            'status': 'new',
            'source_data_identifier': alert.alert_id,
            'container_type': 'default',
            'tags': ['honeyclaw', 'honeypot'] + alert.tags,
            'data': {
                'honeypot_id': alert.honeypot_id,
                'event_type': alert.event_type,
                'source_ip': alert.source_ip,
                'service': alert.service,
                'session_id': alert.session_id,
            },
            'custom_fields': {
                'honeypot_id': alert.honeypot_id,
                'attack_service': alert.service,
            },
        }

    def _add_artifacts(self, container_id: str, alert: SOARAlert):
        """Add artifacts (observables) to a container"""
        artifacts = self._build_artifacts(container_id, alert)

        for artifact in artifacts:
            response = self._http_request(
                'POST',
                f'{self._base_url}/rest/artifact',
                data=artifact,
                headers=self._headers,
            )
            if response and 'id' in response:
                logger.debug(f"Artifact added: {artifact['name']}")
            else:
                logger.warning(f"Failed to add artifact: {artifact['name']}")

    def _build_artifacts(self, container_id: str, alert: SOARAlert) -> List[Dict[str, Any]]:
        """Build Splunk SOAR artifacts with CEF fields"""
        artifacts = []

        # Source IP artifact
        if alert.source_ip and alert.source_ip != 'unknown':
            ip_artifact = {
                'container_id': int(container_id),
                'name': f'Attacker IP: {alert.source_ip}',
                'label': 'attacker',
                'source_data_identifier': f'{alert.alert_id}:ip:{alert.source_ip}',
                'type': 'ip',
                'severity': self._map_severity(alert.severity),
                'tags': ['honeyclaw', 'attacker-ip'],
                'cef': {
                    'sourceAddress': alert.source_ip,
                    'destinationPort': alert.destination_port,
                    'transportProtocol': 'TCP',
                    'deviceAction': 'observed',
                    'deviceVendor': 'Honeyclaw',
                    'deviceProduct': 'Honeypot',
                },
                'cef_types': {
                    'sourceAddress': ['ip'],
                },
            }
            if alert.geo_country:
                ip_artifact['cef']['sourceGeoCountryName'] = alert.geo_country
            artifacts.append(ip_artifact)

        # Username artifact
        if alert.username:
            artifacts.append({
                'container_id': int(container_id),
                'name': f'Username: {alert.username}',
                'label': 'credentials',
                'source_data_identifier': f'{alert.alert_id}:user:{alert.username}',
                'type': 'user name',
                'severity': self._map_severity(alert.severity),
                'tags': ['honeyclaw', 'credential'],
                'cef': {
                    'sourceUserName': alert.username,
                    'sourceAddress': alert.source_ip,
                    'deviceAction': 'observed',
                },
                'cef_types': {
                    'sourceUserName': ['user name'],
                },
            })

        # Command artifact
        if alert.command:
            artifacts.append({
                'container_id': int(container_id),
                'name': f'Command execution',
                'label': 'command',
                'source_data_identifier': f'{alert.alert_id}:cmd',
                'type': 'process',
                'severity': self._map_severity(alert.severity),
                'tags': ['honeyclaw', 'command'],
                'cef': {
                    'fileName': alert.command[:256],
                    'sourceAddress': alert.source_ip,
                    'deviceAction': 'executed',
                },
            })

        # MITRE ATT&CK artifact
        if alert.mitre_techniques:
            artifacts.append({
                'container_id': int(container_id),
                'name': f'MITRE ATT&CK: {", ".join(alert.mitre_techniques[:5])}',
                'label': 'mitre',
                'source_data_identifier': f'{alert.alert_id}:mitre',
                'type': 'other',
                'severity': self._map_severity(alert.severity),
                'tags': ['honeyclaw', 'mitre-attack'] + [
                    f'mitre:{t}' for t in alert.mitre_techniques
                ],
                'cef': {
                    'message': f'MITRE techniques: {", ".join(alert.mitre_techniques)}',
                },
            })

        return artifacts

    @staticmethod
    def _map_severity(severity: IncidentSeverity) -> str:
        """Map to Splunk SOAR severity string"""
        mapping = {
            IncidentSeverity.LOW: 'low',
            IncidentSeverity.MEDIUM: 'medium',
            IncidentSeverity.HIGH: 'high',
            IncidentSeverity.CRITICAL: 'high',  # Phantom doesn't have 'critical'
        }
        return mapping.get(severity, 'medium')

    @staticmethod
    def _map_tlp_to_sensitivity(tlp: TLP) -> str:
        """Map TLP to Splunk SOAR sensitivity"""
        mapping = {
            TLP.WHITE: 'white',
            TLP.GREEN: 'green',
            TLP.AMBER: 'amber',
            TLP.RED: 'red',
        }
        return mapping.get(tlp, 'amber')
