#!/usr/bin/env python3
"""
Honeyclaw SOAR (Security Orchestration, Automation, and Response) Integrations

Connectors for automated incident response platforms:
- TheHive/Cortex
- Splunk SOAR (Phantom)
- Palo Alto XSOAR (Demisto)
- Generic SOAR webhook
"""

from .base import SOARConnector, SOARConfig, SOARAlert, PlaybookTrigger
from .cortex import CortexConnector
from .phantom import PhantomConnector
from .xsoar import XSOARConnector
from .generic_webhook import GenericSOARWebhook

__all__ = [
    'SOARConnector',
    'SOARConfig',
    'SOARAlert',
    'PlaybookTrigger',
    'CortexConnector',
    'PhantomConnector',
    'XSOARConnector',
    'GenericSOARWebhook',
    'get_soar_connector',
]


def get_soar_connector(config: dict) -> SOARConnector:
    """
    Factory function to create the appropriate SOAR connector.

    Args:
        config: SOAR configuration dictionary with 'provider' key

    Returns:
        Configured SOARConnector instance

    Example config:
        {
            'provider': 'cortex',
            'endpoint': 'https://thehive.example.com',
            'api_key': 'your-api-key',
        }
    """
    provider = config.get('provider', '').lower()

    connectors = {
        'cortex': CortexConnector,
        'thehive': CortexConnector,
        'phantom': PhantomConnector,
        'splunk_soar': PhantomConnector,
        'xsoar': XSOARConnector,
        'demisto': XSOARConnector,
        'paloalto': XSOARConnector,
        'generic': GenericSOARWebhook,
        'webhook': GenericSOARWebhook,
    }

    connector_class = connectors.get(provider)
    if not connector_class:
        raise ValueError(
            f"Unknown SOAR provider: {provider}. "
            f"Available: {', '.join(connectors.keys())}"
        )

    return connector_class(config)
