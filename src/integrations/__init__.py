#!/usr/bin/env python3
"""
Honeyclaw SIEM/SOAR Integrations

First-class connectors for enterprise security stacks:
- Splunk (HEC)
- Elasticsearch / Elastic SIEM
- Azure Sentinel (Log Analytics)
- Generic Syslog (CEF/LEEF for QRadar, ArcSight, etc.)
"""

from .base import SIEMConnector, SIEMConfig, HoneypotEvent
from .splunk import SplunkHECConnector
from .elastic import ElasticsearchConnector
from .sentinel import AzureSentinelConnector
from .generic_syslog import SyslogConnector

__all__ = [
    'SIEMConnector',
    'SIEMConfig',
    'HoneypotEvent',
    'SplunkHECConnector',
    'ElasticsearchConnector',
    'AzureSentinelConnector',
    'SyslogConnector',
    'get_connector',
]

# Factory function for connector creation
def get_connector(config: dict) -> SIEMConnector:
    """
    Factory function to create the appropriate SIEM connector.
    
    Args:
        config: SIEM configuration dictionary with 'provider' key
        
    Returns:
        Configured SIEMConnector instance
        
    Example config:
        {
            'provider': 'splunk',
            'endpoint': 'https://hec.splunk.example.com:8088',
            'token': 'your-hec-token',
            'index': 'honeypot'
        }
    """
    provider = config.get('provider', '').lower()
    
    connectors = {
        'splunk': SplunkHECConnector,
        'elastic': ElasticsearchConnector,
        'elasticsearch': ElasticsearchConnector,
        'sentinel': AzureSentinelConnector,
        'azure': AzureSentinelConnector,
        'syslog': SyslogConnector,
        'cef': SyslogConnector,
        'leef': SyslogConnector,
        'qradar': SyslogConnector,
    }
    
    connector_class = connectors.get(provider)
    if not connector_class:
        raise ValueError(f"Unknown SIEM provider: {provider}. "
                        f"Available: {', '.join(connectors.keys())}")
    
    return connector_class(config)
