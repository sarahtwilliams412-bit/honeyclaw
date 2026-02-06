"""
Threat Intelligence Providers for Honeyclaw Enrichment
"""

from .base import BaseProvider, ProviderResult
from .abuseipdb import AbuseIPDBProvider
from .greynoise import GreyNoiseProvider
from .shodan import ShodanProvider
from .virustotal import VirusTotalProvider

__all__ = [
    'BaseProvider',
    'ProviderResult',
    'AbuseIPDBProvider',
    'GreyNoiseProvider',
    'ShodanProvider',
    'VirusTotalProvider',
]

# Provider registry for easy lookup
PROVIDERS = {
    'abuseipdb': AbuseIPDBProvider,
    'greynoise': GreyNoiseProvider,
    'shodan': ShodanProvider,
    'virustotal': VirusTotalProvider,
}


def get_provider(name: str, **kwargs):
    """Get a provider instance by name"""
    provider_class = PROVIDERS.get(name.lower())
    if not provider_class:
        raise ValueError(f"Unknown provider: {name}. Available: {list(PROVIDERS.keys())}")
    return provider_class(**kwargs)
