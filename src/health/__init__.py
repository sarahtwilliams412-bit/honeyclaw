"""
Honeyclaw Health Monitoring & Compromise Detection

Provides continuous health checks, compromise detection, and self-healing
capabilities for deployed honeypot instances.
"""

from .monitor import HealthMonitor, HealthStatus, ServiceHealth, HealthReport
from .self_heal import SelfHealer, HealAction

__all__ = [
    'HealthMonitor',
    'HealthStatus',
    'ServiceHealth',
    'HealthReport',
    'SelfHealer',
    'HealAction',
]
