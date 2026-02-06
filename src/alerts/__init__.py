"""
Honeyclaw Real-Time Alert Pipeline

Stream high-value security events to webhooks (Slack, Discord, PagerDuty).
"""

from .rules import AlertRule, AlertEngine, Severity
from .dispatcher import AlertDispatcher, WebhookConfig

__all__ = [
    'AlertRule',
    'AlertEngine', 
    'Severity',
    'AlertDispatcher',
    'WebhookConfig',
]
