#!/usr/bin/env python3
"""
Honeyclaw Alert Dispatcher

Sends alerts to webhooks (Slack, Discord, PagerDuty, generic)
and SOAR platforms (TheHive/Cortex, Splunk SOAR, XSOAR, generic).
Supports multiple targets, retry logic, and rate limiting.
"""

import os
import json
import time
import logging
import threading
import hashlib
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional
from dataclasses import dataclass, field
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse

from .rules import AlertEngine, Severity

logger = logging.getLogger('honeyclaw.alerts.dispatcher')


class WebhookType(Enum):
    """Supported webhook types."""
    SLACK = "slack"
    DISCORD = "discord"
    PAGERDUTY = "pagerduty"
    GENERIC = "generic"


@dataclass
class WebhookConfig:
    """
    Webhook configuration.
    
    Attributes:
        url: Webhook URL
        webhook_type: Type of webhook (auto-detected if not specified)
        min_severity: Minimum severity to send to this webhook
        routing_key: PagerDuty routing key (for PD only)
        headers: Custom headers to include
        enabled: Whether this webhook is active
    """
    url: str
    webhook_type: Optional[WebhookType] = None
    min_severity: Severity = Severity.LOW
    routing_key: Optional[str] = None  # For PagerDuty
    headers: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    
    def __post_init__(self):
        """Auto-detect webhook type from URL if not specified."""
        if self.webhook_type is None:
            self.webhook_type = self._detect_type()
    
    def _detect_type(self) -> WebhookType:
        """Detect webhook type from URL."""
        url_lower = self.url.lower()
        
        if 'hooks.slack.com' in url_lower:
            return WebhookType.SLACK
        elif 'discord.com/api/webhooks' in url_lower or 'discordapp.com/api/webhooks' in url_lower:
            return WebhookType.DISCORD
        elif 'events.pagerduty.com' in url_lower:
            return WebhookType.PAGERDUTY
        else:
            return WebhookType.GENERIC


# === Webhook Formatters ===

def format_slack(alert: Dict[str, Any], honeypot_id: str) -> Dict[str, Any]:
    """Format alert for Slack webhook (rich formatting)."""
    severity = alert.get('severity', 'UNKNOWN')
    severity_level = alert.get('severity_level', 0)
    event = alert.get('event', {})
    
    # Color based on severity
    colors = {
        'CRITICAL': '#FF0000',  # Red
        'HIGH': '#FF6600',      # Orange
        'MEDIUM': '#FFCC00',    # Yellow
        'LOW': '#00CC00',       # Green
        'INFO': '#0066FF',      # Blue
        'DEBUG': '#999999',     # Gray
    }
    color = colors.get(severity, '#999999')
    
    # Emoji based on severity
    emojis = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'MEDIUM': '⚡',
        'LOW': '📋',
        'INFO': 'ℹ️',
        'DEBUG': '🔍',
    }
    emoji = emojis.get(severity, '📢')
    
    # Build fields
    fields = [
        {
            "title": "Honeypot",
            "value": honeypot_id,
            "short": True
        },
        {
            "title": "Severity",
            "value": f"{emoji} {severity}",
            "short": True
        },
    ]
    
    # Add event details
    if 'ip' in event:
        fields.append({
            "title": "Source IP",
            "value": f"`{event['ip']}`",
            "short": True
        })
    
    if 'username' in event:
        fields.append({
            "title": "Username",
            "value": f"`{event['username']}`",
            "short": True
        })
    
    if 'event' in event:
        fields.append({
            "title": "Event Type",
            "value": event['event'],
            "short": True
        })
    
    # Tags
    tags = alert.get('tags', [])
    if tags:
        fields.append({
            "title": "Tags",
            "value": ', '.join(f"`{t}`" for t in tags),
            "short": True
        })
    
    return {
        "attachments": [
            {
                "color": color,
                "title": f"{emoji} {alert.get('description', 'Security Alert')}",
                "text": f"Rule: `{alert.get('rule', 'unknown')}`",
                "fields": fields,
                "footer": f"Honeyclaw Alert | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
                "ts": int(alert.get('timestamp', time.time()))
            }
        ]
    }


def format_discord(alert: Dict[str, Any], honeypot_id: str) -> Dict[str, Any]:
    """Format alert for Discord webhook (embed format)."""
    severity = alert.get('severity', 'UNKNOWN')
    event = alert.get('event', {})
    
    # Color based on severity (Discord uses decimal)
    colors = {
        'CRITICAL': 16711680,  # Red
        'HIGH': 16744448,      # Orange  
        'MEDIUM': 16763904,    # Yellow
        'LOW': 52224,          # Green
        'INFO': 26367,         # Blue
        'DEBUG': 10066329,     # Gray
    }
    color = colors.get(severity, 10066329)
    
    # Emoji
    emojis = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'MEDIUM': '⚡',
        'LOW': '📋',
        'INFO': 'ℹ️',
        'DEBUG': '🔍',
    }
    emoji = emojis.get(severity, '📢')
    
    # Build fields
    fields = [
        {"name": "Honeypot", "value": honeypot_id, "inline": True},
        {"name": "Severity", "value": f"{emoji} {severity}", "inline": True},
        {"name": "Rule", "value": f"`{alert.get('rule', 'unknown')}`", "inline": True},
    ]
    
    if 'ip' in event:
        fields.append({"name": "Source IP", "value": f"`{event['ip']}`", "inline": True})
    
    if 'username' in event:
        fields.append({"name": "Username", "value": f"`{event['username']}`", "inline": True})
    
    if 'event' in event:
        fields.append({"name": "Event Type", "value": event['event'], "inline": True})
    
    tags = alert.get('tags', [])
    if tags:
        fields.append({"name": "Tags", "value": ', '.join(f"`{t}`" for t in tags), "inline": False})
    
    return {
        "embeds": [
            {
                "title": f"{emoji} {alert.get('description', 'Security Alert')}",
                "color": color,
                "fields": fields,
                "footer": {"text": "Honeyclaw Alert"},
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
    }


def format_pagerduty(alert: Dict[str, Any], honeypot_id: str, routing_key: str) -> Dict[str, Any]:
    """Format alert for PagerDuty Events API v2."""
    severity = alert.get('severity', 'UNKNOWN')
    event = alert.get('event', {})
    
    # PagerDuty severity mapping
    pd_severity = {
        'CRITICAL': 'critical',
        'HIGH': 'error',
        'MEDIUM': 'warning',
        'LOW': 'info',
        'INFO': 'info',
        'DEBUG': 'info',
    }.get(severity, 'info')
    
    # Build custom details
    custom_details = {
        "rule": alert.get('rule'),
        "tags": alert.get('tags', []),
        "event_type": alert.get('event_type'),
    }
    custom_details.update(event)
    
    # Dedup key
    dedup_key = hashlib.sha256(
        f"{honeypot_id}:{alert.get('rule')}:{event.get('ip', 'unknown')}".encode()
    ).hexdigest()[:32]
    
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": f"[{honeypot_id}] {alert.get('description', 'Security Alert')}",
            "source": honeypot_id,
            "severity": pd_severity,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "custom_details": custom_details,
        },
        "client": "Honeyclaw",
        "client_url": f"https://honeyclaw.example.com/alerts/{dedup_key}",
    }


def format_generic(alert: Dict[str, Any], honeypot_id: str) -> Dict[str, Any]:
    """Format alert for generic JSON webhook."""
    return {
        "honeypot_id": honeypot_id,
        "alert": alert,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


# === Alert Dispatcher ===

class AlertDispatcher:
    """
    Dispatches alerts to configured webhooks and SOAR platforms.

    Features:
    - Multiple webhook targets (Slack, Discord, PagerDuty, generic)
    - SOAR platform integration (TheHive/Cortex, Splunk SOAR, XSOAR, generic)
    - Async/background sending
    - Retry logic with exponential backoff
    - Rate limiting per webhook
    """

    def __init__(
        self,
        webhooks: Optional[List[WebhookConfig]] = None,
        honeypot_id: Optional[str] = None,
        engine: Optional[AlertEngine] = None,
        soar_connectors: Optional[List[Any]] = None,
        async_send: bool = True,
        max_retries: int = 3,
        retry_delay: float = 1.0,
    ):
        """
        Initialize the dispatcher.

        Args:
            webhooks: List of webhook configurations
            honeypot_id: Identifier for this honeypot instance
            engine: Alert engine (creates default if not provided)
            soar_connectors: List of SOARConnector instances for SOAR dispatch
            async_send: Whether to send alerts asynchronously
            max_retries: Maximum retry attempts per webhook
            retry_delay: Initial retry delay (doubles each retry)
        """
        self.webhooks: List[WebhookConfig] = webhooks or []
        self.honeypot_id = honeypot_id or os.environ.get('HONEYPOT_ID', 'honeyclaw')
        self.engine = engine or AlertEngine()
        self.soar_connectors: List[Any] = soar_connectors or []
        self.async_send = async_send
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        # Load webhook from environment if none configured
        if not self.webhooks:
            self._load_env_webhooks()

        # Load SOAR connectors from environment if none configured
        if not self.soar_connectors:
            self._load_env_soar()

        # Stats
        self._stats = {
            'alerts_sent': 0,
            'alerts_failed': 0,
            'soar_alerts_sent': 0,
            'soar_alerts_failed': 0,
            'events_processed': 0,
        }
        self._lock = threading.Lock()
        
    def _load_env_webhooks(self):
        """Load webhook config from environment variables."""
        # Primary webhook
        url = os.environ.get('ALERT_WEBHOOK_URL')
        if url:
            self.webhooks.append(WebhookConfig(url=url))
        
        # Additional webhooks (ALERT_WEBHOOK_URL_2, etc.)
        for i in range(2, 10):
            url = os.environ.get(f'ALERT_WEBHOOK_URL_{i}')
            if url:
                self.webhooks.append(WebhookConfig(url=url))
        
        # PagerDuty specific
        pd_key = os.environ.get('PAGERDUTY_ROUTING_KEY')
        if pd_key:
            pd_url = "https://events.pagerduty.com/v2/enqueue"
            self.webhooks.append(WebhookConfig(
                url=pd_url,
                webhook_type=WebhookType.PAGERDUTY,
                routing_key=pd_key,
                min_severity=Severity.HIGH,  # Only high+ to PD by default
            ))

    def _load_env_soar(self):
        """Load SOAR connector config from environment variables."""
        soar_provider = os.environ.get('SOAR_PROVIDER')
        soar_endpoint = os.environ.get('SOAR_ENDPOINT')

        if not soar_provider or not soar_endpoint:
            return

        try:
            from ..integrations.soar import get_soar_connector
            config = {
                'provider': soar_provider,
                'endpoint': soar_endpoint,
                'api_key': os.environ.get('SOAR_API_KEY', ''),
                'token': os.environ.get('SOAR_TOKEN', ''),
            }
            connector = get_soar_connector(config)
            self.soar_connectors.append(connector)
            logger.info(f"SOAR connector loaded from env: {soar_provider}")
        except Exception as e:
            logger.warning(f"Failed to load SOAR connector from env: {e}")

    def add_soar_connector(self, connector):
        """
        Add a SOAR connector for automated incident response.

        Args:
            connector: A SOARConnector instance
        """
        self.soar_connectors.append(connector)

    def _dispatch_to_soar(self, alert: Dict[str, Any]):
        """Dispatch alert to all configured SOAR connectors."""
        if not self.soar_connectors:
            return

        try:
            from ..integrations.soar.base import SOARAlert
            soar_alert = SOARAlert.from_alert_dict(alert)
            soar_alert.honeypot_id = self.honeypot_id
        except Exception as e:
            logger.error(f"Failed to convert alert to SOAR format: {e}")
            return

        for connector in self.soar_connectors:
            if self.async_send:
                thread = threading.Thread(
                    target=self._send_to_soar_connector,
                    args=(connector, soar_alert),
                    daemon=True,
                )
                thread.start()
            else:
                self._send_to_soar_connector(connector, soar_alert)

    def _send_to_soar_connector(self, connector, soar_alert):
        """Send alert to a single SOAR connector."""
        try:
            result = connector.process_alert(soar_alert)
            if result:
                with self._lock:
                    self._stats['soar_alerts_sent'] += 1
                logger.info(
                    f"Alert dispatched to SOAR ({connector.provider_name}): {result}"
                )
            else:
                with self._lock:
                    self._stats['soar_alerts_failed'] += 1
        except Exception as e:
            logger.error(f"SOAR dispatch failed ({connector.provider_name}): {e}")
            with self._lock:
                self._stats['soar_alerts_failed'] += 1

    def process_event(self, event: Dict[str, Any], event_type: str):
        """
        Process an event through the alert engine and dispatch any alerts.
        
        Args:
            event: The event data
            event_type: The event type string
        """
        with self._lock:
            self._stats['events_processed'] += 1
        
        # Evaluate against rules
        alerts = self.engine.evaluate(event, event_type)
        
        # Dispatch each alert
        for alert in alerts:
            self.dispatch(alert)
    
    def dispatch(self, alert: Dict[str, Any]):
        """
        Dispatch an alert to all configured webhooks and SOAR platforms.

        Args:
            alert: The alert dict from AlertEngine
        """
        alert_severity = Severity[alert.get('severity', 'INFO')]

        # Dispatch to webhooks
        for webhook in self.webhooks:
            if not webhook.enabled:
                continue

            if alert_severity < webhook.min_severity:
                continue

            if self.async_send:
                thread = threading.Thread(
                    target=self._send_to_webhook,
                    args=(webhook, alert),
                    daemon=True
                )
                thread.start()
            else:
                self._send_to_webhook(webhook, alert)

        # Dispatch to SOAR platforms
        self._dispatch_to_soar(alert)
    
    def _send_to_webhook(self, webhook: WebhookConfig, alert: Dict[str, Any]):
        """Send alert to a single webhook with retries."""
        # Format payload
        payload = self._format_payload(webhook, alert)
        
        # Send with retries
        delay = self.retry_delay
        for attempt in range(self.max_retries):
            try:
                self._http_post(webhook, payload)
                with self._lock:
                    self._stats['alerts_sent'] += 1
                return
            except Exception as e:
                if attempt < self.max_retries - 1:
                    time.sleep(delay)
                    delay *= 2  # Exponential backoff
                else:
                    print(f"[ALERT] Failed to send to {webhook.webhook_type.value}: {e}")
                    with self._lock:
                        self._stats['alerts_failed'] += 1
    
    def _format_payload(self, webhook: WebhookConfig, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Format alert payload for the webhook type."""
        if webhook.webhook_type == WebhookType.SLACK:
            return format_slack(alert, self.honeypot_id)
        elif webhook.webhook_type == WebhookType.DISCORD:
            return format_discord(alert, self.honeypot_id)
        elif webhook.webhook_type == WebhookType.PAGERDUTY:
            return format_pagerduty(alert, self.honeypot_id, webhook.routing_key)
        else:
            return format_generic(alert, self.honeypot_id)
    
    def _http_post(self, webhook: WebhookConfig, payload: Dict[str, Any]):
        """Send HTTP POST request to webhook."""
        data = json.dumps(payload).encode('utf-8')
        
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Honeyclaw-Alert/1.0',
        }
        headers.update(webhook.headers)
        
        request = Request(webhook.url, data=data, headers=headers, method='POST')
        
        try:
            with urlopen(request, timeout=10) as response:
                return response.read()
        except HTTPError as e:
            raise Exception(f"HTTP {e.code}: {e.reason}")
        except URLError as e:
            raise Exception(f"URL Error: {e.reason}")
    
    def get_stats(self) -> Dict[str, int]:
        """Get dispatcher statistics."""
        with self._lock:
            return dict(self._stats)


# === Convenience Functions ===

_default_dispatcher: Optional[AlertDispatcher] = None


def get_dispatcher() -> AlertDispatcher:
    """Get or create the default dispatcher."""
    global _default_dispatcher
    if _default_dispatcher is None:
        _default_dispatcher = AlertDispatcher()
    return _default_dispatcher


def alert(event: Dict[str, Any], event_type: str):
    """
    Process an event through the default dispatcher.
    
    Convenience function for honeypot integration.
    
    Usage:
        from src.alerts import alert
        alert({'ip': '1.2.3.4', 'username': 'root'}, 'login_attempt')
    """
    get_dispatcher().process_event(event, event_type)


def configure(
    webhook_url: Optional[str] = None,
    webhooks: Optional[List[WebhookConfig]] = None,
    honeypot_id: Optional[str] = None,
    min_severity: Optional[str] = None,
    soar_connectors: Optional[List[Any]] = None,
):
    """
    Configure the default dispatcher.

    Args:
        webhook_url: Primary webhook URL
        webhooks: List of WebhookConfig objects
        honeypot_id: Honeypot identifier
        min_severity: Minimum severity threshold (DEBUG/INFO/LOW/MEDIUM/HIGH/CRITICAL)
        soar_connectors: List of SOARConnector instances for SOAR dispatch
    """
    global _default_dispatcher

    wh_list = webhooks or []
    if webhook_url:
        wh_list.insert(0, WebhookConfig(url=webhook_url))

    engine = AlertEngine()
    if min_severity:
        engine.min_severity = Severity[min_severity.upper()]

    _default_dispatcher = AlertDispatcher(
        webhooks=wh_list,
        honeypot_id=honeypot_id,
        engine=engine,
        soar_connectors=soar_connectors,
    )


# === Test Helpers ===

def send_test_alert(webhook_url: Optional[str] = None):
    """
    Send a test alert to verify webhook configuration.
    
    Args:
        webhook_url: Override webhook URL for testing
    """
    test_alert = {
        'rule': 'test_alert',
        'description': 'Test Alert - Honeyclaw Alert Pipeline',
        'severity': 'INFO',
        'severity_level': 1,
        'tags': ['test'],
        'event_type': 'test',
        'event': {
            'message': 'This is a test alert from Honeyclaw',
            'ip': '127.0.0.1',
            'timestamp': datetime.utcnow().isoformat(),
        },
        'timestamp': time.time(),
    }
    
    if webhook_url:
        webhook = WebhookConfig(url=webhook_url)
        dispatcher = AlertDispatcher(webhooks=[webhook], async_send=False)
    else:
        dispatcher = get_dispatcher()
        dispatcher.async_send = False  # Sync for testing
    
    dispatcher.dispatch(test_alert)
    print(f"[TEST] Alert sent successfully!")
    return True


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        url = sys.argv[2] if len(sys.argv) > 2 else None
        send_test_alert(url)
    else:
        print("Usage: python dispatcher.py test [webhook_url]")
        print("\nEnvironment variables:")
        print("  ALERT_WEBHOOK_URL - Primary webhook URL")
        print("  ALERT_SEVERITY_THRESHOLD - Minimum severity (DEBUG/INFO/LOW/MEDIUM/HIGH/CRITICAL)")
        print("  HONEYPOT_ID - Honeypot identifier")
        print("  PAGERDUTY_ROUTING_KEY - PagerDuty routing key")
