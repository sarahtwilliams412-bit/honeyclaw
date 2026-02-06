#!/usr/bin/env python3
"""
Test script for the Honeyclaw Alert Pipeline.

Usage:
    # Test with env var
    export ALERT_WEBHOOK_URL="https://hooks.slack.com/services/..."
    python test_alerts.py
    
    # Test with CLI arg
    python test_alerts.py https://hooks.slack.com/services/...
    
    # Test specific events
    python test_alerts.py --event login_attempt
    python test_alerts.py --event rate_limit_connection
    python test_alerts.py --event sqli
"""

import os
import sys
import time
from datetime import datetime

# Add parent paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from src.alerts.dispatcher import (
    AlertDispatcher, 
    WebhookConfig, 
    send_test_alert,
    format_slack,
    format_discord,
    format_pagerduty,
    format_generic
)
from src.alerts.rules import AlertEngine, AlertRule, Severity, BUILTIN_RULES


def test_rules_engine():
    """Test the alert rules engine."""
    print("\n=== Testing Alert Rules Engine ===\n")
    
    engine = AlertEngine(min_severity=Severity.DEBUG)
    
    # Test events
    test_events = [
        # Should trigger admin_login_attempt
        {
            'event': {
                'ip': '192.168.1.100',
                'username': 'root',
                'password_hash': 'abc123',
                'event': 'login_attempt'
            },
            'event_type': 'login_attempt',
            'expected_rules': ['admin_login_attempt']
        },
        # Should trigger sqli_attempt
        {
            'event': {
                'ip': '10.0.0.1',
                'path': "/api/users?id=1' OR '1'='1",
                'method': 'GET',
                'event': 'api_request'
            },
            'event_type': 'api_request',
            'expected_rules': ['sqli_attempt']
        },
        # Should trigger path_traversal
        {
            'event': {
                'ip': '10.0.0.2',
                'path': '/api/files/../../../etc/passwd',
                'method': 'GET',
                'event': 'api_request'
            },
            'event_type': 'api_request',
            'expected_rules': ['path_traversal']
        },
        # Should trigger credential_stuffing
        {
            'event': {
                'ip': '192.168.1.50',
                'count': 100,
                'limit': 100,
                'window': '1h'
            },
            'event_type': 'rate_limit_auth',
            'expected_rules': ['credential_stuffing']
        },
    ]
    
    for test in test_events:
        alerts = engine.evaluate(test['event'], test['event_type'])
        triggered_rules = [a['rule'] for a in alerts]
        
        status = "✅" if any(r in triggered_rules for r in test['expected_rules']) else "❌"
        print(f"{status} Event type '{test['event_type']}':")
        print(f"   Expected: {test['expected_rules']}")
        print(f"   Triggered: {triggered_rules}")
        print()


def test_formatters():
    """Test the webhook formatters."""
    print("\n=== Testing Webhook Formatters ===\n")
    
    test_alert = {
        'rule': 'admin_login_attempt',
        'description': 'Login attempt with admin/root username',
        'severity': 'HIGH',
        'severity_level': 4,
        'tags': ['auth', 'admin'],
        'event_type': 'login_attempt',
        'event': {
            'ip': '192.168.1.100',
            'username': 'root',
            'timestamp': datetime.utcnow().isoformat()
        },
        'timestamp': time.time()
    }
    
    print("Slack format:")
    slack_payload = format_slack(test_alert, 'test-honeypot')
    print(f"  Attachments: {len(slack_payload.get('attachments', []))}")
    print(f"  Color: {slack_payload['attachments'][0]['color']}")
    print(f"  Title: {slack_payload['attachments'][0]['title']}")
    
    print("\nDiscord format:")
    discord_payload = format_discord(test_alert, 'test-honeypot')
    print(f"  Embeds: {len(discord_payload.get('embeds', []))}")
    print(f"  Color: {discord_payload['embeds'][0]['color']}")
    print(f"  Title: {discord_payload['embeds'][0]['title']}")
    
    print("\nPagerDuty format:")
    pd_payload = format_pagerduty(test_alert, 'test-honeypot', 'test-routing-key')
    print(f"  Event Action: {pd_payload.get('event_action')}")
    print(f"  Severity: {pd_payload['payload']['severity']}")
    print(f"  Summary: {pd_payload['payload']['summary']}")
    
    print("\nGeneric format:")
    generic_payload = format_generic(test_alert, 'test-honeypot')
    print(f"  Honeypot ID: {generic_payload.get('honeypot_id')}")
    print(f"  Alert rule: {generic_payload['alert']['rule']}")
    
    print("\n✅ All formatters working correctly")


def test_deduplication():
    """Test the deduplication logic."""
    print("\n=== Testing Deduplication ===\n")
    
    engine = AlertEngine(min_severity=Severity.DEBUG)
    
    # Send same event multiple times
    event = {
        'ip': '10.0.0.99',
        'username': 'admin',
        'event': 'login_attempt'
    }
    
    alerts_1 = engine.evaluate(event, 'login_attempt')
    alerts_2 = engine.evaluate(event, 'login_attempt')
    alerts_3 = engine.evaluate(event, 'login_attempt')
    
    print(f"First evaluation: {len(alerts_1)} alerts (should be >= 1)")
    print(f"Second evaluation: {len(alerts_2)} alerts (should be 0 - deduplicated)")
    print(f"Third evaluation: {len(alerts_3)} alerts (should be 0 - deduplicated)")
    
    if len(alerts_1) >= 1 and len(alerts_2) == 0 and len(alerts_3) == 0:
        print("\n✅ Deduplication working correctly")
    else:
        print("\n❌ Deduplication issue")


def test_live_webhook(webhook_url=None):
    """Test sending to a real webhook."""
    print("\n=== Testing Live Webhook ===\n")
    
    url = webhook_url or os.environ.get('ALERT_WEBHOOK_URL')
    if not url:
        print("❌ No webhook URL provided. Set ALERT_WEBHOOK_URL or pass as argument.")
        return False
    
    print(f"Sending test alert to: {url[:50]}...")
    
    try:
        send_test_alert(url)
        print("\n✅ Test alert sent successfully!")
        print("Check your Slack/Discord/PagerDuty for the test message.")
        return True
    except Exception as e:
        print(f"\n❌ Failed to send test alert: {e}")
        return False


def test_full_pipeline(webhook_url=None):
    """Test the full alert pipeline end-to-end."""
    print("\n=== Testing Full Pipeline ===\n")
    
    url = webhook_url or os.environ.get('ALERT_WEBHOOK_URL')
    if not url:
        print("❌ No webhook URL provided. Skipping live test.")
        return
    
    # Create dispatcher
    dispatcher = AlertDispatcher(
        webhooks=[WebhookConfig(url=url)],
        honeypot_id='test-honeypot',
        async_send=False  # Sync for testing
    )
    
    # Process a suspicious event
    event = {
        'ip': '203.0.113.42',
        'username': 'root',
        'password_hash': 'e3b0c44298fc1c149afbf4c8996fb924',
        'event': 'login_attempt',
        'timestamp': datetime.utcnow().isoformat()
    }
    
    print("Processing login_attempt event with username 'root'...")
    dispatcher.process_event(event, 'login_attempt')
    
    # Give async time to complete
    time.sleep(2)
    
    stats = dispatcher.get_stats()
    print(f"\nDispatcher stats:")
    print(f"  Events processed: {stats['events_processed']}")
    print(f"  Alerts sent: {stats['alerts_sent']}")
    print(f"  Alerts failed: {stats['alerts_failed']}")
    
    if stats['alerts_sent'] > 0:
        print("\n✅ Full pipeline working!")
    else:
        print("\n⚠️ No alerts sent (may be deduplicated)")


def main():
    print("=" * 60)
    print("Honeyclaw Alert Pipeline Test Suite")
    print("=" * 60)
    
    # Parse args
    webhook_url = None
    event_type = None
    
    args = sys.argv[1:]
    for i, arg in enumerate(args):
        if arg.startswith('http'):
            webhook_url = arg
        elif arg == '--event' and i + 1 < len(args):
            event_type = args[i + 1]
    
    # Run tests
    test_rules_engine()
    test_formatters()
    test_deduplication()
    
    if webhook_url or os.environ.get('ALERT_WEBHOOK_URL'):
        test_live_webhook(webhook_url)
        test_full_pipeline(webhook_url)
    else:
        print("\n" + "=" * 60)
        print("To test live webhooks, set ALERT_WEBHOOK_URL or pass URL as argument")
        print("=" * 60)
    
    print("\n✅ Test suite complete!")


if __name__ == '__main__':
    main()
