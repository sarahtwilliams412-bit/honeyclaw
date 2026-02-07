#!/usr/bin/env python3
"""
Honeyclaw SOAR Integration Tests

Tests for SOAR connectors, blocklist feed, and dispatcher integration.
Run: python -m pytest src/integrations/soar/test_soar.py -v
  or: python src/integrations/soar/test_soar.py
"""

import json
import sys
import os
import time
import threading
import urllib.request
import urllib.error

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))

from src.integrations.soar.base import (
    SOARConnector,
    SOARConfig,
    SOARAlert,
    PlaybookTrigger,
    IncidentSeverity,
    IncidentStatus,
    TLP,
)
from src.integrations.soar import get_soar_connector
from src.feeds.blocklist import BlocklistFeed, BlocklistEntry


# ============================================================
# Test Helpers
# ============================================================

def make_test_alert(**overrides) -> SOARAlert:
    """Create a test SOARAlert with sensible defaults."""
    defaults = {
        'title': 'Brute Force Attack Detected',
        'description': 'Multiple failed login attempts from 45.33.32.156',
        'source_ip': '45.33.32.156',
        'severity': IncidentSeverity.HIGH,
        'event_type': 'auth_failure',
        'honeypot_id': 'honeyclaw-test-01',
        'username': 'root',
        'service': 'ssh',
        'destination_port': 22,
        'tags': ['brute-force', 'ssh'],
        'mitre_tactics': ['TA0001'],
        'mitre_techniques': ['T1110'],
        'geo_country': 'DE',
        'geo_city': 'Berlin',
        'geo_asn': 'AS24940',
        'session_id': 'sess_abc123',
    }
    defaults.update(overrides)
    return SOARAlert(**defaults)


def make_test_alert_dict() -> dict:
    """Create a test alert dict (as from AlertEngine.evaluate)."""
    return {
        'rule': 'brute_force_detected',
        'description': 'Brute Force Attack Detected',
        'severity': 'HIGH',
        'severity_level': 4,
        'tags': ['brute-force', 'ssh'],
        'event_type': 'auth_failure',
        'event': {
            'ip': '45.33.32.156',
            'username': 'root',
            'service': 'ssh',
            'port': 22,
            'geo_country': 'DE',
        },
        'timestamp': time.time(),
    }


# ============================================================
# SOARAlert Tests
# ============================================================

def test_soar_alert_creation():
    """Test SOARAlert creation and field defaults."""
    alert = make_test_alert()

    assert alert.title == 'Brute Force Attack Detected'
    assert alert.source_ip == '45.33.32.156'
    assert alert.severity == IncidentSeverity.HIGH
    assert alert.event_type == 'auth_failure'
    assert alert.alert_id is not None
    assert len(alert.alert_id) == 16
    assert alert.timestamp is not None
    assert alert.tlp == TLP.AMBER
    assert alert.ioc_type == 'ip'
    assert alert.ioc_value == '45.33.32.156'
    print("[PASS] test_soar_alert_creation")


def test_soar_alert_to_dict():
    """Test SOARAlert serialization to dict."""
    alert = make_test_alert()
    d = alert.to_dict()

    assert d['title'] == 'Brute Force Attack Detected'
    assert d['severity'] == 3  # HIGH = 3
    assert d['tlp'] == 'TLP:AMBER'
    assert 'brute-force' in d['tags']
    assert d['source_ip'] == '45.33.32.156'
    print("[PASS] test_soar_alert_to_dict")


def test_soar_alert_from_alert_dict():
    """Test creating SOARAlert from AlertEngine output."""
    alert_dict = make_test_alert_dict()
    alert = SOARAlert.from_alert_dict(alert_dict)

    assert alert.title == 'Brute Force Attack Detected'
    assert alert.source_ip == '45.33.32.156'
    assert alert.severity == IncidentSeverity.HIGH
    assert alert.username == 'root'
    assert alert.service == 'ssh'
    assert alert.destination_port == 22
    assert 'brute-force' in alert.tags
    print("[PASS] test_soar_alert_from_alert_dict")


def test_soar_alert_from_alert_dict_severity_mapping():
    """Test severity mapping from alert dict to SOARAlert."""
    for sev_str, expected in [
        ('CRITICAL', IncidentSeverity.CRITICAL),
        ('HIGH', IncidentSeverity.HIGH),
        ('MEDIUM', IncidentSeverity.MEDIUM),
        ('LOW', IncidentSeverity.LOW),
        ('INFO', IncidentSeverity.LOW),
    ]:
        alert_dict = make_test_alert_dict()
        alert_dict['severity'] = sev_str
        alert = SOARAlert.from_alert_dict(alert_dict)
        assert alert.severity == expected, f"Expected {expected} for {sev_str}, got {alert.severity}"
    print("[PASS] test_soar_alert_from_alert_dict_severity_mapping")


# ============================================================
# PlaybookTrigger Tests
# ============================================================

def test_playbook_trigger_matching():
    """Test PlaybookTrigger matching logic."""
    trigger = PlaybookTrigger(
        playbook_id='block_ip',
        name='Block Attacker IP',
        trigger_on_severity=IncidentSeverity.HIGH,
        trigger_on_event_types=['auth_failure', 'exploit_attempt'],
        trigger_on_tags=['brute-force'],
    )

    # Should match - high severity, matching event type, matching tag
    alert = make_test_alert()
    assert trigger.matches(alert) is True

    # Should not match - low severity
    low_alert = make_test_alert(severity=IncidentSeverity.LOW)
    assert trigger.matches(low_alert) is False

    # Should not match - wrong event type
    scan_alert = make_test_alert(event_type='scan', tags=[])
    assert trigger.matches(scan_alert) is False

    # Should not match - disabled
    trigger.enabled = False
    assert trigger.matches(alert) is False

    print("[PASS] test_playbook_trigger_matching")


def test_playbook_trigger_no_filters():
    """Test PlaybookTrigger with only severity filter."""
    trigger = PlaybookTrigger(
        playbook_id='notify_soc',
        name='Notify SOC Team',
        trigger_on_severity=IncidentSeverity.MEDIUM,
    )

    high_alert = make_test_alert(severity=IncidentSeverity.HIGH)
    assert trigger.matches(high_alert) is True

    low_alert = make_test_alert(severity=IncidentSeverity.LOW)
    assert trigger.matches(low_alert) is False

    print("[PASS] test_playbook_trigger_no_filters")


# ============================================================
# SOARConfig Tests
# ============================================================

def test_soar_config_from_dict():
    """Test SOARConfig creation from dict."""
    config = SOARConfig.from_dict({
        'provider': 'cortex',
        'endpoint': 'https://thehive.example.com',
        'api_key': 'test-key-123',
        'max_retries': 5,
    })

    assert config.provider == 'cortex'
    assert config.endpoint == 'https://thehive.example.com'
    assert config.api_key == 'test-key-123'
    assert config.max_retries == 5
    assert config.verify_ssl is True  # default
    print("[PASS] test_soar_config_from_dict")


def test_soar_config_env_expansion():
    """Test SOARConfig environment variable expansion."""
    os.environ['TEST_SOAR_KEY'] = 'expanded-key-456'
    try:
        config = SOARConfig.from_dict({
            'provider': 'phantom',
            'endpoint': 'https://phantom.example.com',
            'token': '${TEST_SOAR_KEY}',
        })
        assert config.token == 'expanded-key-456'
    finally:
        del os.environ['TEST_SOAR_KEY']
    print("[PASS] test_soar_config_env_expansion")


# ============================================================
# Factory Tests
# ============================================================

def test_get_soar_connector_factory():
    """Test the SOAR connector factory function."""
    from src.integrations.soar.cortex import CortexConnector
    from src.integrations.soar.phantom import PhantomConnector
    from src.integrations.soar.xsoar import XSOARConnector
    from src.integrations.soar.generic_webhook import GenericSOARWebhook

    # Test cortex
    c = get_soar_connector({
        'provider': 'cortex',
        'endpoint': 'https://test.example.com',
        'api_key': 'test',
    })
    assert isinstance(c, CortexConnector)
    assert c.provider_name == 'cortex'

    # Test thehive (alias)
    c = get_soar_connector({
        'provider': 'thehive',
        'endpoint': 'https://test.example.com',
        'api_key': 'test',
    })
    assert isinstance(c, CortexConnector)

    # Test phantom
    c = get_soar_connector({
        'provider': 'phantom',
        'endpoint': 'https://test.example.com',
        'token': 'test',
    })
    assert isinstance(c, PhantomConnector)
    assert c.provider_name == 'phantom'

    # Test splunk_soar (alias)
    c = get_soar_connector({
        'provider': 'splunk_soar',
        'endpoint': 'https://test.example.com',
        'token': 'test',
    })
    assert isinstance(c, PhantomConnector)

    # Test xsoar
    c = get_soar_connector({
        'provider': 'xsoar',
        'endpoint': 'https://test.example.com',
        'api_key': 'test',
    })
    assert isinstance(c, XSOARConnector)
    assert c.provider_name == 'xsoar'

    # Test demisto (alias)
    c = get_soar_connector({
        'provider': 'demisto',
        'endpoint': 'https://test.example.com',
        'api_key': 'test',
    })
    assert isinstance(c, XSOARConnector)

    # Test generic
    c = get_soar_connector({
        'provider': 'generic',
        'endpoint': 'https://test.example.com',
        'api_key': 'test',
    })
    assert isinstance(c, GenericSOARWebhook)
    assert c.provider_name == 'generic'

    print("[PASS] test_get_soar_connector_factory")


def test_factory_unknown_provider():
    """Test factory raises on unknown provider."""
    try:
        get_soar_connector({'provider': 'nonexistent', 'endpoint': 'https://x.com'})
        assert False, "Should have raised ValueError"
    except ValueError as e:
        assert 'nonexistent' in str(e)
    print("[PASS] test_factory_unknown_provider")


# ============================================================
# Cortex Connector Tests
# ============================================================

def test_cortex_alert_formatting():
    """Test TheHive alert format generation."""
    from src.integrations.soar.cortex import CortexConnector

    connector = CortexConnector({
        'endpoint': 'https://thehive.test.local',
        'api_key': 'test-key',
    })

    alert = make_test_alert()
    formatted = connector._format_alert(alert)

    assert formatted['type'] == 'honeyclaw'
    assert formatted['source'] == 'honeyclaw'
    assert '[Honeyclaw]' in formatted['title']
    assert formatted['severity'] == 3  # HIGH
    assert formatted['tlp'] == 2  # AMBER
    assert 'honeyclaw' in formatted['tags']
    assert 'honeypot' in formatted['tags']
    assert 'auth_failure' in formatted['tags']

    # Check observables
    observables = formatted['observables']
    assert len(observables) >= 1
    ip_obs = [o for o in observables if o['dataType'] == 'ip']
    assert len(ip_obs) == 1
    assert ip_obs[0]['data'] == '45.33.32.156'
    assert ip_obs[0]['ioc'] is True

    print("[PASS] test_cortex_alert_formatting")


def test_cortex_case_tasks():
    """Test TheHive case task generation."""
    from src.integrations.soar.cortex import CortexConnector

    connector = CortexConnector({
        'endpoint': 'https://thehive.test.local',
        'api_key': 'test-key',
    })

    # Non-critical alert
    alert = make_test_alert(severity=IncidentSeverity.HIGH)
    tasks = connector._generate_tasks(alert)
    assert len(tasks) == 3

    # Critical alert should get extra containment task
    critical_alert = make_test_alert(severity=IncidentSeverity.CRITICAL)
    tasks = connector._generate_tasks(critical_alert)
    assert len(tasks) == 4
    assert any('blocklist' in t['title'].lower() or 'firewall' in t['title'].lower()
               for t in tasks)

    print("[PASS] test_cortex_case_tasks")


# ============================================================
# Phantom Connector Tests
# ============================================================

def test_phantom_container_formatting():
    """Test Splunk SOAR container format generation."""
    from src.integrations.soar.phantom import PhantomConnector

    connector = PhantomConnector({
        'endpoint': 'https://phantom.test.local',
        'token': 'test-token',
    })

    alert = make_test_alert()
    container = connector._format_container(alert)

    assert '[Honeyclaw]' in container['name']
    assert container['label'] == 'honeypot'
    assert container['severity'] == 'high'
    assert container['sensitivity'] == 'amber'
    assert container['status'] == 'new'
    assert 'honeyclaw' in container['tags']

    print("[PASS] test_phantom_container_formatting")


def test_phantom_artifact_building():
    """Test Splunk SOAR artifact generation."""
    from src.integrations.soar.phantom import PhantomConnector

    connector = PhantomConnector({
        'endpoint': 'https://phantom.test.local',
        'token': 'test-token',
    })

    alert = make_test_alert()
    artifacts = connector._build_artifacts('123', alert)

    # Should have IP, username, and MITRE artifacts
    assert len(artifacts) >= 2

    # Check IP artifact
    ip_artifacts = [a for a in artifacts if a['type'] == 'ip']
    assert len(ip_artifacts) == 1
    assert ip_artifacts[0]['cef']['sourceAddress'] == '45.33.32.156'
    assert int(ip_artifacts[0]['container_id']) == 123

    # Check username artifact
    user_artifacts = [a for a in artifacts if a['type'] == 'user name']
    assert len(user_artifacts) == 1
    assert user_artifacts[0]['cef']['sourceUserName'] == 'root'

    print("[PASS] test_phantom_artifact_building")


# ============================================================
# XSOAR Connector Tests
# ============================================================

def test_xsoar_incident_formatting():
    """Test XSOAR incident format generation."""
    from src.integrations.soar.xsoar import XSOARConnector

    connector = XSOARConnector({
        'endpoint': 'https://xsoar.test.local',
        'api_key': 'test-key',
    })

    alert = make_test_alert()
    incident = connector._format_incident(alert)

    assert '[Honeyclaw]' in incident['name']
    assert incident['type'] == 'Brute Force'
    assert incident['severity'] == 3  # HIGH
    assert incident['createInvestigation'] is True
    assert incident['CustomFields']['honeypotid'] == 'honeyclaw-test-01'
    assert incident['CustomFields']['attackerip'] == '45.33.32.156'

    print("[PASS] test_xsoar_incident_formatting")


def test_xsoar_labels():
    """Test XSOAR label generation."""
    from src.integrations.soar.xsoar import XSOARConnector

    connector = XSOARConnector({
        'endpoint': 'https://xsoar.test.local',
        'api_key': 'test-key',
    })

    alert = make_test_alert()
    labels = connector._build_labels(alert)

    label_dict = {l['type']: l['value'] for l in labels if l['type'] != 'tag'
                  and l['type'] != 'mitre_tactic' and l['type'] != 'mitre_technique'}

    assert label_dict['source'] == 'honeyclaw'
    assert label_dict['source_ip'] == '45.33.32.156'
    assert label_dict['service'] == 'ssh'
    assert label_dict['username'] == 'root'

    # Check MITRE labels
    mitre_labels = [l for l in labels if l['type'] == 'mitre_technique']
    assert any(l['value'] == 'T1110' for l in mitre_labels)

    print("[PASS] test_xsoar_labels")


def test_xsoar_incident_type_mapping():
    """Test XSOAR event type to incident type mapping."""
    from src.integrations.soar.xsoar import XSOARConnector

    mapping = {
        'auth_success': 'Access',
        'auth_failure': 'Brute Force',
        'command': 'Malware',
        'exploit_attempt': 'Exploit',
        'data_exfil': 'Data Exfiltration',
        'scan': 'Reconnaissance',
        'unknown_type': 'Unclassified',
    }

    for event_type, expected_type in mapping.items():
        result = XSOARConnector._map_incident_type(event_type)
        assert result == expected_type, \
            f"Event type '{event_type}': expected '{expected_type}', got '{result}'"

    print("[PASS] test_xsoar_incident_type_mapping")


# ============================================================
# Generic Webhook Tests
# ============================================================

def test_generic_webhook_payload():
    """Test generic webhook default payload generation."""
    from src.integrations.soar.generic_webhook import GenericSOARWebhook

    connector = GenericSOARWebhook({
        'endpoint': 'https://webhook.test.local/api',
        'api_key': 'test-key',
    })

    alert = make_test_alert()
    payload = connector._build_alert_payload(alert)

    assert payload['source'] == 'honeyclaw'
    assert payload['type'] == 'honeypot_alert'
    assert payload['title'] == 'Brute Force Attack Detected'
    assert payload['severity'] == 'high'
    assert payload['event_type'] == 'auth_failure'
    assert payload['honeypot_id'] == 'honeyclaw-test-01'
    assert payload['tlp'] == 'TLP:AMBER'

    # Check indicators
    assert len(payload['indicators']) >= 1
    ip_indicator = [i for i in payload['indicators'] if i['type'] == 'ip']
    assert len(ip_indicator) == 1
    assert ip_indicator[0]['value'] == '45.33.32.156'
    assert ip_indicator[0]['geo']['country'] == 'DE'

    # Check MITRE
    assert 'TA0001' in payload['mitre']['tactics']
    assert 'T1110' in payload['mitre']['techniques']

    print("[PASS] test_generic_webhook_payload")


def test_generic_webhook_template_substitution():
    """Test generic webhook template variable substitution."""
    from src.integrations.soar.generic_webhook import GenericSOARWebhook

    custom_template = {
        'event': {
            'name': '${title}',
            'ip': '${source_ip}',
            'severity_text': '${severity}',
        },
        'meta': {
            'honeypot': '${honeypot_id}',
        },
    }

    connector = GenericSOARWebhook({
        'endpoint': 'https://webhook.test.local/api',
        'api_key': 'test-key',
        'alert_template': custom_template,
    })

    alert = make_test_alert()
    payload = connector._build_alert_payload(alert)

    assert payload['event']['name'] == 'Brute Force Attack Detected'
    assert payload['event']['ip'] == '45.33.32.156'
    assert payload['event']['severity_text'] == 'high'
    assert payload['meta']['honeypot'] == 'honeyclaw-test-01'

    print("[PASS] test_generic_webhook_template_substitution")


def test_generic_webhook_auth_schemes():
    """Test generic webhook authentication header generation."""
    from src.integrations.soar.generic_webhook import GenericSOARWebhook

    # Bearer token
    c = GenericSOARWebhook({
        'endpoint': 'https://test.local',
        'token': 'my-token',
        'auth_scheme': 'bearer',
    })
    assert c._auth_headers.get('Authorization') == 'Bearer my-token'

    # API key header
    c = GenericSOARWebhook({
        'endpoint': 'https://test.local',
        'api_key': 'my-api-key',
        'auth_scheme': 'apikey',
    })
    assert c._auth_headers.get('X-API-Key') == 'my-api-key'

    print("[PASS] test_generic_webhook_auth_schemes")


# ============================================================
# Blocklist Feed Tests
# ============================================================

def test_blocklist_add_and_retrieve():
    """Test adding and retrieving blocklist entries."""
    feed = BlocklistFeed(min_confidence=0.5, ttl_hours=24)

    feed.add('45.33.32.156', confidence=0.9, tags=['brute-force'], service='ssh')
    feed.add('185.220.101.1', confidence=0.7, tags=['scanner'], service='http')

    assert feed.count == 2
    assert feed.contains('45.33.32.156')
    assert feed.contains('185.220.101.1')
    assert not feed.contains('1.2.3.4')

    entries = feed.get_entries()
    assert len(entries) == 2

    print("[PASS] test_blocklist_add_and_retrieve")


def test_blocklist_update_existing():
    """Test updating an existing blocklist entry."""
    feed = BlocklistFeed(min_confidence=0.5)

    feed.add('45.33.32.156', confidence=0.6, tags=['ssh'], service='ssh')
    feed.add('45.33.32.156', confidence=0.9, tags=['brute-force'], service='http',
             honeypot_id='hp-02')

    assert feed.count == 1
    entries = feed.get_entries()
    entry = entries[0]

    assert entry.confidence == 0.9  # Max of two
    assert entry.times_seen == 2
    assert 'ssh' in entry.tags
    assert 'brute-force' in entry.tags
    assert 'ssh' in entry.services
    assert 'http' in entry.services

    print("[PASS] test_blocklist_update_existing")


def test_blocklist_confidence_filter():
    """Test minimum confidence filtering."""
    feed = BlocklistFeed(min_confidence=0.7)

    feed.add('45.33.32.156', confidence=0.9)
    feed.add('1.2.3.4', confidence=0.5)  # Below threshold, won't be added

    assert feed.count == 1
    assert feed.contains('45.33.32.156')
    assert not feed.contains('1.2.3.4')

    print("[PASS] test_blocklist_confidence_filter")


def test_blocklist_allowlist():
    """Test allowlist exclusion."""
    feed = BlocklistFeed(min_confidence=0.5, allowlist={'45.33.32.156'})

    feed.add('45.33.32.156', confidence=1.0)  # In allowlist, won't be added
    feed.add('185.220.101.1', confidence=0.8)

    assert feed.count == 1
    assert not feed.contains('45.33.32.156')
    assert feed.contains('185.220.101.1')

    print("[PASS] test_blocklist_allowlist")


def test_blocklist_private_ip_rejection():
    """Test that private/reserved IPs are rejected."""
    feed = BlocklistFeed(min_confidence=0.1)

    private_ips = [
        '10.0.0.1', '172.16.0.1', '192.168.1.1', '127.0.0.1', '0.0.0.0',
    ]
    for ip in private_ips:
        feed.add(ip, confidence=1.0)

    assert feed.count == 0

    # Public IP should be accepted
    feed.add('8.8.8.8', confidence=0.5)
    assert feed.count == 1

    print("[PASS] test_blocklist_private_ip_rejection")


def test_blocklist_remove():
    """Test removing entries from the blocklist."""
    feed = BlocklistFeed(min_confidence=0.5)

    feed.add('45.33.32.156', confidence=0.9)
    assert feed.count == 1

    feed.remove('45.33.32.156')
    assert feed.count == 0
    assert not feed.contains('45.33.32.156')

    print("[PASS] test_blocklist_remove")


def test_blocklist_to_text():
    """Test plain text export."""
    feed = BlocklistFeed(min_confidence=0.5)
    feed.add('45.33.32.156', confidence=0.9)
    feed.add('185.220.101.1', confidence=0.7)

    text = feed.to_text()
    lines = text.strip().split('\n')

    # Should have header comments + IPs
    comment_lines = [l for l in lines if l.startswith('#')]
    ip_lines = [l for l in lines if not l.startswith('#') and l.strip()]

    assert len(comment_lines) >= 3
    assert len(ip_lines) == 2
    assert '45.33.32.156' in ip_lines
    assert '185.220.101.1' in ip_lines

    print("[PASS] test_blocklist_to_text")


def test_blocklist_to_csv():
    """Test CSV export."""
    feed = BlocklistFeed(min_confidence=0.5)
    feed.add('45.33.32.156', confidence=0.9, tags=['brute-force'], service='ssh')

    csv_output = feed.to_csv()
    lines = csv_output.strip().split('\n')

    assert len(lines) == 2  # header + 1 entry
    assert 'ip,confidence' in lines[0]
    assert '45.33.32.156' in lines[1]
    assert '0.90' in lines[1]

    print("[PASS] test_blocklist_to_csv")


def test_blocklist_to_json():
    """Test JSON export."""
    feed = BlocklistFeed(min_confidence=0.5)
    feed.add('45.33.32.156', confidence=0.9, tags=['brute-force'])

    json_output = feed.to_json()
    data = json.loads(json_output)

    assert 'feed' in data
    assert 'entries' in data
    assert data['feed']['name'] == 'Honeyclaw Blocklist'
    assert data['feed']['count'] == 1
    assert data['entries'][0]['ip'] == '45.33.32.156'
    assert data['entries'][0]['confidence'] == 0.9

    print("[PASS] test_blocklist_to_json")


def test_blocklist_to_stix():
    """Test STIX 2.1 export."""
    feed = BlocklistFeed(min_confidence=0.5)
    feed.add('45.33.32.156', confidence=0.9, tags=['brute-force'], service='ssh')

    stix_output = feed.to_stix()
    bundle = json.loads(stix_output)

    assert bundle['type'] == 'bundle'
    assert len(bundle['objects']) == 1

    indicator = bundle['objects'][0]
    assert indicator['type'] == 'indicator'
    assert indicator['spec_version'] == '2.1'
    assert "45.33.32.156" in indicator['pattern']
    assert indicator['pattern_type'] == 'stix'
    assert indicator['confidence'] == 90
    assert 'malicious-activity' in indicator['indicator_types']

    print("[PASS] test_blocklist_to_stix")


def test_blocklist_stats():
    """Test blocklist statistics."""
    feed = BlocklistFeed(min_confidence=0.3)
    feed.add('1.1.1.1', confidence=0.5)
    feed.add('2.2.2.2', confidence=0.9)
    feed.add('3.3.3.3', confidence=0.85)

    stats = feed.get_stats()
    assert stats['total_entries'] == 3
    assert stats['high_confidence'] == 2  # >= 0.8
    assert 0.74 < stats['avg_confidence'] < 0.76  # ~0.75

    print("[PASS] test_blocklist_stats")


def test_blocklist_max_entries():
    """Test max entry enforcement."""
    feed = BlocklistFeed(min_confidence=0.1, max_entries=5)

    for i in range(10):
        feed.add(f'8.8.{i}.{i}', confidence=0.5)

    assert feed.count <= 5

    print("[PASS] test_blocklist_max_entries")


def test_blocklist_http_server():
    """Test blocklist HTTP feed server."""
    feed = BlocklistFeed(min_confidence=0.5)
    feed.add('45.33.32.156', confidence=0.9, tags=['brute-force'], service='ssh')

    # Start server on a random high port
    port = 18923
    feed.serve(host='127.0.0.1', port=port, background=True)

    # Give server time to start
    time.sleep(0.5)

    try:
        # Test /blocklist.txt
        resp = urllib.request.urlopen(f'http://127.0.0.1:{port}/blocklist.txt', timeout=5)
        text = resp.read().decode()
        assert '45.33.32.156' in text

        # Test /blocklist.json
        resp = urllib.request.urlopen(f'http://127.0.0.1:{port}/blocklist.json', timeout=5)
        data = json.loads(resp.read().decode())
        assert data['feed']['count'] == 1

        # Test /stats
        resp = urllib.request.urlopen(f'http://127.0.0.1:{port}/stats', timeout=5)
        stats = json.loads(resp.read().decode())
        assert stats['total_entries'] == 1

        # Test /health
        resp = urllib.request.urlopen(f'http://127.0.0.1:{port}/health', timeout=5)
        health = json.loads(resp.read().decode())
        assert health['status'] == 'healthy'

        # Test 404
        try:
            urllib.request.urlopen(f'http://127.0.0.1:{port}/nonexistent', timeout=5)
            assert False, "Should have gotten 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404

        print("[PASS] test_blocklist_http_server")
    finally:
        feed.stop()


# ============================================================
# Dispatcher Integration Tests
# ============================================================

def test_dispatcher_soar_integration():
    """Test that the alert dispatcher can be configured with SOAR connectors."""
    from src.alerts.dispatcher import AlertDispatcher

    # Create a mock SOAR connector
    class MockSOARConnector:
        def __init__(self):
            self.provider_name = 'mock'
            self.alerts_received = []

        def process_alert(self, alert):
            self.alerts_received.append(alert)
            return f'mock-{len(self.alerts_received)}'

    mock = MockSOARConnector()
    dispatcher = AlertDispatcher(
        webhooks=[],
        soar_connectors=[mock],
        async_send=False,
        honeypot_id='test-hp',
    )

    # Dispatch an alert
    alert = make_test_alert_dict()
    dispatcher.dispatch(alert)

    assert len(mock.alerts_received) == 1
    assert mock.alerts_received[0].source_ip == '45.33.32.156'
    assert mock.alerts_received[0].honeypot_id == 'test-hp'

    stats = dispatcher.get_stats()
    assert stats['soar_alerts_sent'] == 1

    print("[PASS] test_dispatcher_soar_integration")


def test_dispatcher_soar_failure_handling():
    """Test that SOAR failures are tracked and don't affect webhook dispatch."""
    from src.alerts.dispatcher import AlertDispatcher

    class FailingSOARConnector:
        provider_name = 'failing'

        def process_alert(self, alert):
            return None  # Simulate failure

    mock = FailingSOARConnector()
    dispatcher = AlertDispatcher(
        webhooks=[],
        soar_connectors=[mock],
        async_send=False,
        honeypot_id='test-hp',
    )

    alert = make_test_alert_dict()
    dispatcher.dispatch(alert)

    stats = dispatcher.get_stats()
    assert stats['soar_alerts_failed'] == 1
    assert stats['soar_alerts_sent'] == 0

    print("[PASS] test_dispatcher_soar_failure_handling")


# ============================================================
# Run all tests
# ============================================================

def run_all_tests():
    """Run all tests and report results."""
    tests = [
        # SOARAlert tests
        test_soar_alert_creation,
        test_soar_alert_to_dict,
        test_soar_alert_from_alert_dict,
        test_soar_alert_from_alert_dict_severity_mapping,

        # PlaybookTrigger tests
        test_playbook_trigger_matching,
        test_playbook_trigger_no_filters,

        # SOARConfig tests
        test_soar_config_from_dict,
        test_soar_config_env_expansion,

        # Factory tests
        test_get_soar_connector_factory,
        test_factory_unknown_provider,

        # Cortex tests
        test_cortex_alert_formatting,
        test_cortex_case_tasks,

        # Phantom tests
        test_phantom_container_formatting,
        test_phantom_artifact_building,

        # XSOAR tests
        test_xsoar_incident_formatting,
        test_xsoar_labels,
        test_xsoar_incident_type_mapping,

        # Generic webhook tests
        test_generic_webhook_payload,
        test_generic_webhook_template_substitution,
        test_generic_webhook_auth_schemes,

        # Blocklist feed tests
        test_blocklist_add_and_retrieve,
        test_blocklist_update_existing,
        test_blocklist_confidence_filter,
        test_blocklist_allowlist,
        test_blocklist_private_ip_rejection,
        test_blocklist_remove,
        test_blocklist_to_text,
        test_blocklist_to_csv,
        test_blocklist_to_json,
        test_blocklist_to_stix,
        test_blocklist_stats,
        test_blocklist_max_entries,
        test_blocklist_http_server,

        # Dispatcher integration tests
        test_dispatcher_soar_integration,
        test_dispatcher_soar_failure_handling,
    ]

    passed = 0
    failed = 0
    errors = []

    print(f"\n{'='*60}")
    print(f"Honeyclaw SOAR Integration Tests")
    print(f"{'='*60}\n")

    for test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            failed += 1
            errors.append((test_fn.__name__, str(e)))
            print(f"[FAIL] {test_fn.__name__}: {e}")

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print(f"{'='*60}")

    if errors:
        print("\nFailures:")
        for name, err in errors:
            print(f"  - {name}: {err}")
        return False

    print("\nAll tests passed!")
    return True


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
