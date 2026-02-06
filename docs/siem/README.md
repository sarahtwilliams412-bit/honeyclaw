# Honeyclaw SIEM Integration Guide

Honeyclaw provides first-class integrations with enterprise SIEM (Security Information and Event Management) platforms for real-time threat detection and incident response.

## Supported Platforms

| Platform | Protocol | Format | Connector |
|----------|----------|--------|-----------|
| **Splunk** | HTTP Event Collector (HEC) | JSON | `splunk.py` |
| **Elasticsearch** | REST API | ECS JSON | `elastic.py` |
| **Azure Sentinel** | Log Analytics API | ASIM JSON | `sentinel.py` |
| **IBM QRadar** | Syslog | LEEF | `generic_syslog.py` |
| **HP ArcSight** | Syslog | CEF | `generic_syslog.py` |
| **Generic SIEM** | Syslog | CEF/LEEF | `generic_syslog.py` |

## Quick Start

### 1. Configure SIEM Connection

Create a SIEM configuration file (`siem.yaml`):

```yaml
siem:
  provider: splunk
  endpoint: https://hec.splunk.example.com:8088
  token: ${SPLUNK_HEC_TOKEN}
  index: honeypot
  source: honeyclaw
  sourcetype: honeyclaw:events
```

### 2. Deploy with SIEM Integration

```bash
# Using config file
./deploy-honeypot.sh --template basic-ssh --name prod-ssh --siem /etc/honeyclaw/siem.yaml

# Using environment variables
export HONEYCLAW_SIEM_PROVIDER=splunk
export HONEYCLAW_SIEM_ENDPOINT=https://hec.splunk.example.com:8088
export HONEYCLAW_SIEM_TOKEN=your-hec-token
./deploy-honeypot.sh --template basic-ssh --name prod-ssh --siem
```

### 3. Import Detection Rules

Pre-built detection rules are available in `siem-rules/`:

- `siem-rules/splunk/` - Splunk saved searches and alerts
- `siem-rules/elastic/` - Elastic SIEM detection rules
- `siem-rules/sentinel/` - Azure Sentinel analytic rules
- `siem-rules/qradar/` - IBM QRadar rules

## Platform-Specific Setup

- [Splunk Setup](splunk.md)
- [Elasticsearch Setup](elastic.md)
- [Azure Sentinel Setup](sentinel.md)
- [QRadar/Generic Syslog Setup](syslog.md)

## Event Schema

All connectors normalize honeypot events to a common schema before translation to platform-specific formats.

### Core Fields

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 | Event timestamp |
| `honeypot_id` | string | Unique honeypot identifier |
| `source_ip` | string | Attacker IP address |
| `source_port` | int | Attacker source port |
| `destination_port` | int | Target port |
| `event_type` | enum | Event category (see below) |
| `severity` | enum | Event severity level |
| `service` | string | Honeypot service type (ssh, http, rdp, etc.) |

### Event Types

| Type | Description | Severity |
|------|-------------|----------|
| `connection` | New connection to honeypot | Low |
| `auth_attempt` | Authentication attempt | Medium |
| `auth_failure` | Failed authentication | Medium |
| `auth_success` | Successful authentication | Critical |
| `command` | Command executed | Critical |
| `file_access` | File accessed | High |
| `data_exfil` | Data exfiltration attempt | Critical |
| `scan` | Port/service scan | Low |
| `exploit_attempt` | Exploit attempt | High |
| `malware` | Malware detected | Critical |
| `lateral_movement` | Lateral movement | High |

### MITRE ATT&CK Mapping

Events are automatically tagged with MITRE ATT&CK tactics and techniques:

| Event Type | Tactic | Technique |
|------------|--------|-----------|
| `auth_failure` | Credential Access | T1110 (Brute Force) |
| `auth_success` | Initial Access | T1078 (Valid Accounts) |
| `command` | Execution | T1059 (Command Interpreter) |
| `scan` | Discovery | T1046 (Network Service Discovery) |
| `exploit_attempt` | Initial Access | T1190 (Exploit Public App) |
| `data_exfil` | Exfiltration | T1041 (Exfil Over C2) |
| `lateral_movement` | Lateral Movement | T1021 (Remote Services) |

## Programmatic Usage

```python
from honeyclaw.integrations import get_connector, HoneypotEvent, EventType, Severity

# Create connector from config
config = {
    'provider': 'splunk',
    'endpoint': 'https://hec.splunk.example.com:8088',
    'token': 'your-token',
    'index': 'honeypot',
}
connector = get_connector(config)

# Test connection
if connector.test_connection():
    print("Connected!")

# Send an event
event = HoneypotEvent(
    timestamp='2024-01-15T10:30:00Z',
    honeypot_id='prod-ssh-01',
    source_ip='192.168.1.100',
    event_type=EventType.AUTH_FAILURE,
    severity=Severity.MEDIUM,
    service='ssh',
    username='admin',
    password_length=8,
)

connector.send(event)

# Or buffer events for batch sending
connector.buffer_event(event)
# ... buffer more events ...
connector.flush()  # Send all buffered events

# Get stats
print(connector.get_stats())
```

## Best Practices

### 1. Use Environment Variables for Secrets

Never hardcode tokens or passwords in config files:

```yaml
siem:
  token: ${SPLUNK_HEC_TOKEN}  # Expanded from environment
```

### 2. Enable SSL Verification in Production

```yaml
siem:
  verify_ssl: true
  ca_cert_path: /etc/ssl/certs/ca-bundle.crt
```

### 3. Configure Appropriate Batch Sizes

For high-volume honeypots:

```yaml
siem:
  batch_size: 100
  flush_interval_seconds: 10
```

### 4. Set Up Alerting

Import the provided detection rules and configure alerting:
- **Critical alerts**: Successful auth, command execution, malware
- **High alerts**: Brute force, exploit attempts, lateral movement
- **Medium alerts**: Port scans, credential stuffing

### 5. Monitor Connector Health

Check connector statistics regularly:

```python
stats = connector.get_stats()
print(f"Events sent: {stats['events_sent']}")
print(f"Events failed: {stats['events_failed']}")
print(f"Last error: {stats['last_error']}")
```

## Troubleshooting

### Connection Failures

1. Verify endpoint URL and port
2. Check token/credentials
3. Ensure network connectivity (firewalls, proxies)
4. Check SSL certificate validity

### Missing Events

1. Check batch flush interval
2. Verify index/table exists
3. Check for rate limiting
4. Review connector logs

### Performance Issues

1. Increase batch size for high-volume honeypots
2. Use UDP syslog for lowest latency
3. Consider local buffering with async shipping

## Security Considerations

- **Network isolation**: SIEM credentials should only be accessible to the aggregator service
- **Encrypted transport**: Always use HTTPS/TLS for SIEM connections
- **Least privilege**: Use write-only tokens where possible
- **Audit logging**: Monitor SIEM API access for anomalies
