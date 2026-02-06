# Honeyclaw Real-Time Alert Pipeline

Stream high-value security events from honeypots to Slack, Discord, PagerDuty, or any webhook endpoint.

## Features

- 🚨 **Real-time alerts** - Events streamed instantly to your preferred platform
- 📊 **Smart deduplication** - Avoid alert fatigue with configurable windows
- 🎯 **Configurable rules** - Severity thresholds and custom rules
- 🔌 **Multiple targets** - Slack, Discord, PagerDuty, generic webhooks
- 📦 **Zero dependencies** - Uses only Python stdlib / Node.js built-ins

## Quick Start

### 1. Set Environment Variables

```bash
# Required: Primary webhook URL (auto-detects type)
export ALERT_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxx"

# Optional: Minimum severity (default: LOW)
export ALERT_SEVERITY_THRESHOLD="MEDIUM"

# Optional: Honeypot identifier
export HONEYPOT_ID="prod-ssh-honeypot"

# Optional: PagerDuty routing key (for PD webhooks)
export PAGERDUTY_ROUTING_KEY="your-routing-key"
```

### 2. Start Your Honeypot

The alert pipeline is automatically integrated into all honeypot templates:

```bash
# SSH Honeypot
cd templates/basic-ssh
ALERT_WEBHOOK_URL="https://hooks.slack.com/..." python honeypot.py

# API Honeypot
cd templates/fake-api
ALERT_WEBHOOK_URL="https://hooks.slack.com/..." npm start

# Enterprise Simulation
cd templates/enterprise-sim
ALERT_WEBHOOK_URL="https://hooks.slack.com/..." docker-compose up
```

### 3. Test the Pipeline

```bash
# Test with your webhook URL
python src/alerts/test_alerts.py "https://hooks.slack.com/services/..."

# Or set the env var and run without argument
export ALERT_WEBHOOK_URL="https://hooks.slack.com/services/..."
python src/alerts/test_alerts.py
```

## Severity Levels

| Level | Value | Description |
|-------|-------|-------------|
| CRITICAL | 5 | Immediate action required (successful auth, malware) |
| HIGH | 4 | Serious events (privesc, exfiltration, rate limit bypass) |
| MEDIUM | 3 | Notable activity (admin attempts, injection attacks) |
| LOW | 2 | Routine suspicious activity (credential stuffing) |
| INFO | 1 | Informational (new IPs) |
| DEBUG | 0 | Debug/development |

## Built-in Rules

| Rule | Severity | Triggers On |
|------|----------|-------------|
| `successful_auth` | CRITICAL | Any successful authentication in honeypot |
| `malware_signature` | CRITICAL | Known malware hash detected |
| `rate_limit_bypass` | HIGH | Rate limit exceeded significantly |
| `exfil_attempt` | HIGH | Data exfiltration patterns |
| `privesc_attempt` | HIGH | Privilege escalation commands |
| `admin_login_attempt` | MEDIUM | root/admin username attempts |
| `sqli_attempt` | MEDIUM | SQL injection patterns |
| `path_traversal` | MEDIUM | Path traversal attempts |
| `cmd_injection` | MEDIUM | Command injection patterns |
| `credential_stuffing` | LOW | Bulk auth attempts |
| `port_scan` | LOW | Port scanning activity |
| `new_attacker_ip` | INFO | First time seeing this IP |

## Webhook Formats

### Slack

Rich message with color-coded severity and fields:

```json
{
  "attachments": [{
    "color": "#FF0000",
    "title": "🚨 Successful authentication detected in honeypot",
    "fields": [
      {"title": "Honeypot", "value": "prod-ssh", "short": true},
      {"title": "Source IP", "value": "`192.168.1.100`", "short": true}
    ]
  }]
}
```

### Discord

Embed format with color and fields:

```json
{
  "embeds": [{
    "title": "🚨 Successful authentication detected in honeypot",
    "color": 16711680,
    "fields": [...]
  }]
}
```

### PagerDuty

Events API v2 format with deduplication:

```json
{
  "routing_key": "...",
  "event_action": "trigger",
  "dedup_key": "abc123",
  "payload": {
    "summary": "[honeypot] Security Alert",
    "severity": "critical"
  }
}
```

### Generic

Simple JSON POST:

```json
{
  "honeypot_id": "prod-ssh",
  "alert": {...},
  "timestamp": "2025-02-06T..."
}
```

## Custom Rules

```python
from src.alerts.rules import AlertRule, Severity, AlertEngine

# Create custom rule
custom_rule = AlertRule(
    name="custom_ssh_key",
    description="SSH key with suspicious comment",
    severity=Severity.HIGH,
    event_types=["pubkey_attempt"],
    conditions={
        "key_type": ["ssh-rsa", "ssh-ed25519"],
        # Regex pattern (r'...')
        "fingerprint": "r'SHA256:.*AAAA.*'",
    },
    tags=["custom", "ssh"],
    dedup_window_sec=300,
)

# Add to engine
engine = AlertEngine()
engine.add_rule(custom_rule)
```

## Deduplication

Alerts are deduplicated based on:
- Rule name
- Configurable key fields (default: source IP)
- Time window (default: 5 minutes)

This prevents alert fatigue during active attacks.

## API Reference

### Python

```python
from src.alerts import alert, configure

# Simple usage
alert(event_dict, event_type)

# Configure
configure(
    webhook_url="https://...",
    honeypot_id="my-honeypot",
    min_severity="MEDIUM"
)
```

### Node.js

```javascript
const { alert, getDispatcher } = require('./alerts');

// Simple usage
alert(eventObject, eventType);

// Get dispatcher for stats
const dispatcher = getDispatcher();
console.log(dispatcher.stats);
```

## Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│   Honeypot      │────▶│ AlertEngine  │────▶│ AlertDispatcher │
│  (SSH/API/etc)  │     │  (rules.py)  │     │ (dispatcher.py) │
└─────────────────┘     └──────────────┘     └────────┬────────┘
                                                      │
                        ┌─────────────────────────────┼─────────────────────────────┐
                        │                             │                             │
                        ▼                             ▼                             ▼
                 ┌──────────────┐           ┌──────────────┐           ┌──────────────┐
                 │    Slack     │           │   Discord    │           │  PagerDuty   │
                 └──────────────┘           └──────────────┘           └──────────────┘
```

## License

MIT - See main project LICENSE.
