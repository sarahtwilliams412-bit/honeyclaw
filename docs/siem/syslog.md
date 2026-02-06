# Syslog Integration (CEF/LEEF) Setup

This guide covers setting up Honeyclaw with any syslog-compatible SIEM using CEF (Common Event Format) or LEEF (Log Event Extended Format).

## Supported Platforms

| Platform | Recommended Format | Protocol |
|----------|-------------------|----------|
| IBM QRadar | LEEF | TCP |
| HP ArcSight | CEF | TCP/TLS |
| LogRhythm | CEF | TCP |
| Splunk (syslog) | CEF | UDP/TCP |
| Graylog | CEF | UDP/TCP |
| rsyslog | CEF | UDP/TCP |
| Generic SIEM | CEF | UDP/TCP |

## Quick Start

### CEF (ArcSight, LogRhythm, Generic)

```yaml
siem:
  provider: syslog
  syslog_host: siem.example.com
  syslog_port: 514
  syslog_protocol: tcp
  syslog_format: cef
```

### LEEF (QRadar)

```yaml
siem:
  provider: syslog
  syslog_host: qradar.example.com
  syslog_port: 514
  syslog_protocol: tcp
  syslog_format: leef
```

## CEF Format

### Structure

```
CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
```

### Example Event

```
<134>Jan 15 10:30:00 prod-ssh-01 honeyclaw: CEF:0|Honeyclaw|Honeypot|1.0.0|honeyclaw:auth_failure|Honeypot auth_failure from 192.168.1.100|5|src=192.168.1.100 spt=54321 dpt=22 proto=tcp app=ssh duser=admin dvchost=prod-ssh-01 cs1=passwd cs1Label=AuthMethod cat=Authentication rt=2024-01-15T10:30:00Z
```

### CEF Field Mappings

| CEF Field | Honeyclaw Data | Description |
|-----------|----------------|-------------|
| `src` | `source_ip` | Attacker IP |
| `spt` | `source_port` | Source port |
| `dpt` | `destination_port` | Target port |
| `proto` | `protocol` | Network protocol |
| `app` | `service` | Honeypot service |
| `duser` | `username` | Target username |
| `dvchost` | `honeypot_id` | Honeypot identifier |
| `cs1` | `command` | Command (if applicable) |
| `cs2` | `session_id` | Session ID |
| `cs3` | `geo_country` | Source country |
| `cs4` | `geo_asn` | Source ASN |
| `cs5` | `mitre_tactics` | MITRE tactics |
| `cs6` | `mitre_techniques` | MITRE techniques |
| `fileHash` | `payload_hash` | Payload SHA256 |
| `fsize` | `payload_size` | Payload size |
| `cat` | Category | Event category |
| `rt` | `timestamp` | Event timestamp |
| `externalId` | Event ID | Unique event ID |

### CEF Severity Mapping

| Honeyclaw Severity | CEF Severity (0-10) |
|-------------------|---------------------|
| Unknown | 0 |
| Low | 3 |
| Medium | 5 |
| High | 7 |
| Critical | 10 |

## LEEF Format (QRadar)

### Structure

```
LEEF:Version|Vendor|Product|Version|EventID|Key=Value<tab>Key=Value...
```

### Example Event

```
<134>Jan 15 10:30:00 prod-ssh-01 honeyclaw: LEEF:2.0|Honeyclaw|Honeypot|1.0.0|auth_failure|src=192.168.1.100	srcPort=54321	dstPort=22	proto=tcp	sev=5	cat=Authentication	usrName=admin	devName=prod-ssh-01	devTime=2024-01-15T10:30:00Z
```

### LEEF Field Mappings

| LEEF Field | Honeyclaw Data |
|------------|----------------|
| `src` | `source_ip` |
| `srcPort` | `source_port` |
| `dstPort` | `destination_port` |
| `proto` | `protocol` |
| `sev` | Severity value |
| `cat` | Event category |
| `usrName` | `username` |
| `devName` | `honeypot_id` |
| `resource` | `service` |
| `command` | `command` |
| `devTime` | `timestamp` |
| `sessionId` | `session_id` |

## IBM QRadar Setup

### Step 1: Create Log Source

1. Go to **Admin > Log Sources**
2. Click **Add**
3. Configure:
   - **Log Source Type**: Universal LEEF
   - **Protocol Configuration**: Syslog
   - **Log Source Identifier**: Pattern matching honeypot hostnames
4. Click **Save**

### Step 2: Import DSM

Import the Honeyclaw DSM from `siem-rules/qradar/honeyclaw_rules.xml`:

1. Go to **Admin > Extensions Management**
2. Click **Add**
3. Upload the XML file
4. Deploy changes

### Step 3: Configure Honeyclaw

```yaml
siem:
  provider: syslog
  syslog_host: qradar.example.com
  syslog_port: 514
  syslog_protocol: tcp
  syslog_format: leef
```

### Step 4: Import Rules

The DSM includes pre-built rules:

- Honeyclaw: Brute Force Attack
- Honeyclaw: Successful Authentication
- Honeyclaw: Command Execution
- Honeyclaw: Multi-Honeypot Attack

## HP ArcSight Setup

### Step 1: Configure Connector

1. Deploy SmartConnector for Syslog
2. Configure to receive CEF events
3. Set device vendor filter: "Honeyclaw"

### Step 2: Configure Honeyclaw

```yaml
siem:
  provider: syslog
  syslog_host: arcsight.example.com
  syslog_port: 514
  syslog_protocol: tcp
  syslog_format: cef
```

### Step 3: Import Rules

Create correlation rules for:
- Multiple auth failures (brute force)
- Any auth success (compromise)
- Command execution (post-exploitation)

## Protocol Options

### UDP (Default)

```yaml
siem:
  syslog_protocol: udp
  syslog_port: 514
```

- **Pros**: Simple, no connection overhead
- **Cons**: No delivery guarantee, max ~64KB per message

### TCP

```yaml
siem:
  syslog_protocol: tcp
  syslog_port: 514
```

- **Pros**: Reliable delivery, larger messages
- **Cons**: Connection overhead

### TLS (Encrypted)

```yaml
siem:
  syslog_protocol: tls
  syslog_port: 6514
  verify_ssl: true
  ca_cert_path: /etc/ssl/certs/siem-ca.pem
```

- **Pros**: Encrypted, authenticated
- **Cons**: More complex setup, TLS overhead

## Testing

### Send Test Event via netcat

```bash
# UDP
echo '<134>Jan 15 10:30:00 test honeyclaw: CEF:0|Honeyclaw|Test|1.0|test|Test Event|1|msg=connectivity test' | nc -u siem.example.com 514

# TCP
echo '<134>Jan 15 10:30:00 test honeyclaw: CEF:0|Honeyclaw|Test|1.0|test|Test Event|1|msg=connectivity test' | nc siem.example.com 514
```

### Verify in SIEM

Check for events with:
- Device Vendor: Honeyclaw
- Device Product: Honeypot

## Troubleshooting

### Events Not Arriving

1. Check network connectivity: `nc -vz siem.example.com 514`
2. Verify firewall allows syslog traffic
3. Check SIEM is listening on configured port
4. Review SIEM logs for parsing errors

### Parsing Errors

1. Verify CEF/LEEF format matches SIEM expectations
2. Check for special character escaping issues
3. Review event field mappings in SIEM

### Performance Issues

For high-volume honeypots:

```yaml
siem:
  syslog_protocol: tcp  # More reliable than UDP
  batch_size: 50        # Balance latency vs efficiency
  flush_interval_seconds: 5
```

## Syslog Priority Calculation

Syslog priority = (Facility × 8) + Severity

- Honeyclaw uses **Facility 16** (local0)
- Severity maps from honeypot severity to syslog severity

| Honeypot Severity | Syslog Severity | Priority |
|-------------------|-----------------|----------|
| Critical | 2 (Critical) | 130 |
| High | 3 (Error) | 131 |
| Medium | 4 (Warning) | 132 |
| Low | 5 (Notice) | 133 |
| Unknown | 6 (Info) | 134 |

## Custom Formatting

If your SIEM needs a custom format, extend the `SyslogConnector`:

```python
from honeyclaw.integrations.generic_syslog import SyslogConnector

class CustomSyslogConnector(SyslogConnector):
    def _format_event(self, event):
        # Custom formatting logic
        return f"CUSTOM|{event.honeypot_id}|{event.source_ip}|{event.event_type.value}"
```
