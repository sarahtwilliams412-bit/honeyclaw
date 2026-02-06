# Honeyclaw Auto-Abuse Reporting

Honeyclaw can automatically report attackers to abuse databases and ISPs.
This guide covers configuration, responsible use, and best practices.

## Overview

The reporting system supports:

- **AbuseIPDB** - Crowdsourced IP reputation database
- **ISP Email** - Direct abuse reports to ISP abuse contacts

Reports are filtered to avoid:
- Known security researchers (GreyNoise benign classification)
- Recently reported IPs (configurable cooldown)
- Low-severity events

## Configuration

### Environment Variables

```bash
# AbuseIPDB (required for reporting)
export ABUSEIPDB_API_KEY="your-api-key"

# Optional: ISP email reporting
export SMTP_HOST="smtp.example.com"
export SMTP_PORT="587"
export SMTP_USER="user@example.com"
export SMTP_PASS="password"
export SMTP_FROM="honeypot@example.com"

# Reporting settings
export HONEYCLAW_REPORTING_ENABLED="true"
export HONEYCLAW_REPORTING_MIN_SEVERITY="high"
export HONEYCLAW_REPORTING_COOLDOWN="24"  # hours
export HONEYCLAW_REPORTING_DAILY_LIMIT="500"
export HONEYCLAW_REPORTING_GREYNOISE_FILTER="true"
```

### YAML Configuration

```yaml
auto_report:
  enabled: true
  min_severity: high
  cooldown: 24h
  require_confirmation: false
  daily_limit: 500
  providers:
    - abuseipdb
    - isp_email  # optional, requires SMTP
  
  # Filtering
  enable_greynoise_filter: true
  allowlist:
    - 185.180.143.  # GreyNoise sensors
    - 64.62.197.    # Censys
```

## CLI Usage

### Report an IP manually

```bash
# Report with reason
honeyclaw report ip 192.0.2.1 --reason "SSH brute force - 500 attempts in 1 hour"

# Skip filters (force report)
honeyclaw report ip 192.0.2.1 --reason "Known attacker" --force

# Dry run (see what would happen)
honeyclaw report ip 192.0.2.1 --reason "Testing" --dry-run
```

### Check reporting status

```bash
# Show status
honeyclaw report status

# JSON output
honeyclaw report status --json
```

### View audit log

```bash
# Recent reports
honeyclaw report log

# More entries
honeyclaw report log --limit 50
```

### Lookup abuse contact

```bash
# Find ISP abuse email
honeyclaw report lookup 192.0.2.1

# With raw WHOIS data
honeyclaw report lookup 192.0.2.1 --verbose
```

## Programmatic Usage

### Basic reporting

```python
from src.reporting import ReportingEngine

engine = ReportingEngine()

# Report an event
results = await engine.report_event(
    ip="192.0.2.1",
    event_type="ssh_brute_force",
    severity="high",
    evidence={
        'username': 'root',
        'attempts': 500,
        'timestamp': '2024-01-15T10:30:00Z'
    }
)

for result in results:
    if result.success:
        print(f"Reported to {result.provider}")
```

### Check if should report

```python
from src.reporting import should_report

result = await should_report(
    ip="192.0.2.1",
    severity="high",
    event_type="ssh_brute_force"
)

if result.should_report:
    # Proceed with report
    pass
else:
    print(f"Skipped: {result.reason}")
```

### With enrichment data

```python
# If you have pre-enriched data from GreyNoise
result = await should_report(
    ip="192.0.2.1",
    severity="high",
    enrichment={
        'greynoise': {
            'classification': 'malicious',
            'riot': False
        }
    }
)
```

## Responsible Reporting Guidelines

### DO Report

✅ Genuine attacks captured by your honeypot  
✅ Brute force attempts with multiple failed logins  
✅ Exploitation attempts targeting known vulnerabilities  
✅ Malware delivery attempts  
✅ Port scanning followed by attack attempts  

### DON'T Report

❌ Single connection or benign scanning  
❌ Security researchers (check GreyNoise first)  
❌ Your own test traffic  
❌ IPs without clear malicious intent  
❌ Already reported IPs (respect cooldown)  

### Best Practices

1. **Use appropriate severity thresholds**
   - `high` or `critical` for auto-reporting
   - Lower severities for logging only

2. **Enable GreyNoise filtering**
   - Automatically skips known researchers
   - Reduces false positives significantly

3. **Set reasonable cooldowns**
   - 24 hours is a good default
   - Prevents duplicate reports
   - Respects abuse team time

4. **Monitor your audit log**
   - Review what's being reported
   - Adjust filters as needed

5. **Include good evidence**
   - Timestamps
   - Attack details
   - Session IDs for reference

6. **Respect rate limits**
   - AbuseIPDB: 1000 reports/day (free tier)
   - Set daily_limit below API max

## Evidence Format

Reports include:

```
[Honeyclaw/your-honeypot-id] SSH Brute Force Attack

Username attempted: root
Attempt count: 500
Session ID: abc123
Time: 2024-01-15T10:30:00Z

Reported via Honeyclaw honeypot system
```

## Audit Logging

All reports are logged with:

- Timestamp
- IP address
- Event type and severity
- Provider used
- Success/failure status
- Filter decisions
- Evidence summary

Log location: Set `HONEYCLAW_REPORTING_AUDIT_LOG` or defaults to stdout.

## Troubleshooting

### "API key not configured"

```bash
export ABUSEIPDB_API_KEY="your-key"
```

### "Rate limit exceeded"

- Wait and retry later
- Reduce `daily_limit` in config
- Enable better filtering

### "IP filtered"

Check filter reason:
- Cooldown: Wait or use `--force`
- Severity: Lower `min_severity` or use `--force`
- Researcher: The IP is classified as benign

### Reports not sending

1. Check `honeyclaw report status`
2. Verify API key is valid
3. Check network connectivity
4. Review audit log for errors
