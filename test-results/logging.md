# Logging & Alerting Test Results

**Executor:** TEST EXECUTOR 6  
**Date:** 2026-02-07 09:28 PST  
**Target:** honeyclaw-ssh (149.248.202.23:8022)  
**Machine ID:** 91855361f31dd8 (sjc)

---

## Test Summary

| Test ID | Test Name | Result | Notes |
|---------|-----------|--------|-------|
| L-01 | Log Completeness | ✅ PASS | All expected fields present |
| L-02 | Log Persistence | ⚠️ PARTIAL | Stdout persists; volume reinitialized on restart |
| L-03 | Log Format | ✅ PASS | Valid JSON structure |
| L-04 | Webhook Alerting | ⚠️ NOT CONFIGURED | No ALERT_WEBHOOK_URL set |
| L-05 | Correlation IDs | ⚠️ NOT ENABLED | Enhanced logging module not active |

---

## L-01: Log Completeness

### Result: ✅ PASS

All required fields are present in structured JSON log entries.

### Sample Log Entries

#### Startup Event
```json
{
  "timestamp": "2026-02-07T17:22:53.498036Z",
  "event": "startup",
  "port": 8022,
  "version": "1.4.0",
  "rate_limiting": true,
  "conn_limit": "20/min",
  "auth_limit": "200/hr",
  "ssh_banner": "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
  "alerting_enabled": false
}
```

#### Connection Event
```json
{
  "timestamp": "2026-02-07T17:00:12.100818Z",
  "event": "connection",
  "ip": "172.16.7.242",
  "ip_valid": true
}
```

#### Login Attempt Event
```json
{
  "timestamp": "2026-02-07T16:58:44.465830Z",
  "event": "login_attempt",
  "ip": "172.16.7.242",
  "username": "admin",
  "username_valid": true,
  "password_hash": "03ac674216f3e15c",
  "password_length": 4,
  "password_valid": true,
  "suspicious": false
}
```

#### Pubkey Attempt Event
```json
{
  "timestamp": "2026-02-07T16:20:38.446929Z",
  "event": "pubkey_attempt",
  "ip": "172.16.7.242",
  "username": "root",
  "username_valid": true,
  "key_type": "ssh-rsa",
  "fingerprint": "SHA256:1M4RzhMyWuFS/86uPY/ce2prh/dVTHW7iD2RhpquOZA"
}
```

#### Disconnect Event
```json
{
  "timestamp": "2026-02-07T16:20:38.585890Z",
  "event": "disconnect",
  "ip": "172.16.7.242",
  "error": "Connection lost"
}
```

### Fields Present

| Field | Type | Present | Notes |
|-------|------|---------|-------|
| timestamp | ISO 8601 | ✅ | UTC with Z suffix |
| event | string | ✅ | connection/login_attempt/pubkey_attempt/disconnect/startup |
| ip | string | ✅ | Source IP address |
| ip_valid | boolean | ✅ | IP validation status |
| username | string | ✅ | Sanitized username |
| username_valid | boolean | ✅ | Username validation status |
| password_hash | string | ✅ | First 16 chars of SHA256 |
| password_length | int | ✅ | Original password length |
| password_valid | boolean | ✅ | Password validation status |
| suspicious | boolean | ✅ | Anomaly flag |
| key_type | string | ✅ | For pubkey attempts |
| fingerprint | string | ✅ | SSH key fingerprint |
| error | string | ✅ | Disconnect reason |

---

## L-02: Log Persistence

### Result: ⚠️ PARTIAL

#### Observations

1. **Stdout Logging**: Persists via Fly.io log aggregation (verified via `fly logs`)
2. **Volume Persistence**: Volume `honeyclaw_data` is configured, BUT:
   - Observed volume reinitialization on restart:
   ```
   [2026-02-07T17:22:49Z] Uninitialized volume 'honeyclaw_data', initializing...
   [2026-02-07T17:22:49Z] Encrypting volume
   [2026-02-07T17:22:50Z] Formatting volume
   ```

3. **Log File Location**: `/var/log/honeypot/ssh.json` (configured via LOG_PATH)

#### Container Restart Observed
```
[2026-02-07T17:22:23Z] Sending signal SIGINT to main child process w/ PID 640
[2026-02-07T17:22:23Z] [INFO] Received signal 2, initiating shutdown...
[2026-02-07T17:22:28Z] Sending signal SIGTERM to main child process w/ PID 640
[2026-02-07T17:22:33Z] Virtual machine exited abruptly
```

#### Concerns
- The volume was "uninitialized" and reformatted, which would lose any persisted logs
- This may indicate the volume wasn't properly mounted before, or a new machine was spawned
- **Recommendation**: Verify log file exists inside container after restart

---

## L-03: Log Format

### Result: ✅ PASS

All log entries are valid JSON and can be parsed programmatically.

#### Validation Tests

```bash
# Extract JSON lines and validate
fly logs -a honeyclaw-ssh | grep -o '{.*}' | while read line; do
  echo "$line" | python3 -c "import sys,json; json.load(sys.stdin)" && echo "✓ Valid"
done
```

#### JSON Structure Analysis

1. **Consistent schema per event type**
2. **No truncation observed** (all entries < 16KB limit)
3. **No malformed entries detected**
4. **UTF-8 encoding throughout**
5. **Timestamps follow ISO 8601 strictly**

#### Edge Cases Handled
- Empty passwords: logged as `"password_hash": "empty"`
- Connection errors: sanitized to max 256 chars
- Invalid usernames: marked with `username_valid: false`

---

## L-04: Webhook Alerting

### Result: ⚠️ NOT CONFIGURED

#### Secrets Check
```bash
$ fly secrets list -a honeyclaw-ssh
NAME    DIGEST    STATUS
(empty)
```

No secrets are configured, including:
- `ALERT_WEBHOOK_URL` - Not set
- `ALERT_SEVERITY_THRESHOLD` - Not set
- `HONEYPOT_ID` - Not set

#### Startup Confirmation
From startup log:
```json
{
  "alerting_enabled": false
}
```

#### Code Analysis (honeypot.py)
```python
try:
    from src.alerts.dispatcher import get_dispatcher, alert as send_alert
    ALERTING_ENABLED = bool(os.environ.get('ALERT_WEBHOOK_URL'))
except ImportError:
    ALERTING_ENABLED = False
```

#### Recommendation
To enable alerting:
```bash
fly secrets set -a honeyclaw-ssh \
  ALERT_WEBHOOK_URL="https://hooks.slack.com/services/..." \
  ALERT_SEVERITY_THRESHOLD="MEDIUM" \
  HONEYPOT_ID="honeyclaw-prod-1"
```

---

## L-05: Correlation IDs

### Result: ⚠️ NOT ENABLED

#### Observations
None of the captured log entries contain a `correlation_id` field.

#### Code Analysis
From honeypot.py:
```python
try:
    from src.utils.correlation import get_correlation_id
    from src.utils.geoip import get_geo_fields
    ENHANCED_LOGGING_ENABLED = True
except ImportError:
    ENHANCED_LOGGING_ENABLED = False
```

The module exists at `src/utils/correlation.py` with full implementation:
- Tracks sessions by source IP within configurable time window (default: 1 hour)
- Generates UUID-based correlation IDs
- Links multi-step attacks across services

#### Why Not Enabled
The correlation module is in `src/utils/correlation.py` but the import fails:
- Container image may not include the `src/` directory
- Or path resolution issue with Docker build context

#### Session Tracking (Without Correlation ID)
Observed same IP (172.16.7.242) across multiple events that SHOULD have been correlated:
- 12:22:29Z - login_attempt (AdminGPON)
- 13:02:54Z - connection + login_attempt (user)
- 13:43:23Z - connection + login_attempt (root)
- 14:23:20Z - connection + login_attempt (ubnt)
- 15:02:58Z - connection + pubkey_attempt (root)
- 16:20:37Z - connection + pubkey_attempt (root)
- 16:58:43Z - connection + login_attempt (admin)

**All 7 sessions from same IP within ~5 hours should share one correlation_id.**

---

## Additional Observations

### Rate Limiting Active
```
[INFO] Rate limiting enabled: 20/min connections, 200/hr auth
```

### SSH Banner Configured
```
ssh_banner: "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
```

### Version Tracking
```
version: "1.4.0"
```

### Debug Logging Present
Extensive debug output alongside structured JSON:
```
[DEBUG] HoneypotServer instance created
[DEBUG] Connection from 172.16.7.242
[DEBUG] Auth attempt for user: admin (valid=True)
[DEBUG] Password attempt: admin:***
```

---

## Recommendations

### Critical
1. **Fix Log Persistence**: Investigate why volume was reinitialized. Ensure `/data/logs/` mount is properly configured.

### High Priority
2. **Enable Alerting**: Set `ALERT_WEBHOOK_URL` for real-time notifications
3. **Enable Correlation**: Fix import path for `src.utils.correlation` module

### Medium Priority
4. **GeoIP Enrichment**: Enable for attacker location tracking
5. **MITRE ATT&CK Mapping**: Enable for threat intelligence enrichment

### Low Priority
6. **Reduce Debug Noise**: Consider `DEBUG=false` in production to reduce log volume

---

## Raw Log Sample (First 50 Lines Available)

See Fly.io logs: `fly logs -a honeyclaw-ssh`

**Test completed: 2026-02-07 09:29 PST**
