# Security Council Verdict
*Analyst: Security Expert*
*Date: 2026-02-05*

---

## 🔴 Top 5 Security Risks (Ranked by Severity)

### 1. CRITICAL: Hardcoded/Exposed Canary Tokens
**Severity:** CRITICAL (9/10)
**Location:** `research/safe-mimicry-patterns.md:177-193`

```javascript
// EXPOSED IN PUBLIC DOCUMENTATION:
const CANARY_DATA = {
  apiKeys: {
    anthropic: 'sk-ant-CANARY-hc001-xxxxxxxx',
    openai: 'sk-CANARY-hc001-xxxxxxxx',
    aws: 'AKIAIOSFODNN7CANARY1'
  },
```

**Risk:** Attackers can fingerprint honeypot by searching for these exact strings. Defeats the purpose of canaries.

**Fix Required:**
1. Remove ALL hardcoded canary examples from documentation
2. Create `canary-generator.py` script that generates unique tokens per deployment
3. Store generated canaries in environment variables or secrets manager
4. Add pre-commit hook to reject commits containing known canary patterns

**Effort:** 2 hours

---

### 2. CRITICAL: Host Key Regeneration Exposes Honeypot
**Severity:** CRITICAL (9/10)
**Location:** `templates/basic-ssh/honeypot.py:69`

```python
# CURRENT - INSECURE:
key = asyncssh.generate_private_key('ssh-rsa', 2048)
```

**Risk:** SSH host key changes on every restart. Sophisticated attackers monitor for key changes - a server that changes keys frequently is obviously synthetic.

**Fix Required:**
```python
# SECURE VERSION:
HOST_KEY_PATH = Path(os.environ.get('HOST_KEY_PATH', '/data/ssh_host_key'))

def get_or_create_host_key():
    if HOST_KEY_PATH.exists():
        return asyncssh.read_private_key(HOST_KEY_PATH)
    key = asyncssh.generate_private_key('ssh-rsa', 4096)  # Use 4096 for realism
    asyncssh.write_private_key(key, HOST_KEY_PATH)
    return key
```

**Effort:** 1 hour

---

### 3. HIGH: Plaintext Password Logging
**Severity:** HIGH (7/10)
**Location:** `templates/basic-ssh/honeypot.py:42-46`

```python
def validate_password(self, username, password):
    print(f"[DEBUG] Password attempt: {username}:{password}", flush=True)  # LEAKS TO STDOUT
    log_event('login_attempt', {
        'ip': self.client_ip,
        'username': username,
        'password': password  # STORED IN PLAINTEXT
    })
```

**Risk:** 
- Passwords visible in `fly logs` output (shared log aggregators)
- Log files contain plaintext credentials
- Violates security best practices even for honeypot

**Fix Required:**
```python
import hashlib

def hash_password(password):
    """Hash password for safe logging, keep original in secure store"""
    return hashlib.sha256(password.encode()).hexdigest()[:16]

def validate_password(self, username, password):
    log_event('login_attempt', {
        'ip': self.client_ip,
        'username': username,
        'password_hash': hash_password(password),
        'password_length': len(password)
    })
    # Full password only to secure log (not stdout)
    secure_log('credentials', {'user': username, 'pass': password})
```

**Effort:** 2 hours (including secure log implementation)

---

### 4. HIGH: No Rate Limiting
**Severity:** HIGH (7/10)
**Location:** All honeypot services

**Risk:**
- Resource exhaustion attacks
- Log storage exhaustion
- Could be used as amplification point
- High AWS/Fly costs from abuse

**Fix Required:**
```python
from collections import defaultdict
import time

class RateLimiter:
    def __init__(self, max_per_minute=60):
        self.requests = defaultdict(list)
        self.max = max_per_minute
    
    def is_allowed(self, ip):
        now = time.time()
        self.requests[ip] = [t for t in self.requests[ip] if now - t < 60]
        if len(self.requests[ip]) >= self.max:
            return False
        self.requests[ip].append(now)
        return True

rate_limiter = RateLimiter(max_per_minute=30)

def connection_made(self, conn):
    if not rate_limiter.is_allowed(self.client_ip):
        log_event('rate_limited', {'ip': self.client_ip})
        conn.close()
        return
```

**Effort:** 3 hours (implement for all services)

---

### 5. MEDIUM: Missing Input Validation
**Severity:** MEDIUM (6/10)
**Location:** `templates/basic-ssh/honeypot.py:10`, `templates/enterprise-sim/services/rdp_sim.py`

**Current:**
```python
PORT = int(os.environ.get("PORT", 8022))  # Crashes on invalid input
```

**Risk:**
- Application crash on malformed config
- Potential for DoS via config manipulation
- No bounds checking (port > 65535)

**Fix Required:**
```python
def get_port():
    try:
        port = int(os.environ.get("PORT", 8022))
        if not 1 <= port <= 65535:
            raise ValueError(f"Port {port} out of range")
        return port
    except ValueError as e:
        print(f"[WARN] Invalid PORT: {e}, using default 8022")
        return 8022

PORT = get_port()
```

**Effort:** 1 hour

---

## Additional Security Hardening Recommendations

### Network Level
1. **Egress Firewall:** Verify Fly.io has no outbound except logging endpoint
2. **IP Blocklist:** Auto-block IPs after 1000+ requests/hour
3. **GeoIP Logging:** Add geographic attribution to all events

### Application Level
1. **Add Request IDs:** Trace requests across log entries
2. **Implement Session Tracking:** Correlate multi-step attacks
3. **Add Timestamp Verification:** Detect time-based attacks

### Operational Security
1. **Log Rotation:** Implement log rotation to prevent disk exhaustion
2. **Alerting:** Add Discord/Slack alerts for anomalous patterns
3. **Audit Trail:** Log all administrative actions

---

## Effort Summary

| Fix | Priority | Hours | Assignee |
|-----|----------|-------|----------|
| Remove hardcoded canaries | P0 | 2h | hitteam-1 |
| Persist SSH host key | P0 | 1h | hitteam-1 |
| Hash passwords in logs | P0 | 2h | hitteam-1 |
| Rate limiting | P1 | 3h | hitteam-1 |
| Input validation | P1 | 1h | hitteam-1 |
| **Total** | | **9h** | |

---

## VERDICT: 🔴 NOT PRODUCTION READY

The honeypot has critical security flaws that would allow sophisticated attackers to identify and avoid it. The P0 fixes must be completed before the next deployment.

*Signed: Security Council*
