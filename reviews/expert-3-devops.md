# DevOps/Infrastructure Review

**Reviewer:** Expert 3 - DevOps/Infrastructure Specialist  
**Date:** 2026-02-07  
**Documents Reviewed:** TEST-PLAN.md, honeypot.py, fly.toml, Dockerfile

---

## Overall Assessment

The test plan demonstrates solid security testing fundamentals but has **critical infrastructure gaps** that will cause production failures. The most concerning issue: **there is a fundamental mismatch between the fly.toml configuration (expects HTTP health on port 9090) and the actual honeypot code (only exposes SSH on 8022)**. This means health checks will fail in production, triggering constant restarts.

Additionally, the plan assumes logs survive restarts (L-02) but **no Fly.io volume is configured**—logs are ephemeral. The rate limiter state is in-memory and lost on every restart. There are no tests for disk exhaustion, log rotation, or what happens when the 256MB RAM limit is hit. These are the gaps that cause 3 AM pages.

---

## Strengths

- O-03 (Graceful Shutdown) tests SIGTERM handling correctly—essential for Fly.io
- O-04 (Container Restart) tests basic restart behavior
- Rate limiting tests (R-*) are comprehensive for the application layer
- Log format validation (L-03) ensures parseable logs
- Correlation ID testing (L-05) enables incident response

---

## Infrastructure Gaps

### Critical Issues

1. **No Volume Mount Configured**
   - `fly.toml` has no `[mounts]` section
   - Logs write to `/var/log/honeypot/ssh.json` (ephemeral)
   - L-02 claims "Logs survive restart (volume mount)" — **this test will fail**
   - Rate limiter state (`_conn_counts`, `_auth_counts`) is in-memory only

2. **Health Check Mismatch**
   - `fly.toml` expects HTTP health check on port 9090 at `/health`
   - `honeypot.py` does NOT expose port 9090 or any HTTP endpoint
   - Dockerfile HEALTHCHECK uses TCP on 8022 (incompatible with fly.toml)
   - **Result:** Fly.io will mark instances unhealthy and restart them continuously

3. **No Log Rotation**
   - `log_event()` appends forever: `with open(LOG_FILE, 'a') as f:`
   - No logrotate, no size limit on the file
   - Attack simulation tests (A-*) will generate substantial logs
   - **Result:** Disk exhaustion → container death

4. **Memory Constraints Not Tested**
   - VM config: 256MB RAM (`memory_mb = 256`)
   - O-01 tests 50 concurrent connections, but no OOM behavior test
   - No test for graceful degradation when nearing memory limit

### Missing Tests

- Disk space exhaustion behavior
- Log file size limits
- Volume mount failure scenarios
- Memory pressure / OOM-killer behavior
- Health endpoint response under load
- Container image pull failures (registry issues)

---

## Fly.io Specific Concerns

### Configuration Issues

| Issue | fly.toml | Reality | Impact |
|-------|----------|---------|--------|
| Health port | 9090 (HTTP) | Not implemented | Constant restarts |
| Volume | Not configured | Logs to ephemeral fs | Data loss on restart |
| S3 storage | `HONEYCLAW_STORAGE = "s3"` | No S3 client in code | Dead config |
| Self-heal | `HONEYCLAW_SELF_HEAL_ENABLED = "true"` | Not implemented | No-op |

### Missing Fly.io Tests

| Gap | Why It Matters |
|-----|----------------|
| **No multi-region failover test** | `primary_region = "iad"` only; no DR testing |
| **No machine migration test** | Fly.io moves machines during maintenance |
| **No IP change test** | Attacker tracking relies on IP stability |
| **No Anycast behavior test** | Traffic routing during region outages |
| **No `fly scale` test** | Scale-up/down behavior under load |
| **No volume attachment test** | What happens if volume attach fails? |
| **No secrets injection test** | Secrets available at boot? Race conditions? |

### Fly.io-Specific Behaviors

- `auto_stop_machines = false` is set, but no test validates this prevents unexpected stops
- `min_machines_running = 1` — no test for machine replacement during crashes
- TCP services have `hard_limit = 100` — exceeding this isn't tested (test plan tests 50)

---

## Observability Gaps

### Metrics
- **No Prometheus endpoint** — How will you alert on auth attempt rates?
- **No `/metrics` test** — No metrics exposure in code or tests
- **No Fly.io metrics integration** — CPU/memory thresholds not tested

### Logging
- **No log shipping test** — How do logs get to your SIEM?
- **No log format versioning** — Schema changes break parsers
- **No log sampling under load** — 100 auth/hr * many attackers = log flood

### Alerting
- L-04 tests webhook alerting exists, but:
  - No test for webhook failure (timeout, 5xx, network error)
  - No test for alert deduplication
  - No test for alert rate limiting (don't DoS your Slack)
  - No test for escalation paths

### Tracing
- No distributed tracing (correlation IDs exist but no span export)
- No test for trace propagation to alert webhook

---

## Test Improvements

| Test ID | Current | Suggested Improvement |
|---------|---------|----------------------|
| O-01 | 50 concurrent connections | Add memory tracking with `fly machine status`; verify RSS stays under 200MB |
| O-02 | CPU < 80% | Add Fly.io metrics verification via API, not just subjective "reasonable" |
| O-04 | "Comes back healthy" | Must verify health check endpoint responds within 5s grace period |
| O-05 | 1 hour stability | Extend to 24 hours minimum; check for memory creep via `fly ssh console` |
| L-02 | "Logs survive restart" | **THIS WILL FAIL** — need volume mount first, then test |
| L-04 | "Alert sent to webhook" | Add failure cases: webhook timeout, 4xx, 5xx, malformed response |
| R-04 | Wait 60s for recovery | Verify rate limit state persists across container restart (it won't—intentional?) |

---

## Additional Tests Recommended

| New Test | Description | Priority |
|----------|-------------|----------|
| **I-01: Health Endpoint** | Verify `/health` on port 9090 returns 200 OK | 🔴 Critical |
| **I-02: Volume Persistence** | Write log, restart, verify log exists | 🔴 Critical |
| **I-03: Disk Exhaustion** | Fill disk to 95%, verify graceful handling | 🔴 Critical |
| **I-04: Log Rotation** | Verify logs rotate at 100MB or have size limit | 🔴 Critical |
| **I-05: OOM Behavior** | Hit memory limit, verify clean restart | 🟡 High |
| **I-06: Health Under Load** | Health check during 50 concurrent connections | 🟡 High |
| **I-07: Rate Limit Persistence** | Verify behavior after restart (state loss) | 🟡 High |
| **I-08: Fly Machine Migration** | Trigger `fly machine clone`, verify state | 🟡 High |
| **I-09: Metrics Endpoint** | Verify Prometheus metrics at `/metrics` | 🟡 High |
| **I-10: Webhook Failure** | Webhook returns 500, verify no crash/block | 🟡 High |
| **I-11: Log Shipping** | Verify logs reach external aggregator | 🟢 Medium |
| **I-12: Alert Rate Limit** | Trigger 100 alerts/min, verify throttling | 🟢 Medium |
| **I-13: Multi-Region** | Deploy to 2 regions, verify both work | 🟢 Medium |
| **I-14: Cold Start Time** | Measure time from deploy to healthy | 🟢 Medium |
| **I-15: Secrets at Boot** | Verify secrets available immediately | 🟢 Medium |

---

## What Will Break at 3 AM

1. **Health check fails → restart loop** — Fly.io can't reach `:9090/health`, restarts the container, health check fails again, repeat forever until on-call investigates
2. **Disk fills with logs** — After a few days of sustained attacks, `/var/log/honeypot/ssh.json` exhausts the ephemeral disk, container crashes
3. **Memory creep under attack** — Rate limiter dictionaries grow, Python GC doesn't free fast enough, OOM-killer strikes
4. **Rate limit state lost on restart** — Attacker triggers rate limit, container restarts for any reason, rate limit resets, attacker continues
5. **Webhook blocks event loop** — Slow webhook response blocks `log_event()`, which blocks `validate_password()`, honeypot becomes unresponsive
6. **S3 storage never configured** — `HONEYCLAW_STORAGE = "s3"` is set but no S3 logic exists; someone will expect cloud storage and find nothing

---

## DevOps Verdict

- [ ] APPROVE plan as-is
- [x] **APPROVE with modifications**
- [ ] REJECT - major gaps

### Required Before Production

1. **Fix health check mismatch** — Either implement HTTP `:9090/health` or change fly.toml to TCP check on 8022
2. **Add Fly.io volume** — `[mounts]` section for `/var/log/honeypot`
3. **Implement log rotation** — Size-based rotation or ship to external storage
4. **Add infrastructure tests I-01 through I-04** — These are blockers

### Recommended Before Production

5. Add I-05 through I-10 (memory, metrics, webhook resilience)
6. Increase VM memory to 512MB for safety margin
7. Implement `/metrics` endpoint for observability
8. Document expected behavior when rate limit state is lost

### Acceptable Post-Launch

9. Multi-region testing (I-13)
10. Log shipping to SIEM (I-11)
11. Alert escalation testing (I-12)

---

*Review complete. The security testing is solid—the infrastructure will undermine it if these gaps aren't addressed.*
