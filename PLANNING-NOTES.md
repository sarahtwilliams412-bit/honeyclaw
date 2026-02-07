# Planning Phase Notes

**Test Plan:** HoneyClaw v17 Security Test Plan  
**Date:** 2026-02-07  
**Status:** ✅ ALL REVIEWS COMPLETE

---

## Expert Reviews Received
- [x] Offensive Security Expert ✅ (09:28 PST)
- [x] Defensive Security Expert ✅ (09:28 PST)
- [x] DevOps/Infrastructure Expert ✅ (09:29 PST)
- [x] Honeypot/Deception Expert ✅ (09:28 PST)

---

## Key Concerns Raised

### From Offensive Security Expert
1. **Shodan/Censys fingerprinting not tested** — Honeypots have known signatures; we may already be flagged
2. **SSH algorithm ordering differs** — golang.org/x/crypto/ssh defaults differ from real OpenSSH
3. **TCP fingerprint reveals container** — nmap -O will show Docker/Fly, not Ubuntu
4. **Post-auth behavior untested** — If auth succeeds, fake shell must look real
5. **Missing feature detection** — No agent forwarding, subsystems = obvious honeypot
6. **Evasion tests too superficial** — Need byte-level comparison against real OpenSSH 8.9p1
7. **No baseline comparison** — Tests check if honeypot works, not if it's distinguishable from real SSH
8. **"Experienced attacker identifies honeypot in 30 seconds"** with current test coverage

### From Defensive Security Expert
1. **Log enrichment missing** — No GeoIP, threat intel, ASN context = useless to SOC
2. **No SIEM integration tests** — CEF/Splunk HEC/Elastic compatibility not tested
3. **Alert quality untested** — L-04 only tests "alert sent", not actionable content
4. **No alert aggregation** — 1000 events from same IP = 1000 alerts = alert fatigue
5. **Schema not defined** — "Valid JSON" is too vague; need ECS/OCSF compliance
6. **Campaign correlation missing** — Multiple IPs using same password list should link
7. **Client fingerprinting absent** — SSH client version reveals attacker tooling
8. **"The honeypot works but doesn't help defenders"** without enrichment

### From DevOps/Infrastructure Expert
1. **🚨 CRITICAL: Health check mismatch** — fly.toml expects HTTP on :9090, code only exposes SSH on 8022 → restart loop
2. **🚨 CRITICAL: No volume mount** — fly.toml has no [mounts], logs are ephemeral → L-02 will fail
3. **🚨 CRITICAL: No log rotation** — Logs append forever → disk exhaustion
4. **Memory constraints untested** — 256MB VM with no OOM behavior test
5. **Rate limit state lost on restart** — In-memory dict resets on container restart
6. **Webhook failure not tested** — Slow webhook blocks event loop
7. **S3 storage dead config** — HONEYCLAW_STORAGE="s3" set but no S3 logic exists
8. **"The security testing is solid—the infrastructure will undermine it"**

### From Deception Expert
1. **Host key stability not tested** — Regenerating keys on restart is detection vector
2. **Already flagged in Shodan?** — Need to check if IP is in honeypot databases
3. **OS fingerprinting reveals container** — nmap -O may expose Docker/Fly.io signature
4. **Realism gaps** — No hostname/motd customization, uptime consistency
5. **Intel collection limited** — No tool identification, credential taxonomy
6. **Only catches bots/script kiddies** — Won't deceive nation-state/APT actors

---

## Suggested Additions

### 🔴 CRITICAL (Blocker for Deployment)

| Test | Description | Sources |
|------|-------------|---------|
| **I-01: Health Endpoint** | Verify /health on port 9090 returns 200 OK (OR fix fly.toml) | DevOps |
| **I-02: Volume Persistence** | Write log, restart, verify log exists | DevOps |
| **I-03: Disk Exhaustion** | Fill disk to 95%, verify graceful handling | DevOps |
| **I-04: Log Rotation** | Verify logs rotate at 100MB or have size limit | DevOps |
| Shodan Fingerprint Check | Query Shodan for IP, verify not flagged as honeypot | Offensive, Deception |
| Algorithm Ordering | Capture KEX, compare to real OpenSSH 8.9p1 | Offensive |
| TCP/OS Fingerprint | nmap -O should show Ubuntu, not Docker/container | Offensive, Deception |

### 🟡 HIGH Priority

| Test | Description | Sources |
|------|-------------|---------|
| Host Key Persistence | Verify key survives restarts | Deception |
| GeoIP Enrichment | Logs must include country, city, ASN | Defensive |
| Threat Intel Lookup | Flag known-bad IPs from AbuseIPDB/OTX | Defensive |
| ECS/OCSF Compliance | Schema must match industry standards | Defensive |
| Alert Aggregation | 100 events from same IP = 1 alert | Defensive |
| OOM Behavior (I-05) | Hit memory limit, verify clean restart | DevOps |
| Rate Limit Persistence (I-07) | Document behavior after restart | DevOps |
| Metrics Endpoint (I-09) | Verify Prometheus metrics at /metrics | DevOps |
| Webhook Failure (I-10) | Webhook returns 500, verify no crash | DevOps |

### 🟢 MEDIUM Priority

| Test | Description | Sources |
|------|-------------|---------|
| Post-Auth Behavior | If auth succeeds, shell must look real | Offensive |
| Subsystem Handling | Test sftp, exec, shell requests | Offensive |
| Campaign Correlation | Link multiple IPs using same credentials | Defensive, Deception |
| Long-term Key Stability | Re-check host key after 24h, 7d | Deception |
| SSH Client Identification | Log client version strings | Offensive, Deception |
| Agent/Port Forwarding | Request forwarding, compare to OpenSSH | Offensive |
| Credential Intelligence | Flag if password in known wordlists | Defensive |
| SIEM Integration | Test Splunk HEC or Elastic ingestion | Defensive |
| Alert Rate Limiting | Trigger 100 alerts/min, verify throttling | DevOps |

### Improvements to Existing Tests

| Test | Improvement | Source |
|------|-------------|--------|
| E-01 | Nanosecond precision timing across 1000+ requests | Offensive |
| E-02 | Specify KEX order, compression, auth method ordering | Offensive, Deception |
| E-03 | Byte-for-byte comparison to real OpenSSH 8.9p1 | Offensive, Deception |
| L-01 | Define exact required fields (see Defensive review for ECS schema) | Defensive |
| L-02 | **⚠️ WILL FAIL** — Need volume mount first | DevOps |
| L-03 | Add ECS/OCSF compliance check, not just "valid JSON" | Defensive |
| L-04 | Validate alert payload schema + test failure cases | Defensive, DevOps |
| O-01 | Add memory tracking via fly machine status, verify <200MB | DevOps |
| O-02 | Verify via Fly.io metrics API, not subjective "reasonable" | DevOps |
| O-05 | Extend to 24 hours, check for memory creep | DevOps |
| A-01 | Require specific MITRE tags: T1078, T1110, TA0006 | Defensive |
| A-05 | Extend to 24-72 hours for realistic APT timing | Offensive, Deception |
| R-04 | Document expected behavior (state loss is intentional?) | DevOps |

---

## Conflicts/Disagreements

**No major conflicts detected.** All four experts agree the plan validates *function* but misses critical aspects:

| Perspective | Focus | Unique Contributions |
|-------------|-------|---------------------|
| Offensive | Attacker evasion | Algorithm ordering, TCP fingerprint, baseline comparison |
| Defensive | SOC operability | GeoIP, threat intel, ECS schema, alert aggregation |
| DevOps | Production stability | Health check mismatch, volume mount, log rotation, OOM |
| Deception | Realism & intel | Host key persistence, Shodan check, credential taxonomy |

**These perspectives are complementary, not conflicting.**

---

## Consensus Recommendations

### 🚨 BLOCKERS — Must Fix Before ANY Testing

1. ⚠️ **Fix health check mismatch** — Implement HTTP :9090/health OR change fly.toml to TCP check on 8022
2. ⚠️ **Add Fly.io volume mount** — [mounts] section for /var/log/honeypot
3. ⚠️ **Implement log rotation** — Size-based rotation or ship to external storage

### Must-Have Before Deployment (All 4 Experts)

4. ✅ **Shodan/Censys fingerprint check** — Verify not already burned
5. ✅ **OS/TCP fingerprint test** — Confirm doesn't scream "container"
6. ✅ **Algorithm ordering comparison** — Match real OpenSSH behavior
7. ✅ **Host key persistence** — Survive restarts with same key
8. ✅ **Log enrichment** — GeoIP + Threat Intel + client fingerprint
9. ✅ **Schema compliance** — ECS or OCSF standard
10. ✅ **Infrastructure tests I-01 through I-04** — Health, volume, disk, rotation

### Should-Have (Majority Agreement)

- Alert aggregation and deduplication
- Post-auth behavior testing
- Campaign correlation
- At least one SIEM integration test
- OOM behavior test
- Webhook failure resilience

### Nice-to-Have (Single Expert)

- SOAR webhook integration
- 24-72 hour APT timing tests
- Multi-region failover testing
- Timezone consistency checks

---

## Plan Modifications Required

### Infrastructure Fixes (Before Testing Can Begin)
1. Add `/health` HTTP endpoint on port 9090 OR modify fly.toml to use TCP health check on 8022
2. Add `[mounts]` section to fly.toml for persistent storage
3. Implement log rotation (logrotate or size-based)
4. Consider increasing VM memory from 256MB to 512MB

### New Test Categories to Add

**Category 9: Infrastructure Resilience (NEW)**
| Test ID | Name | Description | Expected Result |
|---------|------|-------------|-----------------|
| I-01 | Health Endpoint | HTTP GET /health:9090 | 200 OK within 100ms |
| I-02 | Volume Persistence | Restart container, check logs exist | Logs survive |
| I-03 | Disk Exhaustion | Fill to 95%, continue operating | Graceful handling |
| I-04 | Log Rotation | Generate 150MB logs | Rotation at 100MB |
| I-05 | OOM Behavior | Exceed memory limit | Clean restart |
| I-06 | Health Under Load | Health check during 50 connections | Still responds |
| I-07 | Rate Limit Reset | Document post-restart behavior | Documented |
| I-10 | Webhook Failure | Webhook returns 500 | No crash/block |

**Category 10: Detection Resistance (NEW)**
| Test ID | Name | Description | Expected Result |
|---------|------|-------------|-----------------|
| D-01 | Shodan Check | Query Shodan for our IP | Not flagged as honeypot |
| D-02 | Algorithm Ordering | Compare KEX to real OpenSSH | Matches OpenSSH 8.9p1 |
| D-03 | TCP Fingerprint | nmap -O verification | Shows Ubuntu, not Docker |
| D-04 | Hostkey Uniqueness | Search for duplicates | Unique key |
| D-05 | Post-Auth Shell | Test successful auth | Realistic shell |
| D-06 | Subsystems | Test sftp, exec requests | Match OpenSSH behavior |

### Test Modifications

| Test | Current | Modified |
|------|---------|----------|
| L-02 | "Logs survive restart (volume mount)" | Precondition: volume mounted; verify via I-02 |
| L-01 | "Timestamp, IP, credentials, fingerprint" | Add: geo, ASN, threat_intel_match, client_version |
| L-03 | "Valid JSON, consistent schema" | Add: ECS v8 compliance verification |
| L-04 | "Alert sent to webhook" | Add: schema validation + failure tests (I-10) |
| E-01 through E-05 | Basic evasion tests | Add quantitative metrics, baseline comparison |

---

## Expert Verdicts

| Expert | Verdict | Key Condition |
|--------|---------|---------------|
| Offensive Security | **APPROVE WITH MODS** | Must add Shodan check, algorithm ordering, TCP fingerprint |
| Defensive Security | **APPROVE WITH MODS** | Must add GeoIP, threat intel, ECS compliance, alert aggregation |
| DevOps/Infrastructure | **APPROVE WITH MODS** | Must fix health check, add volume mount, log rotation |
| Deception Expert | **APPROVE WITH MODS** | Must add host key persistence, Shodan check, OS fingerprint |

### Consolidated Verdict: **APPROVE WITH MODIFICATIONS**

All four experts conditionally approve. The test plan is solid for security validation but needs:
1. **Infrastructure fixes** before testing can even begin (health check, volume, log rotation)
2. **Detection resistance tests** to validate deception quality
3. **Log enrichment tests** to ensure SOC utility

---

## Summary

The expert panel identified **three major gaps** in the original test plan:

### Gap 1: Infrastructure Will Undermine Security (DevOps)
The honeypot will crash-loop in production due to health check mismatch. Logs will be lost on restart. Disk will fill up. These issues must be fixed before security testing is meaningful.

### Gap 2: Deception Quality Untested (Offensive + Deception)
The plan tests if the honeypot *works*, not if it *deceives*. An experienced attacker will identify it as a honeypot in 30 seconds using Shodan, TCP fingerprinting, and algorithm analysis. New detection resistance tests are required.

### Gap 3: Intelligence Value Untested (Defensive)
The plan ensures logs exist but not that they're *useful*. Without GeoIP, threat intel enrichment, proper schema, and alert aggregation, the honeypot generates noise instead of actionable intelligence.

### Action Items
1. **Immediate:** Fix infrastructure (health check, volume mount, log rotation)
2. **Before testing:** Add Category 9 (Infrastructure) and Category 10 (Detection Resistance) tests
3. **Enhance existing:** Upgrade L-* and E-* tests per expert recommendations
4. **Document:** Expected rate limit behavior after restart, log schema, alert payload format

---

*Review completed: 2026-02-07 09:29 PST*  
*All 4 expert reviews received and synthesized*  
*Ready for plan modification phase*
