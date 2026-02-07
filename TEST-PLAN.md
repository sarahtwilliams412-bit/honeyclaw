# HoneyClaw v17 Security Test Plan

**Target:** honeyclaw-ssh on Fly.io  
**IP:** 149.248.202.23:8022  
**Date:** 2026-02-07  
**Version:** v17 (deployment-01KGWJ1459HVAG7JES1EK2CYJ3)

---

## Executive Summary

This plan defines comprehensive security testing for the HoneyClaw SSH honeypot. Testing covers functionality, security hardening, evasion resistance, logging integrity, and operational resilience.

---

## Test Categories

### Category 1: Functional Verification
Verify core honeypot functionality works as designed.

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| F-01 | Basic SSH Connection | Connect to port 8022 | Connection accepted, banner displayed |
| F-02 | Authentication Capture | Attempt login with test credentials | Credentials logged, authentication denied |
| F-03 | SSH Banner Verification | Check SSH version string | Returns configured banner (OpenSSH_8.9p1 Ubuntu-3ubuntu0.6) |
| F-04 | Multiple Auth Attempts | Try 5 different credential pairs | All attempts logged with timestamps |
| F-05 | Connection Persistence | Maintain connection for 60 seconds | Connection remains stable |

### Category 2: Rate Limiting
Verify rate limiting protects against abuse.

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| R-01 | Connection Rate Limit | Exceed 10 connections/minute from single IP | 11th connection blocked |
| R-02 | Auth Rate Limit | Exceed 100 auth attempts/hour from single IP | 101st attempt blocked |
| R-03 | Rate Limit Logging | Trigger rate limit | Block event logged with IP, count, limit |
| R-04 | Rate Limit Recovery | Wait 60s after conn limit | Connections allowed again |
| R-05 | Multi-IP Rate Limit | Different IPs hit limits independently | Each IP tracked separately |

### Category 3: Input Validation & Injection
Test resistance to malicious input.

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| I-01 | Username Overflow | Send 10KB username | Truncated/rejected safely |
| I-02 | Password Overflow | Send 10KB password | Truncated/rejected safely |
| I-03 | Null Bytes | Include \x00 in credentials | Handled without crash |
| I-04 | Unicode Exploits | Send unicode normalization attacks | Sanitized in logs |
| I-05 | Log Injection | Include JSON/newlines in credentials | Escaped properly in logs |
| I-06 | Shell Metacharacters | Include $(), ``, | in username | No command execution |
| I-07 | Format String | Include %s, %n, %x in credentials | No format string vuln |

### Category 4: Protocol Attacks
Test SSH protocol-level security.

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| P-01 | Malformed Packets | Send invalid SSH protocol data | Connection closed gracefully |
| P-02 | Slowloris | Slow-send SSH handshake over 5 minutes | Connection times out |
| P-03 | Cipher Downgrade | Request weak/null ciphers | Rejected or logged |
| P-04 | Key Exchange Flood | Rapid renegotiation requests | Rate limited or ignored |
| P-05 | Banner Grab Only | Connect, grab banner, disconnect | Logged as reconnaissance |

### Category 5: Evasion Detection
Test ability to detect honeypot evasion techniques.

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| E-01 | Timing Analysis | Measure response timing consistency | Consistent timing (no detection signal) |
| E-02 | Behavioral Fingerprinting | Test SSH implementation quirks | Mimics real OpenSSH behavior |
| E-03 | Error Message Analysis | Trigger various errors | Error messages match real SSH |
| E-04 | Keyboard-Interactive | Test keyboard-interactive auth | Behaves like real server |
| E-05 | Public Key Auth | Attempt pubkey authentication | Behaves like real server |

### Category 6: Logging & Alerting
Verify logging completeness and alerting.

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| L-01 | Log Completeness | Check all events logged | Timestamp, IP, credentials, fingerprint |
| L-02 | Log Persistence | Restart container, check logs | Logs survive restart (volume mount) |
| L-03 | Log Format | Validate JSON structure | Valid JSON, consistent schema |
| L-04 | Webhook Alerting | Trigger alert if configured | Alert sent to webhook |
| L-05 | Correlation IDs | Check session correlation | Same session has consistent ID |

### Category 7: Operational Resilience
Test stability and resource handling.

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| O-01 | Memory Under Load | 50 concurrent connections | Memory stable, no leak |
| O-02 | CPU Under Load | Sustained auth attempts | CPU reasonable (<80%) |
| O-03 | Graceful Shutdown | Send SIGTERM | Clean shutdown, no data loss |
| O-04 | Container Restart | Fly.io restart | Comes back healthy |
| O-05 | Long-Running Stability | 1 hour continuous operation | No degradation |

### Category 8: Attack Simulation
Simulate real-world attack patterns.

| Test ID | Test Name | Description | Expected Result |
|---------|-----------|-------------|-----------------|
| A-01 | Credential Stuffing | Common username/password combos | All logged with MITRE tags |
| A-02 | Dictionary Attack | wordlist-based attempts | Logged, rate limited |
| A-03 | Targeted Bruteforce | Focused on single username | Detected, logged pattern |
| A-04 | Lateral Movement Sim | Credentials from "other systems" | Logged for correlation |
| A-05 | APT Behavior | Low-and-slow attempts | Still captured despite timing |

---

## Test Execution Phases

### Phase 1: Connectivity & Basics (15 min)
- F-01 through F-05
- L-03 (log format validation)

### Phase 2: Security Controls (30 min)
- R-01 through R-05 (rate limiting)
- I-01 through I-07 (input validation)

### Phase 3: Protocol & Evasion (30 min)
- P-01 through P-05 (protocol attacks)
- E-01 through E-05 (evasion detection)

### Phase 4: Logging & Alerting (15 min)
- L-01, L-02, L-04, L-05

### Phase 5: Operational (30 min)
- O-01 through O-05

### Phase 6: Attack Simulation (30 min)
- A-01 through A-05

---

## Tools Required

| Tool | Purpose | Source |
|------|---------|--------|
| ssh/openssh-client | Basic SSH testing | System |
| nmap | Port scanning, service fingerprinting | apt/brew |
| hydra | Credential bruteforce testing | apt/brew |
| python3 + asyncssh | Custom protocol tests | pip |
| curl | Webhook testing | System |
| jq | Log parsing | apt/brew |

---

## Success Criteria

| Category | Pass Threshold |
|----------|----------------|
| Functional | 100% of F-* tests pass |
| Rate Limiting | 100% of R-* tests pass |
| Input Validation | 100% of I-* tests pass |
| Protocol | 80% of P-* tests pass (some may be N/A) |
| Evasion | 80% of E-* tests pass |
| Logging | 100% of L-* tests pass |
| Operational | 100% of O-* tests pass |
| Attack Sim | 100% of A-* tests pass |

**Overall Pass:** All categories meet threshold

---

## Risk Considerations

1. **Testing from known IP** — Our IP will be logged; this is expected
2. **Rate limits may block tests** — Coordinate tests to avoid self-blocking
3. **Production system** — Tests are non-destructive but will generate logs
4. **Legal** — We own this honeypot; testing is authorized

---

## Deliverables

1. Test execution report (pass/fail per test)
2. Log samples from each test category
3. Performance metrics (response times, resource usage)
4. List of bugs/improvements discovered
5. Security recommendations

---

*Plan Version: 1.0*  
*Author: Sarah AI (Security Testing)*
