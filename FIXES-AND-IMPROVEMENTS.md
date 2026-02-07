# HoneyClaw Fixes and Improvements

**Generated:** 2026-02-07  
**Source:** Parallel Security Testing Campaign  
**Status:** 🔄 In Progress (Planning phase complete, execution phase active)

---

## Summary

| Priority | Count | Status |
|----------|-------|--------|
| Critical (Must Fix) | 6 | From expert reviews |
| High Priority | 9 | From expert reviews |
| Medium Priority | 8 | From expert reviews |
| Enhancements | 4 | From expert reviews |
| Security Recommendations | 7 | From expert reviews |

---

## Critical (Must Fix)

*Issues that could cause security vulnerabilities, service failures, or test invalidity.*

| Issue | Found By | Test ID | Suggested Fix |
|-------|----------|---------|---------------|
| Health check mismatch — fly.toml expects HTTP on :9090, code only exposes SSH on 8022 | DevOps Expert | Pre-test | Implement /health HTTP endpoint on port 9090 OR change fly.toml to TCP check on 8022 |
| No volume mount — logs are ephemeral, will be lost on restart | DevOps Expert | L-02 will fail | Add [mounts] section to fly.toml for /var/log/honeypot |
| No log rotation — logs append forever until disk exhaustion | DevOps Expert | Pre-test | Implement logrotate or size-based rotation (100MB max) |
| Already flagged in Shodan? — IP may be in honeypot databases | Offensive + Deception | E-07 | Query Shodan API before deployment; rotate IP if flagged |
| OS/TCP fingerprint reveals container — nmap -O shows Docker/Fly, not Ubuntu | Offensive + Deception | D-03 | Configure kernel parameters or accept deception limitation |
| Host key regenerates on restart — clear honeypot detection signal | Deception Expert | E-06 | Persist SSH host key in volume mount |

---

## High Priority

*Issues that significantly impact functionality, security posture, or operational value.*

| Issue | Found By | Test ID | Suggested Fix |
|-------|----------|---------|---------------|
| SSH algorithm ordering differs from real OpenSSH | Offensive Expert | D-02 | Match golang.org/x/crypto/ssh KEX order to OpenSSH 8.9p1 |
| No GeoIP enrichment — logs missing country, city, ASN context | Defensive Expert | L-01+ | Integrate MaxMind GeoLite2 or ip-api for enrichment |
| No threat intel lookup — can't flag known-bad IPs | Defensive Expert | L-06 | Integrate AbuseIPDB or OTX for IP reputation |
| Schema not defined — "valid JSON" too vague for SOC | Defensive Expert | L-03 | Implement ECS v8 or OCSF compliant log schema |
| No alert aggregation — 1000 events = 1000 alerts = noise | Defensive Expert | L-04+ | Implement deduplication (same IP/hour = 1 alert) |
| Rate limit state lost on restart — attackers get fresh limits | DevOps Expert | R-04 | Document as intentional OR persist to volume |
| Memory constraints untested — 256MB may be insufficient | DevOps Expert | O-01/I-05 | Test OOM behavior, consider 512MB |
| Webhook failure not tested — slow webhook may block event loop | DevOps Expert | I-10 | Test 500 errors, timeouts; implement async/timeout |
| S3 storage dead config — env var set but no S3 logic exists | DevOps Expert | Pre-test | Remove config or implement S3 shipping |

---

## Medium Priority

*Issues that should be addressed but don't block core operation.*

| Issue | Found By | Test ID | Suggested Fix |
|-------|----------|---------|---------------|
| Post-auth behavior untested — if auth succeeds, shell must look real | Offensive Expert | D-05 | Implement realistic fake shell response |
| Missing feature detection — no agent forwarding, subsystems | Offensive Expert | D-06 | Handle sftp/exec/shell requests per OpenSSH behavior |
| SSH client version not logged — missing attacker tool intel | Offensive + Defensive | I-08 | Add client_version to log schema |
| Campaign correlation missing — same password from different IPs not linked | Defensive Expert | A-06 | Implement credential-based clustering |
| PTR record validation — generic cloud PTR is red flag | Deception Expert | E-10 | Document limitation or set custom rDNS |
| Evasion tests too shallow — need nanosecond timing, byte comparison | Offensive + Deception | E-01 to E-05 | Add quantitative metrics and baseline comparisons |
| SIEM integration untested — CEF/Splunk HEC/Elastic compatibility unknown | Defensive Expert | L-07 | Add at least one SIEM integration test |
| Alert rate limiting — no test for 100 alerts/min scenario | DevOps Expert | L-04+ | Test throttling under alert flood |

---

## Enhancements (Nice to Have)

*Improvements that would enhance the honeypot but aren't bugs.*

| Enhancement | Found By | Test ID | Benefit |
|-------------|----------|---------|---------|
| Credential intelligence — flag passwords in known breach wordlists | Defensive Expert | A-07 | Enrich with "known_credential: true" for triage |
| SOAR webhook integration | Defensive Expert | L-04+ | Enable automated response playbooks |
| 24-72 hour APT timing tests | Offensive + Deception | A-05 | Validate slow-and-low attack detection |
| Multi-region failover testing | DevOps Expert | O-06+ | Improve resilience for production deployment |

---

## Security Recommendations

*Expert recommendations for improving overall security posture.*

| Recommendation | Rationale | Priority |
|----------------|-----------|----------|
| Query Shodan/Censys before deployment | Verify IP not already in honeypot databases | Critical |
| Match OpenSSH 8.9p1 behavior exactly | Algorithm ordering, error messages, timing | High |
| Implement ECS or OCSF log schema | SOC integration requires standard format | High |
| Add client fingerprinting | SSH client version reveals attacker tooling | High |
| Persist host key across restarts | Key changes are primary detection vector | High |
| Implement alert aggregation | Prevent alert fatigue with deduplication | High |
| Test infrastructure before security | Health check, volume, logging must work first | Critical |

---

## Test Execution Status

*Final results from 2026-02-07 testing campaign*

| Agent | Category | Status | Result | Notes |
|-------|----------|--------|--------|-------|
| 1 | Functional (F-01 to F-05) | ✅ Complete | 0/5 ❌ | SSH handshake broken — KEX failure |
| 2 | Rate Limiting (R-01 to R-05) | ✅ Complete | 1/5 ⚠️ | Aggressive rate limiting works but blocks testing |
| 3 | Input Validation (I-01 to I-07) | ✅ Complete | 5/55 confirmed ⚠️ | Most tests inconclusive due to KEX failure |
| 4 | Protocol Attacks (P-01 to P-05) | ✅ Complete | 4/5 ✅ | Resilient to protocol abuse |
| 5 | Evasion Detection (E-01 to E-05) | ✅ Complete | 0/5 ❌ | Trivially detectable as honeypot |
| 6 | Logging & Alerting (L-01 to L-05) | ✅ Complete | 2/5 ⚠️ | Alerting/correlation not configured |
| 7 | Operational Resilience (O-01 to O-05) | ✅ Complete | 4/5 ✅ | Memory/CPU stable under load |
| 8 | Attack Simulation (A-01 to A-05) | ✅ Complete | 0/5 ⚠️ | All tests blocked by rate limiting |

---

## Gap Analysis

> See [SECURITY-AUDIT-2026-02-07.md](SECURITY-AUDIT-2026-02-07.md) for the consolidated gap analysis and prioritized fix plan.
> See [PLANNING-NOTES.md](PLANNING-NOTES.md) for detailed expert review synthesis.

---

*Last updated: 2026-02-07*
