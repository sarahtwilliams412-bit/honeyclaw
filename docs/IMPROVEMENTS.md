# Honeyclaw Improvements Roadmap

Based on fleet agent testing and analysis of the SSH honeypot at `149.248.202.23:8022`.

**Created:** 2026-02-07  
**Source:** Fleet feedback (Juanita Marquez security analysis)

---

## Priority Levels
- **P0**: Critical - Must fix immediately (security/detection issues)
- **P1**: High - Implement within 1 week
- **P2**: Medium - Implement within 1 month

---

## P0 - Critical Improvements

### 1. Timing Analysis Vulnerability
**Issue:** Response times may be distinguishable from real SSH servers, allowing attackers to fingerprint the honeypot.

**Suggested Fix:**
- Add randomized delays (50-200ms jitter) to authentication responses
- Implement realistic "thinking time" for password validation
- Match timing characteristics of target OpenSSH version

**Effort:** 2-4 hours

**Files to Modify:**
- `src/honeyclaw/ssh/server.py` - Authentication handler
- Add timing configuration to `config.yaml`

---

### 2. OS Fingerprinting Inconsistency
**Issue:** Host fingerprinting (nmap OS detection) might reveal inconsistencies between claimed OS and actual behavior.

**Suggested Fix:**
- Audit TCP/IP stack responses against Ubuntu 22.04 baseline
- Ensure TTL, window sizes, and TCP options match target OS
- Consider running in VM/container matching claimed OS

**Effort:** 4-8 hours

---

## P1 - High Priority Improvements

### 3. Enhanced Session Logging
**Issue:** Current logging may not capture full session context for threat intelligence.

**Suggested Fix:**
- Implement full session recording (TTY replay)
- Add structured logging format (JSON) for SIEM integration
- Include geolocation data for source IPs (MaxMind GeoIP)

**Effort:** 8-16 hours

**Files to Modify:**
- `src/honeyclaw/logging/` - Add session recorder
- `src/honeyclaw/enrichment/` - Add GeoIP lookup

---

### 4. Realistic MOTD/Banners
**Issue:** Missing or generic message-of-the-day could indicate honeypot.

**Suggested Fix:**
- Add configurable MOTD templates matching common Ubuntu setups
- Include realistic system info (fake uptime, load, last login)
- Rotate banners to appear like real systems

**Effort:** 2-4 hours

**Files to Modify:**
- `templates/motd/` - Add banner templates
- `src/honeyclaw/ssh/session.py` - Banner display logic

---

### 5. Authentication Response Patterns
**Issue:** Uniform rejection of all credentials may be detectable.

**Suggested Fix:**
- Implement variable delay before rejection
- Add support for "honeypot accounts" that grant limited shell access
- Log and analyze credential patterns for common attack dictionaries

**Effort:** 8-16 hours

---

### 6. Threat Intelligence Integration
**Issue:** Collected attack data not being shared with threat intel platforms.

**Suggested Fix:**
- Add STIX/TAXII output for IOC sharing
- Integrate with AbuseIPDB for reputation reporting
- Create automated IOC extraction pipeline

**Effort:** 16-24 hours

**Files to Modify:**
- `src/honeyclaw/intel/` - New module for threat intel
- `deploy/` - Add export cronjobs

---

## P2 - Medium Priority Improvements

### 7. Tarpit Capabilities
**Issue:** No active defense against aggressive scanners.

**Suggested Fix:**
- Implement SSH tarpit mode (slow responses to detected scanners)
- Add configurable tarpit triggers (rapid auth attempts, known scanner IPs)
- Rate limit by source IP

**Effort:** 8-16 hours

---

### 8. Dynamic Blacklisting
**Issue:** Known malicious IPs continue to consume resources.

**Suggested Fix:**
- Integrate with threat intel feeds for proactive blocking
- Implement auto-blacklist after N failed attempts
- Add whitelist for legitimate security researchers

**Effort:** 4-8 hours

---

### 9. Honeytoken Deployment
**Issue:** Advanced attackers may detect honeypot and not engage.

**Suggested Fix:**
- Add fake credentials/keys that trigger alerts when used elsewhere
- Implement SSH key honeytokens
- Create fake "interesting" file paths visible in limited shell

**Effort:** 16-24 hours

---

### 10. SIEM Rule Tuning
**Issue:** Current SIEM rules may not cover all attack patterns.

**Suggested Fix:**
- Review and expand Splunk/Elastic detection rules
- Add rules for MITRE ATT&CK techniques identified (T1078, T1110, T1046, T1018)
- Create dashboards for attack pattern visualization

**Effort:** 8-16 hours

**Files to Modify:**
- `siem-rules/` - Update detection rules

---

## Implementation Timeline

| Week | Items | Effort |
|------|-------|--------|
| 1 | P0 items (timing, OS fingerprinting) | 8-12 hours |
| 2 | P1 items 3-4 (logging, banners) | 10-20 hours |
| 3 | P1 items 5-6 (auth patterns, threat intel) | 24-40 hours |
| 4+ | P2 items (tarpit, blacklist, honeytokens, SIEM) | 36-64 hours |

---

## Validation Criteria

After implementing improvements, fleet agents should re-test and verify:

1. [ ] Timing analysis no longer distinguishes honeypot from real SSH
2. [ ] OS fingerprinting matches claimed Ubuntu version
3. [ ] Session logs capture full attacker activity
4. [ ] MOTD/banners appear realistic
5. [ ] Threat intel exports functional
6. [ ] SIEM rules triggering correctly

---

## References

- [MITRE ATT&CK - SSH](https://attack.mitre.org/techniques/T1021/004/)
- [OpenSSH Fingerprinting](https://github.com/offensive-security/exploitdb)
- [Cowrie SSH Honeypot](https://github.com/cowrie/cowrie) - Reference implementation
- Juanita Marquez Fleet Analysis (2026-02-07)
