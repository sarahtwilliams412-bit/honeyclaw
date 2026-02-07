# Deception Technology Review

## Overall Assessment

This test plan represents a solid **medium-interaction SSH honeypot** with good foundational testing, but it lacks the depth required to deceive sophisticated adversaries. The current E-* tests cover only basic fingerprinting resistance; experienced attackers (and automated scanners like Shodan, Censys, and GreyNoise) use far more advanced honeypot detection techniques that this plan doesn't address. From a deception technology standpoint, HoneyClaw is currently testing for script kiddies and commodity botnets, not APT-level adversaries.

The intelligence collection strategy appears limited to credential capture and basic connection metadata. Modern deception platforms (Attivo ThreatDefend, Illusive Networks, TrapX DeceptionGrid) provide layered intelligence including attacker TTPs, tool identification, lateral movement tracking, and campaign correlation. This plan tests for data collection but not for intelligence *extraction* or *actionability*.

## Strengths

- **Solid rate limiting tests (R-*)** — Properly protects against resource exhaustion while still allowing enough interaction to gather intel
- **Comprehensive input validation (I-*)** — Critical for honeypot survival; malformed input is common in automated attacks
- **Attack simulation category (A-*)** — Tests real-world attack patterns, which validates intelligence utility
- **MITRE tagging mentioned** — Indicates intent to map to ATT&CK framework, which is best practice
- **Log persistence testing** — Critical for intel preservation; many honeypots lose data on restart
- **Session correlation IDs** — Essential for tracking multi-stage attacks

## Realism Gaps

- **No SSH key host fingerprint rotation testing** — Real servers have stable host keys; honeypots often regenerate them on restart, which attackers detect
- **No filesystem interaction testing** — Even failed auth reveals filesystem behavior through error messages and timing
- **No hostname/motd realism checks** — Generic "Ubuntu" banner may trigger honeypot detection heuristics
- **No network neighborhood testing** — Isolated hosts with no related services are suspicious
- **No uptime consistency** — Real servers have uptimes of days/weeks; fresh containers are flagged
- **No CPU/memory fingerprinting resistance** — `/proc` contents, timing jitter from virtualization
- **No geographic/ASN consistency** — Fly.io IP ranges are well-known cloud infrastructure; real SSH servers are often on business/ISP IPs
- **No history/bash profile realism** — If any shell access is provided, empty history is a red flag

## Evasion Detection Gaps

The E-* tests miss critical detection vectors used by real adversaries:

| Detection Vector | Status | Real-World Usage |
|-----------------|--------|------------------|
| SSH host key stability | **NOT TESTED** | Shodan tracks host keys over time; honeypots that regenerate keys are flagged |
| TCP/IP stack fingerprinting | **NOT TESTED** | p0f, nmap OS detection reveal container vs bare-metal |
| TLS/cipher ordering | Partial (P-03) | Specific cipher preference order identifies implementations |
| Response jitter analysis | **NOT TESTED** | Virtualized/containerized systems have measurable timing patterns |
| Honeypot signature databases | **NOT TESTED** | Kippo, Cowrie, HoneyClaw may have known signatures in Shodan |
| PTR record validation | **NOT TESTED** | Missing/generic PTR records indicate cloud honeypots |
| Banner string databases | Partial (F-03) | Known fake banners are catalogued and matched |
| Failed auth message fingerprinting | **NOT TESTED** | Different SSH implementations have distinct error strings |
| MAC address OUI | **NOT TESTED** | Fly.io/Docker has identifiable MAC prefixes |
| Deliberate interaction testing | **NOT TESTED** | Attackers may probe with "honeypot detector" payloads |

## Intelligence Value Assessment

**Current intel captured:**
- Credentials (usernames/passwords) — HIGH VALUE for credential reuse detection
- Source IPs — MEDIUM VALUE for threat feed/blocklist
- Timing patterns — MEDIUM VALUE for campaign correlation
- Connection metadata — LOW VALUE without enrichment

**Intelligence gaps:**
- **No tool identification** — Cannot tell if attacker uses Hydra, Medusa, custom tooling
- **No client fingerprinting** — SSH client version/capabilities not explicitly tested
- **No campaign correlation** — No testing for linking sessions across time/IPs
- **No threat intel integration** — No testing for enriching IPs with known-bad databases
- **No credential taxonomy** — Are these default creds? Leaked creds? Targeted?
- **No post-auth behavior capture** — If attackers ever "succeed," what do they do?

**Compared to commercial solutions:**
- Attivo: Provides full endpoint deception with fake files, AD integration, lateral movement tracking
- Illusive: Creates deceptive credentials/connections on real endpoints to detect insider threats
- TrapX: Full network deception with fake SCADA/IoT/medical devices

HoneyClaw is closer to Cowrie/Kippo level — valid, but limited to perimeter credential harvesting.

## Test Improvements

| Test ID | Current | Suggested Improvement |
|---------|---------|----------------------|
| E-01 | Timing consistency | Add jitter variance measurement; compare to genuine OpenSSH timing distributions |
| E-02 | "SSH implementation quirks" | Specify: test KEX algorithm order, compression support, auth method ordering |
| E-03 | Error message analysis | Add specific error string comparison matrix vs OpenSSH 8.9p1 |
| E-04 | Keyboard-interactive | Test multi-round prompts; honeypots often fail on complex PAM flows |
| E-05 | Public key auth | Test with valid-format but wrong keys; check rejection message timing |
| F-03 | Banner verification | Cross-reference against Shodan honeypot detection database |
| L-01 | Log completeness | Add SSH client version string to logged fields |
| A-05 | APT behavior | Extend to 24-72 hours; real APTs space attempts over days |

## Additional Tests Recommended

| New Test | Description | Priority |
|----------|-------------|----------|
| E-06 | Host Key Persistence | Verify host key survives restarts, matches across test window | **CRITICAL** |
| E-07 | Shodan Fingerprint Check | Query Shodan for 149.248.202.23; verify not already flagged as honeypot | **CRITICAL** |
| E-08 | OS Fingerprint Resistance | Run nmap -O; verify matches claimed Ubuntu, not Docker/Fly signature | **HIGH** |
| E-09 | Censys/GreyNoise Check | Verify IP not in honeypot databases | **HIGH** |
| E-10 | PTR Record Validation | Check reverse DNS; generic cloud PTR is a red flag | **MEDIUM** |
| E-11 | Deliberate Honeypot Probes | Send known honeypot test strings (e.g., "honeypot", admin/admin) and verify no special handling | **MEDIUM** |
| E-12 | Long-term Key Stability | Re-check host key after 24h, 7d | **HIGH** |
| I-08 | SSH Client Identification | Log and test extraction of SSH client version from each connection | **MEDIUM** |
| A-06 | Multi-Source Correlation | Same credentials from 3 different IPs; verify correlation in logs | **MEDIUM** |
| A-07 | Known-Credential Detection | Test with credentials from haveibeenpwned/public breaches; verify flagging | **LOW** |
| L-06 | Threat Intel Enrichment | Verify IPs enriched with AbuseIPDB/GreyNoise/OTX context | **MEDIUM** |

## Deception Expert Verdict

- [ ] APPROVE plan as-is
- [x] APPROVE with modifications
- [ ] REJECT - major gaps

**Conditional approval.** The plan is adequate for testing a commodity credential harvesting honeypot, but it will not deceive sophisticated adversaries or provide the intelligence depth of commercial deception platforms. 

**Required before production deployment:**
1. Add E-06 (Host Key Persistence) — this is a trivial check but critical fingerprinting vector
2. Add E-07 (Shodan Fingerprint Check) — verify we're not already burned
3. Add E-08 (OS Fingerprint Resistance) — confirm we don't scream "container"

**Recommended for v18:**
- Expand to medium-interaction with fake shell/filesystem to capture post-auth TTPs
- Integrate threat intel enrichment for IP context
- Add credential taxonomy (default vs leaked vs targeted)
- Consider breadcrumb deployment on other infrastructure to drive traffic

This honeypot will catch bots and script kiddies. To catch nation-state actors, it needs significantly more realism investment.

---

*Reviewed by: Deception Technology Specialist*  
*Date: 2026-02-07*  
*Methodology: Compared against MITRE Engage framework and commercial deception platform capabilities*
